"""Gold market watcher and mathematical trend analysis for Lumi.

This module is read-only with respect to the market. It fetches public market
data, calculates transparent indicators, and can emit informational Windows
notifications. It never places trades or moves money.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from security.descriptor import Origin
from security.gate import SecurityGate, ToolRequest

logger = logging.getLogger(__name__)

_YAHOO_HOST = "query1.finance.yahoo.com"
_GOLD_SYMBOL = "XAUUSD=X"
_FX_SYMBOL = "USDIDR=X"
_MAX_HISTORY_DAYS = 365
_DEFAULT_HISTORY_DAYS = 180


@dataclass
class GoldSnapshot:
    gold_usd_oz: float
    usd_idr: float
    idr_gram: float
    previous_idr_gram: float | None
    change_1d_pct: float | None
    sma_7: float | None
    sma_30: float | None
    ema_20: float | None
    momentum_7_pct: float | None
    momentum_30_pct: float | None
    volatility_30_pct: float | None
    rsi_14: float | None
    trend: str
    signal_score: float
    confidence: str
    as_of: str


def _fetch_chart(symbol: str, period_days: int) -> list[tuple[int, float]]:
    period_days = max(2, min(int(period_days), _MAX_HISTORY_DAYS))
    now = int(time.time())
    start = now - period_days * 86400
    query = urllib.parse.urlencode({
        "period1": start,
        "period2": now,
        "interval": "1d",
        "events": "history",
    })
    url = f"https://{_YAHOO_HOST}/v8/finance/chart/{urllib.parse.quote(symbol)}?{query}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Lumi-GoldWatcher/1.0"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))

    result = payload.get("chart", {}).get("result")
    if not result:
        raise RuntimeError(f"No market data returned for {symbol}")

    item = result[0]
    timestamps = item.get("timestamp") or []
    closes = ((item.get("indicators") or {}).get("quote") or [{}])[0].get("close") or []
    rows = []
    for timestamp, close in zip(timestamps, closes):
        if close is not None and float(close) > 0:
            rows.append((int(timestamp), float(close)))
    if not rows:
        raise RuntimeError(f"No closing prices returned for {symbol}")
    return rows


def _sma(values: list[float], window: int) -> float | None:
    if len(values) < window:
        return None
    return sum(values[-window:]) / window


def _ema(values: list[float], window: int) -> float | None:
    if len(values) < window:
        return None
    alpha = 2.0 / (window + 1.0)
    value = sum(values[:window]) / window
    for price in values[window:]:
        value = alpha * price + (1.0 - alpha) * value
    return value


def _momentum(values: list[float], periods: int) -> float | None:
    if len(values) <= periods:
        return None
    return (values[-1] / values[-1 - periods] - 1.0) * 100.0


def _volatility(values: list[float], window: int) -> float | None:
    if len(values) < window + 1:
        return None
    returns = [
        math.log(values[i] / values[i - 1])
        for i in range(len(values) - window, len(values))
        if values[i] > 0 and values[i - 1] > 0
    ]
    if len(returns) < 2:
        return None
    mean = sum(returns) / len(returns)
    variance = sum((x - mean) ** 2 for x in returns) / (len(returns) - 1)
    return math.sqrt(variance) * math.sqrt(252.0) * 100.0


def _rsi(values: list[float], window: int = 14) -> float | None:
    if len(values) <= window:
        return None
    changes = [values[i] - values[i - 1] for i in range(1, len(values))]
    gains = [max(x, 0.0) for x in changes]
    losses = [max(-x, 0.0) for x in changes]
    avg_gain = sum(gains[:window]) / window
    avg_loss = sum(losses[:window]) / window
    for i in range(window, len(changes)):
        avg_gain = (avg_gain * (window - 1) + gains[i]) / window
        avg_loss = (avg_loss * (window - 1) + losses[i]) / window
    if avg_loss == 0:
        return 100.0
    return 100.0 - (100.0 / (1.0 + avg_gain / avg_loss))


def _signal(values: list[float]) -> tuple[str, float, str]:
    sma7 = _sma(values, 7)
    sma30 = _sma(values, 30)
    ema20 = _ema(values, 20)
    mom7 = _momentum(values, 7)
    mom30 = _momentum(values, 30)
    rsi = _rsi(values, 14)

    score = 0.0
    evidence = 0

    if sma7 is not None and sma30 is not None:
        score += 1.5 if sma7 > sma30 else -1.5
        evidence += 1
    if ema20 is not None:
        score += 1.0 if values[-1] > ema20 else -1.0
        evidence += 1
    if mom7 is not None:
        score += 1.0 if mom7 > 0 else -1.0
        evidence += 1
    if mom30 is not None:
        score += 1.0 if mom30 > 0 else -1.0
        evidence += 1
    if rsi is not None:
        if rsi >= 70:
            score -= 0.5
        elif rsi <= 30:
            score += 0.5
        evidence += 1

    if score >= 2.0:
        trend = "bullish"
    elif score <= -2.0:
        trend = "bearish"
    else:
        trend = "mixed"

    confidence = "low" if evidence < 3 else ("medium" if evidence < 5 else "higher")
    return trend, score, confidence


def analyze_gold(history_days: int = _DEFAULT_HISTORY_DAYS) -> dict:
    gold = _fetch_chart(_GOLD_SYMBOL, history_days)
    fx = _fetch_chart(_FX_SYMBOL, history_days)

    # Align by date and use the latest common observations.
    fx_by_day = {datetime.fromtimestamp(ts, tz=timezone.utc).date(): value for ts, value in fx}
    common = []
    for ts, gold_usd in gold:
        day = datetime.fromtimestamp(ts, tz=timezone.utc).date()
        if day in fx_by_day:
            common.append((ts, gold_usd, fx_by_day[day]))

    if len(common) < 31:
        raise RuntimeError("Not enough aligned gold/FX history for analysis")

    idr_per_gram = [
        (gold_usd * usd_idr) / 31.1034768
        for _, gold_usd, usd_idr in common
    ]
    current = idr_per_gram[-1]
    previous = idr_per_gram[-2] if len(idr_per_gram) >= 2 else None
    trend, score, confidence = _signal(idr_per_gram)

    result = GoldSnapshot(
        gold_usd_oz=common[-1][1],
        usd_idr=common[-1][2],
        idr_gram=current,
        previous_idr_gram=previous,
        change_1d_pct=((current / previous) - 1.0) * 100.0 if previous else None,
        sma_7=_sma(idr_per_gram, 7),
        sma_30=_sma(idr_per_gram, 30),
        ema_20=_ema(idr_per_gram, 20),
        momentum_7_pct=_momentum(idr_per_gram, 7),
        momentum_30_pct=_momentum(idr_per_gram, 30),
        volatility_30_pct=_volatility(idr_per_gram, 30),
        rsi_14=_rsi(idr_per_gram, 14),
        trend=trend,
        signal_score=score,
        confidence=confidence,
        as_of=datetime.fromtimestamp(common[-1][0], tz=timezone.utc).isoformat(),
    )
    return {
        "benchmark": "XAU/USD spot converted with USD/IDR",
        "note": "This is a mathematical market signal, not a prediction or investment instruction. It does not include Antam retail premiums, taxes, spreads, or buyback prices.",
        "data": result.__dict__,
    }


def _fmt(value: float | None, suffix: str = "") -> str:
    return "n/a" if value is None else f"{value:,.2f}{suffix}"


def _notify_text(report: dict) -> str:
    d = report["data"]
    return (
        f"Gold benchmark ~Rp{d['idr_gram']:,.0f}/g | "
        f"1d {_fmt(d['change_1d_pct'], '%')} | "
        f"trend {d['trend']} | RSI {_fmt(d['rsi_14'])} | "
        f"7d {_fmt(d['momentum_7_pct'], '%')} | "
        f"30d {_fmt(d['momentum_30_pct'], '%')}. "
        f"Signal confidence: {d['confidence']}."
    )


class GoldWatcher:
    """Background read-only watcher. Notifications are informational only."""

    def __init__(self, notifier, interval_minutes: int = 60):
        self.notifier = notifier
        self.interval_seconds = max(15, int(interval_minutes) * 60)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_state: str | None = None
        self._last_alert_at = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="LumiGoldWatcher", daemon=True)
        self._thread.start()
        logger.info("Gold watcher started (interval=%sm).", self.interval_seconds // 60)

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                report = analyze_gold()
                d = report["data"]
                state = d["trend"]
                now = time.time()
                significant_move = (
                    d["change_1d_pct"] is not None and abs(d["change_1d_pct"]) >= 1.0
                )
                state_changed = self._last_state is not None and state != self._last_state
                first_report = self._last_state is None
                daily_cooldown_ok = now - self._last_alert_at >= 23 * 3600

                # First report, meaningful daily move, or a mathematical trend
                # regime change. Never sends more often than the cooldown.
                if first_report or significant_move or state_changed:
                    if first_report or daily_cooldown_ok or state_changed:
                        self.notifier.notify("Lumi — Gold Watcher", _notify_text(report))
                        self._last_alert_at = now
                self._last_state = state
            except Exception:
                logger.exception("Gold watcher update failed")
            self._stop.wait(self.interval_seconds)


def _do_analyze(args: dict) -> dict:
    days = int(args.get("history_days", _DEFAULT_HISTORY_DAYS))
    return analyze_gold(days)


def register(gate: SecurityGate) -> None:
    """Register the read-only gold analysis tool with the SecurityGate."""
    from security.permissions import PermissionLevel

    gate.register(
        name="gold.analyze",
        permission=PermissionLevel.SAFE,
        path_params=[],
        executor=lambda request: _do_analyze(request.arguments),
    )
