"""
A label-like widget that paints text as YouTube-style captions:
each wrapped line gets its own black rounded bar behind it.

Also supports a typewriter reveal via animateText(), and reports the
minimum height it needs to render the current text via preferred_height().
"""
from PyQt6.QtCore import Qt, QRect, QRectF, QTimer
from PyQt6.QtGui import QFont, QFontMetrics, QPainter, QColor, QPainterPath
from PyQt6.QtWidgets import QWidget, QSizePolicy

from ui import themes


class CaptionLabel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._full_text = ""
        self._reveal_pos = 0
        self._font = QFont(themes.FONT_FAMILY, themes.FONT_SIZE)

        self.setFont(self._font)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        self._type_timer = QTimer(self)
        self._type_timer.timeout.connect(self._on_type_tick)

    # ---------- Public API ----------

    def setText(self, text: str):
        """Instant set (no animation)."""
        self._type_timer.stop()
        text = text or ""
        self._full_text = text
        self._reveal_pos = len(text)
        if text != self._text:
            self._text = text
            self.update()

    def animateText(self, text: str, cps: int = 55):
        """Reveal text character by character at cps chars per second."""
        text = text or ""
        self._full_text = text
        self._reveal_pos = 0
        self._text = ""
        self.update()
        self._type_timer.stop()
        if not text:
            return
        self._type_timer.start(max(12, int(1000 / max(1, cps))))

    def text(self) -> str:
        return self._text

    def preferred_height(self, width: int | None = None) -> int:
        """
        Minimum height needed to paint the FULL text (not just the revealed
        part) at the given width. Used by the parent window to auto-resize.
        """
        src = self._full_text or self._text
        if not src:
            fm = QFontMetrics(self._font)
            return fm.height() + 2 * getattr(themes, "CAPTION_V_PAD", 2)

        w = width if width is not None else self.width()
        if w <= 0:
            # Layout hasn't given us a width yet; guess from window
            w = max(1, (self.parent().width() if self.parent() else 520) - 100)

        fm = QFontMetrics(self._font)
        line_h = fm.height()
        h_pad = getattr(themes, "CAPTION_H_PAD", 8)
        v_pad = getattr(themes, "CAPTION_V_PAD", 2)
        gap = getattr(themes, "CAPTION_GAP", 2)
        bar_h = line_h + v_pad * 2

        inner_w = max(1, w - h_pad * 2)
        lines = self._wrap_lines(inner_w, src)
        if not lines:
            return bar_h
        return len(lines) * bar_h + max(0, len(lines) - 1) * gap

    # ---------- Typewriter ----------

    def _on_type_tick(self):
        if self._reveal_pos >= len(self._full_text):
            self._type_timer.stop()
            return
        step = 2 if len(self._full_text) > 220 else 1
        self._reveal_pos = min(len(self._full_text), self._reveal_pos + step)
        self._text = self._full_text[: self._reveal_pos]
        self.update()

    # ---------- Wrapping ----------

    def _wrap_lines(self, max_width: int, source: str | None = None) -> list[str]:
        fm = QFontMetrics(self._font)
        lines: list[str] = []

        text = source if source is not None else self._text

        for paragraph in text.split("\n"):
            words = paragraph.split()
            if not words:
                lines.append("")
                continue

            current = words[0]
            for w in words[1:]:
                candidate = current + " " + w
                if fm.horizontalAdvance(candidate) <= max_width:
                    current = candidate
                else:
                    lines.append(current)
                    current = w
            lines.append(current)

        return lines

    # ---------- Painting ----------

    def paintEvent(self, event):
        if not self._text:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(self._font)

        fm = QFontMetrics(self._font)
        line_h = fm.height()

        h_pad = getattr(themes, "CAPTION_H_PAD", 8)
        v_pad = getattr(themes, "CAPTION_V_PAD", 2)
        gap = getattr(themes, "CAPTION_GAP", 2)
        radius = getattr(themes, "CAPTION_RADIUS", 6)

        bar_h = line_h + v_pad * 2
        inner_w = max(1, self.width() - h_pad * 2)
        lines = self._wrap_lines(inner_w)

        total_h = len(lines) * bar_h + max(0, len(lines) - 1) * gap
        y = max(0, (self.height() - total_h) // 2)

        bg = getattr(themes, "CAPTION_BG", QColor(0, 0, 0, 160))
        fg = QColor(themes.FG)

        for line in lines:
            if line:
                text_w = fm.horizontalAdvance(line)
                bar_w = text_w + h_pad * 2
                x = (self.width() - bar_w) // 2

                path = QPainterPath()
                path.addRoundedRect(QRectF(x, y, bar_w, bar_h), radius, radius)
                painter.fillPath(path, bg)

                painter.setPen(fg)
                painter.drawText(
                    QRect(x + h_pad, y + v_pad, text_w, line_h),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    line,
                )

            y += bar_h + gap