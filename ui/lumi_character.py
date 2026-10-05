"""
Lumi's animated character. Drawn with QPainter — no sprite assets needed.

Reacts to emotion, blinks, bobs while idle, and animates her mouth
while TTS is playing.
"""
import math

from PyQt6.QtCore import Qt, QTimer, QPointF
from PyQt6.QtGui import QPainter, QPainterPath, QColor, QPen
from PyQt6.QtWidgets import QWidget


class LumiCharacter(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(64, 64)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        self._emotion = "neutral"
        self._speaking = False
        self._blink = False
        self._tick = 0
        self._bob = 0.0

        # Idle animation timer (~12 fps)
        self._idle_timer = QTimer(self)
        self._idle_timer.timeout.connect(self._on_tick)
        self._idle_timer.start(85)

        # Blink timer
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._start_blink)
        self._blink_timer.start(3400)

    # ---------- Public API ----------

    def set_emotion(self, emotion: str):
        if emotion != self._emotion:
            self._emotion = emotion
            self.update()

    def set_speaking(self, speaking: bool):
        if speaking != self._speaking:
            self._speaking = speaking
            self.update()

    # ---------- Animation ticks ----------

    def _on_tick(self):
        self._tick += 1
        # Gentle vertical bob while idle; stronger while speaking
        amp = 2.0 if self._speaking else 1.2
        self._bob = math.sin(self._tick * 0.13) * amp
        self.update()

    def _start_blink(self):
        if self._blink:
            return
        self._blink = True
        self.update()
        QTimer.singleShot(140, self._end_blink)

    def _end_blink(self):
        self._blink = False
        self.update()

    # ---------- Painting ----------

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.translate(0, self._bob)

        cx = self.width() / 2
        cy = self.height() / 2 + 3
        head_r = self.width() * 0.32

        hair_c = QColor("#3d2d5c")
        hair_hi = QColor("#5a4a82")
        face_c = QColor("#ffe4d4")
        eye_c = QColor("#3d2d5c")
        eye_hl = QColor("#ffffff")
        mouth_c = QColor("#5a3a4a")
        blush_c = QColor(255, 140, 160, 110)

        # --- Back hair silhouette ---
        hair_back = QPainterPath()
        hair_back.addEllipse(QPointF(cx, cy - 3), head_r + 4, head_r + 3)
        p.fillPath(hair_back, hair_c)

        # --- Face ---
        face = QPainterPath()
        face.addEllipse(QPointF(cx, cy), head_r, head_r * 0.95)
        p.fillPath(face, face_c)

        # --- Bangs ---
        bangs = QPainterPath()
        bangs.moveTo(cx - head_r - 3, cy - 4)
        bangs.cubicTo(
            cx - head_r - 3, cy - head_r - 8,
            cx + head_r + 3, cy - head_r - 8,
            cx + head_r + 3, cy - 4,
        )
        bangs.lineTo(cx + head_r - 2, cy - 2)
        bangs.cubicTo(
            cx + head_r * 0.4, cy - head_r * 0.4,
            cx - head_r * 0.4, cy - head_r * 0.4,
            cx - head_r + 2, cy - 2,
        )
        bangs.closeSubpath()
        p.fillPath(bangs, hair_c)

        # --- Hair highlight ---
        hl = QPainterPath()
        hl.addEllipse(QPointF(cx - 6, cy - head_r * 0.6), 8, 3)
        p.setBrush(hair_hi)
        p.setPen(Qt.PenStyle.NoPen)
        p.fillPath(hl, hair_hi)

        # --- Blush ---
        if self._emotion in ("happy", "annoyed", "confused"):
            p.setBrush(blush_c)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(cx - head_r * 0.55, cy + head_r * 0.25), 4, 2.5)
            p.drawEllipse(QPointF(cx + head_r * 0.55, cy + head_r * 0.25), 4, 2.5)

        # --- Eyes ---
        eye_y = cy + 1
        eye_dx = head_r * 0.42
        self._draw_eye(p, cx - eye_dx, eye_y, eye_c, eye_hl, is_right=False)
        self._draw_eye(p, cx + eye_dx, eye_y, eye_c, eye_hl, is_right=True)

        # --- Mouth ---
        self._draw_mouth(p, cx, cy + head_r * 0.45, mouth_c)

    def _draw_eye(self, p, x, y, eye_c, hl_c, is_right: bool):
        # Blink / sleepy — closed arc
        if self._blink or self._emotion == "sleepy":
            p.setPen(QPen(eye_c, 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            path.moveTo(x - 4, y)
            path.quadTo(x, y + 3, x + 4, y)
            p.drawPath(path)
            return

        # Happy — ^ ^
        if self._emotion == "happy":
            p.setPen(QPen(eye_c, 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            path.moveTo(x - 4, y + 1)
            path.lineTo(x, y - 3)
            path.lineTo(x + 4, y + 1)
            p.drawPath(path)
            return

        # Annoyed — half-lidded
        if self._emotion == "annoyed":
            p.setPen(QPen(eye_c, 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawLine(QPointF(x - 4, y - 1), QPointF(x + 4, y - 1))
            p.setBrush(eye_c)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y + 1), 2.5, 2)
            return

        # Thinking — looking up
        if self._emotion == "thinking":
            p.setBrush(eye_c)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y - 1.5), 3, 3)
            return

        # Confused — one eye becomes ><
        if self._emotion == "confused" and is_right:
            p.setPen(QPen(eye_c, 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawLine(QPointF(x - 4, y - 2), QPointF(x + 4, y + 2))
            p.drawLine(QPointF(x - 4, y + 2), QPointF(x + 4, y - 2))
            return

        # Normal round eyes
        p.setBrush(eye_c)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(QPointF(x, y), 3.2, 3.8)
        p.setBrush(hl_c)
        p.drawEllipse(QPointF(x - 1, y - 1.5), 1.1, 1.1)

    def _draw_mouth(self, p, x, y, color):
        # Speaking overrides everything — mouth flaps
        if self._speaking:
            open_phase = (self._tick // 2) % 2 == 0
            if open_phase:
                p.setBrush(color)
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(x, y), 2.6, 3.6)
            else:
                p.setPen(QPen(color, 1.6))
                p.drawLine(QPointF(x - 2.5, y), QPointF(x + 2.5, y))
            return

        p.setPen(QPen(color, 1.7))
        p.setBrush(Qt.BrushStyle.NoBrush)

        if self._emotion == "happy":
            path = QPainterPath()
            path.moveTo(x - 4, y - 1)
            path.quadTo(x, y + 3, x + 4, y - 1)
            p.drawPath(path)
            return

        if self._emotion == "annoyed":
            path = QPainterPath()
            path.moveTo(x - 4, y + 1)
            path.quadTo(x, y - 2, x + 4, y + 1)
            p.drawPath(path)
            return

        if self._emotion == "sleepy":
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 2.2, 2.8)
            return

        if self._emotion == "thinking":
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 1.8, 1.8)
            return

        if self._emotion == "confused":
            path = QPainterPath()
            path.moveTo(x - 4, y)
            path.quadTo(x - 2, y - 2, x, y)
            path.quadTo(x + 2, y + 2, x + 4, y)
            p.drawPath(path)
            return

        # Neutral — tiny line
        p.drawLine(QPointF(x - 2.5, y), QPointF(x + 2.5, y))