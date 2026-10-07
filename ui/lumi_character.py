"""
Lumi's lightweight animated character.

Procedural 2D character rendered with QPainter. No emoji, video, or large
sprite sheets are required. Animation is driven by the assistant state and
kept intentionally small to fit low-RAM machines.
"""
import math

from PyQt6.QtCore import Qt, QTimer, QPointF, QRectF
from PyQt6.QtGui import QPainter, QPainterPath, QColor, QPen
from PyQt6.QtWidgets import QWidget


class LumiCharacter(QWidget):
    """Small state-driven 2D character with expressive face animation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(96, 112)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

        self._emotion = "neutral"
        self._speaking = False
        self._blink = False
        self._tick = 0
        self._bob = 0.0
        self._squash = 1.0

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_tick)
        self._timer.start(50)  # 20 FPS: smooth enough, still lightweight

        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._start_blink)
        self._blink_timer.start(3200)

    def set_emotion(self, emotion: str):
        emotion = str(emotion or "neutral").lower()
        if emotion != self._emotion:
            self._emotion = emotion
            self.update()

    def set_speaking(self, speaking: bool):
        speaking = bool(speaking)
        if speaking != self._speaking:
            self._speaking = speaking
            self.update()

    def _on_tick(self):
        self._tick += 1
        phase = self._tick * 0.11

        if self._speaking:
            self._bob = math.sin(phase) * 2.0
            self._squash = 1.0 + math.sin(phase * 1.8) * 0.018
        elif self._emotion in ("happy", "excited", "laughing"):
            self._bob = math.sin(phase) * 1.7
            self._squash = 1.0 + math.sin(phase) * 0.012
        elif self._emotion in ("angry", "annoyed"):
            self._bob = math.sin(phase * 0.7) * 0.6
            self._squash = 1.0
        else:
            self._bob = math.sin(phase) * 1.0
            self._squash = 1.0

        self.update()

    def _start_blink(self):
        if self._blink or self._emotion in ("sleepy",):
            return
        self._blink = True
        self.update()
        QTimer.singleShot(125, self._end_blink)

    def _end_blink(self):
        self._blink = False
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        cx = self.width() / 2
        # Keep the character centered while allowing the bob to move her.
        cy = 57 + self._bob

        hair = QColor("#33264d")
        hair_light = QColor("#65558e")
        hair_shadow = QColor("#241b37")
        skin = QColor("#ffe3d2")
        skin_shadow = QColor("#f2c7b8")
        eye = QColor("#30233f")
        eye_light = QColor("#ffffff")
        mouth = QColor("#673d50")
        outfit = QColor("#7568b7")
        outfit_dark = QColor("#4b427d")
        accent = QColor("#c6b9ff")
        blush = QColor(245, 112, 145, 115)

        p.save()
        p.translate(cx, cy)
        p.scale(self._squash, 1.0)

        # Soft shoulder / outfit silhouette.
        shoulders = QPainterPath()
        shoulders.moveTo(-37, 50)
        shoulders.quadTo(-31, 35, -19, 31)
        shoulders.lineTo(19, 31)
        shoulders.quadTo(31, 35, 37, 50)
        shoulders.closeSubpath()
        p.fillPath(shoulders, outfit_dark)

        body = QPainterPath()
        body.moveTo(-29, 50)
        body.quadTo(-27, 34, -16, 30)
        body.lineTo(16, 30)
        body.quadTo(27, 34, 29, 50)
        body.closeSubpath()
        p.fillPath(body, outfit)

        # Collar and small ribbon.
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(skin)
        p.drawPolygon([
            QPointF(-10, 29), QPointF(0, 38), QPointF(10, 29),
        ])
        p.setBrush(accent)
        p.drawEllipse(QPointF(0, 39), 4.0, 4.0)
        p.setBrush(outfit_dark)
        p.drawEllipse(QPointF(0, 39), 1.7, 1.7)

        # Long side hair behind the face.
        back = QPainterPath()
        back.moveTo(-29, -4)
        back.cubicTo(-39, 8, -38, 34, -28, 43)
        back.cubicTo(-22, 48, -18, 34, -20, 19)
        back.lineTo(-14, -15)
        back.closeSubpath()
        p.fillPath(back, hair_shadow)

        back_r = QPainterPath()
        back_r.moveTo(29, -4)
        back_r.cubicTo(39, 8, 38, 34, 28, 43)
        back_r.cubicTo(22, 48, 18, 34, 20, 19)
        back_r.lineTo(14, -15)
        back_r.closeSubpath()
        p.fillPath(back_r, hair_shadow)

        # Main hair mass.
        p.setBrush(hair)
        p.drawEllipse(QPointF(0, -3), 34, 39)

        # Face, slightly narrower than the hair.
        face = QPainterPath()
        face.moveTo(-25, -3)
        face.cubicTo(-26, 13, -22, 29, 0, 34)
        face.cubicTo(22, 29, 26, 13, 25, -3)
        face.cubicTo(21, -21, -21, -21, -25, -3)
        face.closeSubpath()
        p.fillPath(face, skin)

        # Ears / side locks.
        p.setBrush(hair_light)
        p.drawEllipse(QPointF(-27, 8), 5, 13)
        p.drawEllipse(QPointF(27, 8), 5, 13)

        # Bangs: multiple locks give a more character-like silhouette.
        bangs = QPainterPath()
        bangs.moveTo(-29, -7)
        bangs.cubicTo(-25, -27, -7, -32, 0, -29)
        bangs.cubicTo(10, -33, 25, -24, 29, -7)
        bangs.lineTo(20, -4)
        bangs.cubicTo(15, -12, 12, -17, 8, -20)
        bangs.cubicTo(6, -11, 4, -6, 0, -3)
        bangs.cubicTo(-4, -8, -6, -15, -8, -20)
        bangs.cubicTo(-13, -13, -17, -7, -22, -4)
        bangs.closeSubpath()
        p.fillPath(bangs, hair)

        # Hair highlight.
        highlight = QPainterPath()
        highlight.moveTo(-19, -19)
        highlight.cubicTo(-10, -27, 2, -29, 10, -24)
        highlight.cubicTo(3, -23, -7, -20, -15, -14)
        highlight.closeSubpath()
        p.fillPath(highlight, hair_light)

        # Emotion-specific blush.
        if self._emotion in (
            "happy", "excited", "laughing", "embarrassed", "annoyed", "confused"
        ):
            p.setBrush(blush)
            p.drawEllipse(QPointF(-17, 15), 7, 3)
            p.drawEllipse(QPointF(17, 15), 7, 3)

        # Brows communicate the stronger emotions.
        self._draw_brows(p, eye, self._emotion)

        # Eyes.
        self._draw_eye(p, -13, 5, eye, eye_light, False)
        self._draw_eye(p, 13, 5, eye, eye_light, True)

        # Nose + mouth.
        p.setPen(QPen(skin_shadow, 1.2))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawLine(QPointF(-1, 12), QPointF(1, 13))

        self._draw_mouth(p, 0, 21, mouth)

        # Tiny animated sparkle when excited/happy.
        if self._emotion in ("excited", "happy"):
            pulse = 1.0 + 0.25 * math.sin(self._tick * 0.22)
            self._draw_sparkle(p, -36, -22, 3.5 * pulse)
            self._draw_sparkle(p, 36, -5, 2.7 * pulse)

        p.restore()

    def _draw_brows(self, p, color, emotion):
        p.setPen(QPen(color, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)

        if emotion in ("angry", "annoyed"):
            p.drawLine(QPointF(-19, -5), QPointF(-7, -2))
            p.drawLine(QPointF(7, -2), QPointF(19, -5))
        elif emotion in ("surprised", "confused", "worried"):
            p.drawArc(QRectF(-20, -9, 13, 6), 20 * 16, 130 * 16)
            p.drawArc(QRectF(7, -9, 13, 6), 30 * 16, 130 * 16)
        elif emotion == "happy":
            p.drawArc(QRectF(-20, -6, 13, 5), 20 * 16, 140 * 16)
            p.drawArc(QRectF(7, -6, 13, 5), 20 * 16, 140 * 16)

    def _draw_eye(self, p, x, y, color, highlight, is_right):
        if self._blink or self._emotion == "sleepy":
            p.setPen(QPen(color, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            path.moveTo(x - 6, y)
            path.quadTo(x, y + (3 if self._emotion == "sleepy" else 2), x + 6, y)
            p.drawPath(path)
            return

        if self._emotion == "happy":
            p.setPen(QPen(color, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.setBrush(Qt.BrushStyle.NoBrush)
            path = QPainterPath()
            path.moveTo(x - 6, y + 1)
            path.quadTo(x, y - 6, x + 6, y + 1)
            p.drawPath(path)
            return

        if self._emotion == "annoyed":
            p.setPen(QPen(color, 2.0))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawLine(QPointF(x - 6, y - 1), QPointF(x + 6, y - 1))
            return

        # Large expressive eye.
        eye_h = 7 if self._emotion in ("surprised", "excited") else 6
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(color)
        p.drawEllipse(QPointF(x, y), 5.2, eye_h)

        # Subtle pupil direction based on the current animation phase.
        look = math.sin(self._tick * 0.025) * 0.9
        if self._emotion == "thinking":
            look = -1.5
        if is_right and self._emotion == "confused":
            look = 1.5

        p.setBrush(highlight)
        p.drawEllipse(QPointF(x - 1.4 + look, y - 2.0), 1.7, 1.7)
        p.setBrush(QColor("#a998d8"))
        p.drawEllipse(QPointF(x + 1.1 + look, y + 2.0), 1.0, 1.5)

    def _draw_mouth(self, p, x, y, color):
        p.setPen(QPen(color, 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)

        if self._speaking:
            open_phase = (self._tick // 2) % 3
            if open_phase == 0:
                p.setBrush(color)
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(x, y), 4.0, 5.0)
            elif open_phase == 1:
                p.setBrush(color)
                p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(x, y), 3.0, 2.4)
            else:
                p.drawLine(QPointF(x - 3.5, y), QPointF(x + 3.5, y))
            return

        if self._emotion in ("happy", "excited", "laughing"):
            path = QPainterPath()
            path.moveTo(x - 6, y - 1)
            path.quadTo(x, y + 7, x + 6, y - 1)
            p.drawPath(path)
            return

        if self._emotion in ("surprised",):
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y + 1), 3.5, 5)
            return

        if self._emotion in ("sad", "worried"):
            path = QPainterPath()
            path.moveTo(x - 5, y + 2)
            path.quadTo(x, y - 3, x + 5, y + 2)
            p.drawPath(path)
            return

        if self._emotion in ("angry", "annoyed"):
            p.drawLine(QPointF(x - 5, y + 1), QPointF(x + 5, y + 1))
            return

        if self._emotion == "sleepy":
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 2.8, 2.2)
            return

        if self._emotion == "thinking":
            p.setPen(QPen(color, 1.5))
            p.drawLine(QPointF(x - 3, y), QPointF(x + 3, y))
            return

        # Neutral / curious / confused.
        path = QPainterPath()
        path.moveTo(x - 4, y)
        path.quadTo(x, y + 2, x + 4, y)
        p.drawPath(path)

    @staticmethod
    def _draw_sparkle(p, x, y, size):
        pen = QPen(QColor("#cfc7ff"), 1.4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCapCap)
        p.setPen(pen)
        p.drawLine(QPointF(x - size, y), QPointF(x + size, y))
        p.drawLine(QPointF(x, y - size), QPointF(x, y + size))
