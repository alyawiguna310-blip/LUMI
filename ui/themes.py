"""
Minimal dark theme constants for Lumi's interface.
"""
from PyQt6.QtGui import QColor

# Text
FG = "#ffffff"
FONT_FAMILY = "Segoe UI"
FONT_SIZE = 11

# Per-line caption bar (YouTube CC style)
CAPTION_BG = QColor(0, 0, 0, 160)
CAPTION_H_PAD = 8
CAPTION_V_PAD = 2
CAPTION_GAP = 2
CAPTION_RADIUS = 6

# Input pill
ACCENT = "#6c63ff"
INPUT_BG = "rgba(0, 0, 0, 120)"
INPUT_BORDER = "rgba(160, 160, 160, 90)"
INPUT_RADIUS = 14

# Window
WINDOW_WIDTH = 640                 # wider — fits more text per line
WINDOW_HEIGHT = 180                # minimum height; window grows from here
WINDOW_MAX_HEIGHT_FRACTION = 0.85  # cap at 85% of screen height