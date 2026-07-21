"""Renders the app icon (beetle emoji) into a multi-resolution .ico.

Run this manually if the icon ever needs to be regenerated:
    python assets/generate_icon.py

Requires Pillow and a color emoji font (Windows ships Segoe UI Emoji).
"""

import os

from PIL import Image, ImageDraw, ImageFont

EMOJI = "\U0001FAB2"  # beetle
FONT_PATH = r"C:\Windows\Fonts\seguiemj.ttf"
SIZES = [16, 32, 48, 64, 128, 256]
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")


def render(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(FONT_PATH, size=int(size * 0.85))
    bbox = draw.textbbox((0, 0), EMOJI, font=font, embedded_color=True)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
    pos = ((size - w) / 2 - bbox[0], (size - h) / 2 - bbox[1])
    draw.text(pos, EMOJI, font=font, embedded_color=True)
    return img


def main():
    base = render(256)
    base.save(OUTPUT, format="ICO", sizes=[(s, s) for s in SIZES])
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
