#!/usr/bin/env python3
"""Generate the repo banner and social-preview images (Pillow, no network).

Usage:  python assets/generate_banner.py
Output: assets/banner.png (1280x640), assets/social-preview.png (1200x630),
        assets/banner.svg (vector twin of banner.png, git-friendly text)
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
BG = (10, 14, 20)
ACCENT = (0, 255, 136)
TEXT = (201, 209, 217)
MUTED = (139, 148, 158)
GRID = (22, 27, 34)
DANGER = (248, 81, 73)

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_DIR / name), size)


def _grid(img: ImageDraw.ImageDraw, w: int, h: int, step: int = 44) -> None:
    for x in range(0, w, step):
        img.line([(x, 0), (x, h)], fill=GRID, width=1)
    for y in range(0, h, step):
        img.line([(0, y), (w, y)], fill=GRID, width=1)


def _accent_bar(img: ImageDraw.ImageDraw, w: int, y: int) -> None:
    img.rectangle([0, y, w, y + 6], fill=ACCENT)


def make(width: int, height: int, out: Path) -> None:
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    _grid(draw, width, height)
    _accent_bar(draw, width, y=height // 5)

    cx = width // 2
    title_font = _font("DejaVuSans-Bold.ttf", int(height * 0.17))
    sub_font = _font("DejaVuSans.ttf", int(height * 0.052))
    small_font = _font("DejaVuSansMono.ttf", int(height * 0.034))

    title = "WiCrackAgent"
    tbox = draw.textbbox((0, 0), title, font=title_font)
    draw.text((cx - (tbox[2] - tbox[0]) / 2, height * 0.26), title,
              font=title_font, fill=ACCENT)

    subtitle = "Automated Wireless Security Assessment"
    sbox = draw.textbbox((0, 0), subtitle, font=sub_font)
    draw.text((cx - (sbox[2] - sbox[0]) / 2, height * 0.52), subtitle,
              font=sub_font, fill=TEXT)

    sub2 = "GPU + CPU dual engine  ·  live web console  ·  pentest reports"
    s2box = draw.textbbox((0, 0), sub2, font=small_font)
    draw.text((cx - (s2box[2] - s2box[0]) / 2, height * 0.64), sub2,
              font=small_font, fill=MUTED)

    line = "pip install wicrack    ->    wicrack serve"
    lbox = draw.textbbox((0, 0), line, font=small_font)
    draw.text((cx - (lbox[2] - lbox[0]) / 2, height * 0.76), line,
              font=small_font, fill=ACCENT)

    warn = "AUTHORIZED USE ONLY"
    wbox = draw.textbbox((0, 0), warn, font=small_font)
    draw.text((cx - (wbox[2] - wbox[0]) / 2, height * 0.88), warn,
              font=small_font, fill=DANGER)

    out.parent.mkdir(parents=True, exist_ok=True)
    image.save(out, "PNG")
    print(f"written: {out} ({out.stat().st_size // 1024} KB)")


def make_svg(out: Path, width: int = 1280, height: int = 640) -> None:
    """Vector twin of make(): same palette/layout, pure text file."""
    bg = "#%02x%02x%02x" % BG
    accent = "#%02x%02x%02x" % ACCENT
    text = "#%02x%02x%02x" % TEXT
    muted = "#%02x%02x%02x" % MUTED
    grid = "#%02x%02x%02x" % GRID
    danger = "#%02x%02x%02x" % DANGER
    cx = width // 2
    step = 44

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{bg}"/>',
    ]
    for x in range(0, width, step):
        parts.append(f'<line x1="{x}" y1="0" x2="{x}" y2="{height}" '
                     f'stroke="{grid}" stroke-width="1"/>')
    for y in range(0, height, step):
        parts.append(f'<line x1="0" y1="{y}" x2="{width}" y2="{y}" '
                     f'stroke="{grid}" stroke-width="1"/>')
    bar_y = height // 5
    parts.append(f'<rect x="0" y="{bar_y}" width="{width}" height="6" '
                 f'fill="{accent}"/>')

    def txt(y_frac: int, size: float, fill: str, weight: str, family: str,
            content: str) -> None:
        parts.append(
            f'<text x="{cx}" y="{int(height * y_frac)}" '
            f'font-family="{family}" font-size="{int(size)}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="middle">'
            f"{content}</text>"
        )

    sans = "DejaVu Sans, Verdana, sans-serif"
    mono = "DejaVu Sans Mono, Consolas, monospace"
    txt(33, height * 0.17, accent, "bold", sans, "WiCrackAgent")
    txt(55, height * 0.052, text, "normal", sans,
        "Automated Wireless Security Assessment")
    txt(67, height * 0.034, muted, "normal", mono,
        "GPU + CPU dual engine &#183; live web console &#183; pentest reports")
    txt(79, height * 0.034, accent, "normal", mono,
        "pip install wicrack &#8594; wicrack serve")
    txt(90, height * 0.034, danger, "normal", mono, "AUTHORIZED USE ONLY")

    parts.append("</svg>")
    out.write_text("\n".join(parts) + "\n", encoding="utf-8")
    print(f"written: {out} ({out.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    make(1280, 640, HERE / "banner.png")
    make(1200, 630, HERE / "social-preview.png")
    make_svg(HERE / "banner.svg")
