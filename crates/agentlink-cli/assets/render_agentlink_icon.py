#!/usr/bin/env python3
"""Build crates/agentlink-cli/assets/agentlink.ico from the octopus sticker SVG.

Requires rsvg-convert (librsvg). 16/20/24/32/40 are palette-snapped so the
notification-area sizes stay crisp. 48 and up keep the antialiased render.
"""

import struct
import subprocess
import zlib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SVG = ROOT / "agentlink-octopus.svg"
ICO = ROOT / "agentlink.ico"

PALETTE = [
    (36, 28, 22),
    (247, 241, 232),
    (92, 200, 210),
    (143, 217, 225),
    (255, 255, 255),
    (238, 141, 150),
    (216, 106, 118),
    (247, 251, 255),
    (223, 227, 230),
    (236, 239, 241),
    (154, 163, 171),
    (215, 246, 248),
]
INK = (36, 28, 22, 255)
CREAM = (247, 241, 232, 255)
CLEAR = (0, 0, 0, 0)
CRISP_SIZES = (16, 20, 24, 32, 40)
SMOOTH_SIZES = (48, 64, 128, 256)
PNG_SIZES = {128, 256}
MASTER = 512

# 16 and 20 are drawn on the pixel grid. Downsampling the sticker loses the
# eyes at those sizes; the tray icon has to stay readable there.
# `.` cream, `#` ink, `T` teal, `W` eye, `P`/`D` mouth, `E` tear, `R` keyring.
HAND = {
    16: [
        "    ########    ",
        "  ##........##  ",
        " #..RR........# ",
        "#..R..R..TTT..#.",
        "#...RR..TWWWT.#.",
        "#......#WW#WW#.#",
        "#......#W#P#WE#.",
        "#.....#TT#D#ET#.",
        "#....#TTTT#TTT#.",
        "#...#T#TT#TTTT#.",
        "#..#T##T#TTTT.#.",
        ".#..#T#T#TTT..#.",
        ".#...#.#TT....#.",
        " #............# ",
        "  ##........##  ",
        "    ########    ",
    ],
    20: [
        "     ##########     ",
        "   ##..........##   ",
        "  #..RR..........#  ",
        " #..R..R...TTT....# ",
        "#...R..R..TWWWT...#.",
        "#....RR..#WW#WW#..#.",
        "#........#W##WW#..#.",
        "#.......#T#PP#E#..#.",
        "#......#TT#DD#ET..#.",
        "#.....#TTTT#TTT#..#.",
        "#....#T#TTT#TTTT..#.",
        "#...#T##TT#TTTT#..#.",
        "#..#T#T#T#TTTTT...#.",
        "#..#T#T#T#TTTT....#.",
        ".#..#T#.#TTT......#.",
        ".#...#..#TT.......#.",
        " #.............#..# ",
        "  #.............##  ",
        "   ##..........##   ",
        "     ##########     ",
    ],
}


def read_png(path):
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise SystemExit(f"not a png: {path}")
    pos = 8
    width = height = color = None
    idat = b""
    while pos < len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        kind = data[pos + 4 : pos + 8]
        chunk = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            width, height, _bit, color = struct.unpack(">IIBB", chunk[:10])
        elif kind == b"IDAT":
            idat += chunk
        elif kind == b"IEND":
            break
    raw = zlib.decompress(idat)
    bpp = 4 if color == 6 else 3
    rows = []
    stride = width * bpp
    index = 0
    prev = bytearray(stride)

    def paeth(left, up, up_left):
        estimate = left + up - up_left
        pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - up_left)
        if pa <= pb and pa <= pc:
            return left
        if pb <= pc:
            return up
        return up_left

    for _y in range(height):
        filt = raw[index]
        index += 1
        row = bytearray(raw[index : index + stride])
        index += stride
        for x in range(len(row)):
            left = row[x - bpp] if x >= bpp else 0
            up = prev[x]
            up_left = prev[x - bpp] if x >= bpp else 0
            if filt == 1:
                row[x] = (row[x] + left) & 255
            elif filt == 2:
                row[x] = (row[x] + up) & 255
            elif filt == 3:
                row[x] = (row[x] + ((left + up) // 2)) & 255
            elif filt == 4:
                row[x] = (row[x] + paeth(left, up, up_left)) & 255
            elif filt != 0:
                raise SystemExit(f"unsupported png filter {filt}")
        prev = bytearray(row)
        if bpp == 4:
            rows.append(bytes(row))
        else:
            rgba = bytearray()
            for x in range(0, len(row), 3):
                rgba += row[x : x + 3] + b"\xff"
            rows.append(bytes(rgba))
    return width, height, rows


def snap(pixel):
    red, green, blue, alpha = pixel
    if alpha < 128:
        return CLEAR
    best = None
    best_distance = 10**9
    for cred, cgreen, cblue in PALETTE:
        distance = (red - cred) ** 2 + (green - cgreen) ** 2 + (blue - cblue) ** 2
        if distance < best_distance:
            best_distance = distance
            best = (cred, cgreen, cblue, 255)
    return best


def render_svg(size, dest):
    subprocess.check_call(
        ["rsvg-convert", "-w", str(size), "-h", str(size), "-o", str(dest), str(SVG)]
    )


def pixels_of(path):
    _w, _h, rows = read_png(path)
    image = []
    for row in rows:
        image.append([tuple(row[x * 4 : x * 4 + 4]) for x in range(len(row) // 4)])
    return image


def in_round_rect(x, y, size, inset, radius):
    radius = max(0.0, radius - inset)
    px, py = x + 0.5, y + 0.5
    left = inset
    right = size - inset
    top = inset
    bottom = size - inset
    cx = min(max(px, left + radius), right - radius)
    cy = min(max(py, top + radius), bottom - radius)
    return (px - cx) ** 2 + (py - cy) ** 2 <= radius * radius + 0.01


def close_sticker_frame(image):
    """Force a solid ink rim so small sizes do not lose the sticker edge."""
    size = len(image)
    radius = max(2.0, round(size * 0.30))
    out = []
    for y in range(size):
        row = []
        for x in range(size):
            if not in_round_rect(x, y, size, 0, radius):
                row.append(CLEAR)
            elif not in_round_rect(x, y, size, 1, radius):
                row.append(INK)
            else:
                pixel = image[y][x]
                row.append(CREAM if pixel[3] == 0 else pixel)
        out.append(row)
    return out


ART = {
    " ": CLEAR,
    ".": CREAM,
    "#": INK,
    "T": (92, 200, 210, 255),
    "L": (143, 217, 225, 255),
    "W": (255, 255, 255, 255),
    "P": (238, 141, 150, 255),
    "D": (216, 106, 118, 255),
    "E": (247, 251, 255, 255),
    "R": (223, 227, 230, 255),
}


def from_art(rows):
    size = len(rows)
    image = []
    for index, row in enumerate(rows):
        if len(row) != size:
            raise SystemExit(f"art row {index} is {len(row)} px, expected {size}")
        image.append([ART[cell] for cell in row])
    return image


def crisp(master, size):
    factor = len(master) // size
    image = []
    for y in range(size):
        row = []
        for x in range(size):
            counts = Counter()
            for dy in range(factor):
                for dx in range(factor):
                    counts[snap(master[y * factor + dy][x * factor + dx])] += 1
            row.append(counts.most_common(1)[0][0])
        image.append(row)
    return close_sticker_frame(image)


def smooth(size, directory):
    path = directory / f"smooth-{size}.png"
    render_svg(size, path)
    image = pixels_of(path)
    # Knock out near-transparent antialias fringe outside the sticker.
    cleaned = []
    for row in image:
        cleaned.append([pixel if pixel[3] >= 32 else CLEAR for pixel in row])
    return cleaned


def dib_for(image):
    size = len(image)
    xor_rows = []
    and_rows = []
    and_stride = ((size + 31) // 32) * 4
    for y in range(size - 1, -1, -1):
        xor_row = bytearray()
        bits = []
        for x in range(size):
            red, green, blue, alpha = image[y][x]
            xor_row += bytes((blue, green, red, alpha))
            bits.append(1 if alpha < 128 else 0)
        xor_rows.append(bytes(xor_row))
        mask = bytearray(and_stride)
        for index, bit in enumerate(bits):
            if bit:
                mask[index // 8] |= 0x80 >> (index % 8)
        and_rows.append(bytes(mask))
    xor = b"".join(xor_rows)
    mask = b"".join(and_rows)
    header = struct.pack(
        "<IiiHHIIiiII",
        40,
        size,
        size * 2,
        1,
        32,
        0,
        len(xor) + len(mask),
        0,
        0,
        0,
        0,
    )
    return header + xor + mask


def png_bytes(image):
    height = len(image)
    width = len(image[0])
    raw = bytearray()
    for row in image:
        raw.append(0)
        for red, green, blue, alpha in row:
            raw += bytes((red, green, blue, alpha))

    def chunk(tag, payload):
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def write_ico(images, dest):
    count = len(images)
    header = struct.pack("<HHH", 0, 1, count)
    entries = b""
    blobs = []
    offset = 6 + count * 16
    for size, image in images:
        blob = png_bytes(image) if size in PNG_SIZES else dib_for(image)
        blobs.append(blob)
        width_byte = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII",
            width_byte,
            width_byte,
            0,
            0,
            1,
            32,
            len(blob),
            offset,
        )
        offset += len(blob)
    dest.write_bytes(header + entries + b"".join(blobs))


def main():
    tmp = Path("/tmp/agentlink-icon")
    tmp.mkdir(parents=True, exist_ok=True)
    master_path = tmp / "master.png"
    render_svg(MASTER, master_path)
    master = pixels_of(master_path)
    images = []
    for size in CRISP_SIZES:
        if size in HAND:
            images.append((size, from_art(HAND[size])))
        else:
            images.append((size, crisp(master, size)))
    images += [(size, smooth(size, tmp)) for size in SMOOTH_SIZES]
    write_ico(images, ICO)
    print(f"wrote {ICO} ({ICO.stat().st_size} bytes, {len(images)} sizes)")


if __name__ == "__main__":
    main()
