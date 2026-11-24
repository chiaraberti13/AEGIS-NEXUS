"""Dependency-free, safe PDF generation for reports.

This writer emits a PDF containing **plain text only**. It never renders HTML,
CSS or JavaScript and uses no headless browser, so attacker-controlled report
content cannot execute or trigger network fetches during export. Text is
escaped for PDF literal strings and encoded to Latin-1 (standard-font glyphs),
with non-representable characters replaced — the attacker's bytes become inert
glyphs, never markup.
"""

from __future__ import annotations

# US Letter, 10pt Helvetica, generous margins.
_PAGE_WIDTH = 612
_PAGE_HEIGHT = 792
_MARGIN = 54
_FONT_SIZE = 10
_LINE_HEIGHT = 14
_WRAP = 95  # characters per line before hard wrap
_LINES_PER_PAGE = (_PAGE_HEIGHT - 2 * _MARGIN) // _LINE_HEIGHT


def _escape(text: str) -> str:
    # Latin-1 only (standard font encoding); drop control chars; escape PDF
    # string delimiters. Attacker content is reduced to inert glyphs.
    encoded = text.encode("latin-1", "replace").decode("latin-1")
    out = []
    for ch in encoded:
        if ch in "\\()":
            out.append("\\" + ch)
        elif ord(ch) < 32:
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _wrap_lines(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for raw in lines:
        line = raw.replace("\t", "    ").rstrip("\n")
        if not line:
            wrapped.append("")
            continue
        while len(line) > _WRAP:
            wrapped.append(line[:_WRAP])
            line = line[_WRAP:]
        wrapped.append(line)
    return wrapped


def _paginate(lines: list[str]) -> list[list[str]]:
    pages = [lines[i:i + _LINES_PER_PAGE] for i in range(0, len(lines), _LINES_PER_PAGE)]
    return pages or [[""]]


def _content_stream(page_lines: list[str]) -> bytes:
    parts = ["BT", f"/F1 {_FONT_SIZE} Tf", f"{_LINE_HEIGHT} TL", f"1 0 0 1 {_MARGIN} {_PAGE_HEIGHT - _MARGIN} Tm"]
    for index, line in enumerate(page_lines):
        if index == 0:
            parts.append(f"({_escape(line)}) Tj")
        else:
            parts.append(f"T* ({_escape(line)}) Tj")
    parts.append("ET")
    return "\n".join(parts).encode("latin-1")


def text_to_pdf(title: str, body: str) -> bytes:
    """Render ``title`` + ``body`` (newline-separated text) to a PDF byte string."""
    lines = _wrap_lines([title, ""] + body.split("\n"))
    pages = _paginate(lines)

    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)  # 1-based object number

    catalog_num = 1  # reserved: catalog is object 1
    pages_num = 2    # reserved: pages tree is object 2
    font_num = 3     # reserved: font is object 3
    objects.extend([b"", b"", b""])  # placeholders for 1..3

    page_nums: list[int] = []
    for page_lines in pages:
        content = _content_stream(page_lines)
        content_num = add(b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content))
        page_obj = (
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] "
            b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
            % (pages_num, _PAGE_WIDTH, _PAGE_HEIGHT, font_num, content_num)
        )
        page_nums.append(add(page_obj))

    objects[catalog_num - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages_num
    kids = b" ".join(b"%d 0 R" % num for num in page_nums)
    objects[pages_num - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_nums))
    objects[font_num - 1] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (index, obj)

    xref_pos = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, catalog_num, xref_pos,
    )
    return bytes(out)
