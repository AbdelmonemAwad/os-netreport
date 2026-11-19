#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""A small PDF writer for the report, in the standard library alone: A4 pages of headings,
paragraphs, lists, figure boxes and tables, set in one embedded TrueType font, left to right
or right to left. Arabic and Persian letters are shaped and lines reordered here, since the
firewall has no PDF or text-shaping library to lean on.

    pdf.render(blocks, direction='ltr', title='', font_path=None) -> bytes

blocks, in order:
    ('title', text)  ('subtitle', text)  ('h2', text)  ('h3', text)
    ('p', text, style)                    style: normal, muted, ok, warn, bad
    ('list', [(text, style), ...])
    ('kpis', [(value, label, note), ...])
    ('table', headers, rows)              a cell may hold '\\n' line breaks
"""
import hashlib
import io
import os
import struct
import unicodedata
import zlib

DEFAULT_FONT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fonts', 'DejaVuSans.ttf')

PAGE_W, PAGE_H = 595, 842
LEFT, RIGHT, TOP, BOTTOM = 40, PAGE_W - 40, PAGE_H - 40, 50
WIDTH = RIGHT - LEFT
FOOTER_TOP = 32
LEAD = 1.35
KEEP = 36           # room a heading wants below it, or it moves to the next page
CELL, CELL_PAD = 8.5, 4
KPI_MIN, KPI_GAP, KPI_PAD = 110, 8, 6

TEXT = (0.13, 0.13, 0.13)
MUTED = (0.42, 0.42, 0.42)
ACCENT = (0.11, 0.24, 0.42)
STYLES = {
    'normal': (TEXT, 9),
    'muted': (MUTED, 8),
    'ok': ((0.08, 0.46, 0.20), 9),
    'warn': ((0.72, 0.43, 0.0), 9),
    'bad': ((0.77, 0.12, 0.12), 9),
}
HEAD_FILL, STRIPE, RULE = 0.88, 0.965, 0.80
BOX_FILL, BOX_LINE = 0.965, 0.80

LAM = '\u0644'
LAM_ALEF = ('\u0627', '\u0622', '\u0623', '\u0625')
BIDI_MARKS = ('\u200e', '\u200f', '\u061c')         # LRM, RLM, ALM: steer the order, draw nothing
LRI, RLI, FSI, PDI = '\u2066', '\u2067', '\u2068', '\u2069'
ISOLATE_OPEN = (LRI, RLI, FSI)
OPENERS = {'(': ')', '[': ']', '{': '}', '\u00ab': '\u00bb', '\u2039': '\u203a'}
MIRROR = {}
for _open, _close in list(OPENERS.items()) + [('<', '>')]:
    MIRROR[_open], MIRROR[_close] = _close, _open


# ---------------------------------------------------------------- the font

class Font:
    """A TrueType font read from its file: glyph ids by character, advance widths and the metrics the PDF needs."""

    def __init__(self, path, data=None):
        if data is None:
            with open(path, 'rb') as fh:
                data = fh.read()
        self.data = data
        stem = os.path.splitext(os.path.basename(path or 'Font'))[0]
        self.name = ''.join(c for c in stem if c.isalnum() or c in '-_') or 'Font'
        count = struct.unpack_from('>H', data, 4)[0]
        tables = {}
        for i in range(count):
            tag, _, offset, length = struct.unpack_from('>4sIII', data, 12 + 16 * i)
            tables[tag.decode('latin-1')] = (offset, length)
        self.tables = tables
        head = tables['head'][0]
        self.upem = struct.unpack_from('>H', data, head + 18)[0]
        self.bbox = struct.unpack_from('>hhhh', data, head + 36)
        self.long_loca = struct.unpack_from('>h', data, head + 50)[0] == 1
        hhea = tables['hhea'][0]
        self.ascent, self.descent = struct.unpack_from('>hh', data, hhea + 4)
        metrics = struct.unpack_from('>H', data, hhea + 34)[0]
        glyphs = struct.unpack_from('>H', data, tables['maxp'][0] + 4)[0]
        self.cap = self.ascent
        if 'OS/2' in tables:
            os2, length = tables['OS/2']
            version = struct.unpack_from('>H', data, os2)[0]
            typo_asc, typo_desc = struct.unpack_from('>hh', data, os2 + 68)
            if not self.ascent and typo_asc:
                self.ascent, self.descent = typo_asc, typo_desc
            if version >= 2 and length >= 90:
                self.cap = struct.unpack_from('>h', data, os2 + 88)[0] or self.ascent
        self.italic = 0.0
        if 'post' in tables:
            self.italic = struct.unpack_from('>i', data, tables['post'][0] + 4)[0] / 65536.0
        advances = list(struct.unpack_from('>%dH' % (2 * metrics), data, tables['hmtx'][0])[::2])
        advances += [advances[-1]] * max(0, glyphs - metrics)
        self.widths = [int(round(a * 1000.0 / self.upem)) for a in advances]
        self.cmap = {}
        if 'cmap' in tables:
            self._read_cmap(tables['cmap'][0])

    def _read_cmap(self, base):
        """Fill self.cmap from the Unicode subtables: format 4 first, then format 12 over it."""
        data = self.data
        found = {}
        for i in range(struct.unpack_from('>H', data, base + 2)[0]):
            platform, encoding, offset = struct.unpack_from('>HHI', data, base + 4 + 8 * i)
            if platform == 0 or (platform == 3 and encoding in (1, 10)):
                found[base + offset] = struct.unpack_from('>H', data, base + offset)[0]
        for offset, fmt in sorted(found.items(), key=lambda item: (item[1] == 12, item[0])):
            if fmt == 4:
                self._cmap4(offset)
            elif fmt == 12:
                self._cmap12(offset)

    def _cmap4(self, off):
        data = self.data
        segs = struct.unpack_from('>H', data, off + 6)[0] // 2
        ends = struct.unpack_from('>%dH' % segs, data, off + 14)
        starts = struct.unpack_from('>%dH' % segs, data, off + 16 + 2 * segs)
        deltas = struct.unpack_from('>%dh' % segs, data, off + 16 + 4 * segs)
        at = off + 16 + 6 * segs
        ranges = struct.unpack_from('>%dH' % segs, data, at)
        for i in range(segs):
            for code in range(starts[i], ends[i] + 1):
                if code == 0xFFFF:
                    break
                if ranges[i] == 0:
                    gid = (code + deltas[i]) & 0xFFFF
                else:
                    gid = struct.unpack_from('>H', data, at + 2 * i + ranges[i] + 2 * (code - starts[i]))[0]
                    gid = (gid + deltas[i]) & 0xFFFF if gid else 0
                if 0 < gid < len(self.widths):
                    self.cmap[code] = gid

    def _cmap12(self, off):
        groups = struct.unpack_from('>I', self.data, off + 12)[0]
        for i in range(groups):
            start, end, gid = struct.unpack_from('>III', self.data, off + 16 + 12 * i)
            for code in range(start, min(end, 0x10FFFF) + 1):
                if 0 < gid + code - start < len(self.widths):
                    self.cmap[code] = gid + code - start

    def has(self, ch):
        """Whether the font draws this character."""
        return ord(ch) in self.cmap

    def outline(self, gid):
        """Where a glyph's outline lies in the file: (start, end), equal when the glyph is empty."""
        if 'glyf' not in self.tables or 'loca' not in self.tables:
            return 0, 0
        loca = self.tables['loca'][0]
        if self.long_loca:
            start, end = struct.unpack_from('>II', self.data, loca + 4 * gid)
        else:
            start, end = (2 * v for v in struct.unpack_from('>HH', self.data, loca + 2 * gid))
        base = self.tables['glyf'][0]
        return base + start, base + max(start, end)

    def components(self, gid):
        """The glyph ids a composite glyph is built from (none for a simple glyph)."""
        start, end = self.outline(gid)
        if end - start < 10 or struct.unpack_from('>h', self.data, start)[0] >= 0:
            return []
        out, at = [], start + 10
        while at + 4 <= end:
            flags, part = struct.unpack_from('>HH', self.data, at)
            out.append(part)
            at += 4 + (4 if flags & 0x0001 else 2)
            at += 8 if flags & 0x0080 else 4 if flags & 0x0040 else 2 if flags & 0x0008 else 0
            if not flags & 0x0020:
                break
        return out

    def leads(self, gid):
        """Whether a zero-width mark is drawn from the left edge of its letter (its outline lies
        right of its origin, as Arabic harakat do here) rather than hanging back from the letter's
        right edge (as Latin accents do)."""
        start, end = self.outline(gid)
        if self.widths[gid] or end <= start:
            return False
        x_min, _, x_max = struct.unpack_from('>hhh', self.data, start + 2)
        return x_min + x_max > 0

    def scale(self, value):
        """A value in font units, in thousandths of the font size."""
        return int(round(value * 1000.0 / self.upem))


_FONTS = {}


def load_font(path=None):
    """The font at path (the shipped one by default), read once per process."""
    path = os.path.abspath(path or DEFAULT_FONT)
    if path not in _FONTS:
        _FONTS[path] = Font(path)
    return _FONTS[path]


# ---------------------------------------------------------------- Arabic shaping

_FORMS = {}


def forms(ch):
    """The presentation forms Unicode names for an Arabic letter: {'isol', 'fina', 'init', 'medi'} to characters."""
    if ch not in _FORMS:
        found = {}
        cp = ord(ch)
        if 0x0620 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F:
            name = unicodedata.name(ch, '')
            if name.startswith('ARABIC LETTER '):
                for key, suffix in (('isol', 'ISOLATED'), ('fina', 'FINAL'), ('init', 'INITIAL'), ('medi', 'MEDIAL')):
                    try:
                        found[key] = unicodedata.lookup('%s %s FORM' % (name, suffix))
                    except KeyError:
                        pass
        _FORMS[ch] = found
    return _FORMS[ch]


def joining(ch):
    """The joining type of a character: D joins on both sides, R only to the letter before it,
    C causes joining (tatweel, ZWJ), T is transparent (harakat and other marks), U does not join."""
    if ch in ('\u0640', '\u200d'):
        return 'C'
    if ch == '\u200c':
        return 'U'
    if unicodedata.category(ch) in ('Mn', 'Me', 'Cf'):
        return 'T'
    found = forms(ch)
    if 'init' in found or 'medi' in found:
        return 'D'
    return 'R' if 'fina' in found else 'U'


def ligature(alef, final):
    """The lam-alef ligature for this alef, final or isolated form, or None."""
    rest = unicodedata.name(alef, '')[len('ARABIC LETTER '):]
    try:
        return unicodedata.lookup('ARABIC LIGATURE LAM WITH %s %s FORM' % (rest, 'FINAL' if final else 'ISOLATED'))
    except KeyError:
        return None


def shape(text, font):
    """Text with each Arabic letter replaced by its form for its place in the word, and lam-alef by
    its ligature, where the font has the glyph: a list of (shown, original) pairs in logical order."""
    kinds = [joining(c) for c in text]
    n = len(text)

    def neighbour(i, step):
        i += step
        while 0 <= i < n and kinds[i] == 'T':
            i += step
        return kinds[i] if 0 <= i < n else 'U'

    out = []
    i = 0
    while i < n:
        ch, kind = text[i], kinds[i]
        if kind not in ('D', 'R'):
            out.append((ch, ch))
            i += 1
            continue
        joins_before = neighbour(i, -1) in ('D', 'C')
        if ch == LAM and i + 1 < n and text[i + 1] in LAM_ALEF:
            lig = ligature(text[i + 1], joins_before)
            if lig and font.has(lig):
                out.append((lig, text[i:i + 2]))
                i += 2
                continue
        joins_after = kind == 'D' and neighbour(i, 1) in ('D', 'R', 'C')
        if joins_before:
            form = 'medi' if joins_after else 'fina'
        else:
            form = 'init' if joins_after else 'isol'
        shown = forms(ch).get(form)
        out.append((shown if shown and font.has(shown) else ch, ch))
        i += 1
    return out


# ---------------------------------------------------------------- clusters, wrapping, bidi

class Cluster:
    """One drawn unit: a base character with any marks on it. glyphs holds (gid, shown, original)
    for each glyph; width is in thousandths of the font size; char is the original base character."""
    __slots__ = ('char', 'glyphs', 'width')

    def __init__(self, char, glyphs, width=0):
        self.char, self.glyphs, self.width = char, glyphs, width


class Isolate:
    """Text set apart by LRI or RLI ... PDI: laid out in its own direction, and placed in the
    line around it as one unit that counts as a neutral there."""
    __slots__ = ('rtl', 'items')

    def __init__(self, rtl):
        self.rtl, self.items = rtl, []


def dropped(ch):
    """Whether a character is left out before anything else: embedding and override controls,
    variation selectors, zero-width spaces, the soft hyphen and control characters. (Isolates
    are kept until the line is ordered, and never drawn.)"""
    cp = ord(ch)
    return (0x202A <= cp <= 0x202E or 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF
            or cp in (0x200B, 0x2060, 0xFEFF, 0x00AD) or unicodedata.category(ch) == 'Cc')


def first_strong(items, start):
    """The isolate an FSI at start stands for: RLI when the first strong letter after it (up to
    its PDI, nested isolates skipped) runs right to left, else LRI."""
    depth = 0
    for cl in items[start + 1:]:
        if cl.char in ISOLATE_OPEN:
            depth += 1
        elif cl.char == PDI:
            if not depth:
                break
            depth -= 1
        elif not depth:
            kind = unicodedata.bidirectional(cl.char)
            if kind in ('R', 'AL'):
                return RLI
            if kind == 'L':
                return LRI
    return LRI


def clusters(text, font):
    """One line of text as clusters in logical order: shaped, marks joined to the letter before
    them, and characters the font cannot draw (emoji, CJK) left out. Direction marks and isolates
    stay as clusters with no glyph; an FSI becomes the LRI or RLI it stands for."""
    text = unicodedata.normalize('NFC', str(text).replace('\t', ' '))
    text = ''.join(c for c in text if not dropped(c))
    out = []
    for shown, orig in shape(text, font):
        if orig in ('\u200c', '\u200d'):
            continue
        if orig in BIDI_MARKS or orig in ISOLATE_OPEN or orig == PDI:
            out.append(Cluster(orig, []))
            continue
        gid = font.cmap.get(ord(shown), 0)
        if not gid:
            continue
        glyph = (gid, shown, orig)
        if unicodedata.category(orig[0]) in ('Mn', 'Me') and out and out[-1].glyphs and out[-1].char != ' ':
            out[-1].glyphs.append(glyph)
            out[-1].width += font.widths[gid]
            continue
        out.append(Cluster(orig[0], [glyph], font.widths[gid]))
    for i, cl in enumerate(out):
        if cl.char == FSI:
            out[i] = Cluster(first_strong(out, i), [])
    return out


def carry(lines):
    """Wrapped lines of one paragraph, with each isolate still open at the end of a line opened
    again at the start of the next, so a value broken across lines keeps its direction."""
    out, stack = [], []
    for line in lines:
        line = [Cluster(c, []) for c in stack] + line
        stack = []
        for cl in line:
            if cl.char in ISOLATE_OPEN:
                stack.append(cl.char)
            elif cl.char == PDI and stack:
                stack.pop()
        out.append(line)
    return out


def wrap(line, limit):
    """Clusters broken into lines no wider than limit (thousandths of the font size): at spaces,
    and inside a word only when that word alone is wider than a line."""
    words, word, gap = [], [], None
    for cl in line:
        if cl.char == ' ':
            if word:
                words.append((gap, word))
                word = []
            gap = cl
        else:
            word.append(cl)
    if word:
        words.append((gap, word))
    lines, cur, width = [], [], 0
    for gap, word in words:
        size = sum(c.width for c in word)
        if cur and width + gap.width + size <= limit:
            cur.append(gap)
            cur.extend(word)
            width += gap.width + size
            continue
        if cur:
            lines.append(cur)
        while size > limit and len(word) > 1:
            k, used = 0, 0
            while k < len(word) and used + word[k].width <= limit:
                used += word[k].width
                k += 1
            k = max(k, 1)
            lines.append(word[:k])
            word = word[k:]
            size = sum(c.width for c in word)
        cur, width = list(word), size
    if cur or not lines:
        lines.append(cur)
    return lines


def mirrored(cl, font):
    """The cluster with its bracket or angle mark swapped for the mirror image, for right-to-left runs."""
    other = MIRROR.get(cl.char)
    gid = font.cmap.get(ord(other), 0) if other else 0
    if not gid or not cl.glyphs:
        return cl
    rest = cl.glyphs[1:]
    return Cluster(cl.char, [(gid, other, other)] + rest, font.widths[gid] + sum(font.widths[g[0]] for g in rest))


def bracket_pairs(line):
    """Index pairs of matching brackets in a line, in order of their opening bracket."""
    stack, pairs = [], []
    for i, cl in enumerate(line):
        char = getattr(cl, 'char', '')          # an Isolate is never a bracket
        if char in OPENERS:
            if len(stack) == 63:
                break
            stack.append((OPENERS[char], i))
            continue
        for k in range(len(stack) - 1, -1, -1):
            if stack[k][0] == char:
                pairs.append((stack[k][1], i))
                del stack[k:]
                break
    return sorted(pairs)


def nest(line):
    """A line's clusters with each LRI/RLI/FSI ... PDI gathered into an Isolate (nesting kept):
    the marks themselves dropped, a PDI with nothing open ignored, an isolate still open at the
    end of the line closed there."""
    root = []
    stack = [root]
    for i, cl in enumerate(line):
        if cl.char in ISOLATE_OPEN:
            group = Isolate(cl.char == RLI or (cl.char == FSI and first_strong(line, i) == RLI))
            stack[-1].append(group)
            stack.append(group.items)
        elif cl.char == PDI:
            if len(stack) > 1:
                stack.pop()
        else:
            stack[-1].append(cl)
    return root


def reorder(line, rtl, font):
    """One wrapped line, logical order in, drawing order (left to right) out. A small subset of
    the Unicode bidi algorithm: Arabic and Hebrew letters run right to left; Latin, digits and
    the separators and signs between them run left to right as whole units; bracket pairs take
    one direction; other neutrals take the direction on both sides of them, else the paragraph's;
    brackets in right-to-left runs are mirrored. Text in an isolate is ordered in the isolate's
    own direction and placed as one neutral unit."""
    return order(nest(line), rtl, font)


def order(line, rtl, font):
    """The ordering of one level: clusters and Isolate units, logical order in, visual out."""
    para = 'R' if rtl else 'L'
    raw = ['ON' if isinstance(c, Isolate) else unicodedata.bidirectional(c.char) for c in line]
    kind = ['R' if b in ('R', 'AL') else 'L' if b in ('L', 'EN', 'AN') else 'N' for b in raw]
    n = len(line)
    i = 0
    while i < n:                       # % # $ and the like go with the number they touch
        if raw[i] != 'ET':
            i += 1
            continue
        j = i
        while j < n and raw[j] == 'ET':
            j += 1
        if (i and raw[i - 1] in ('EN', 'AN')) or (j < n and raw[j] in ('EN', 'AN')):
            kind[i:j] = ['L'] * (j - i)
        i = j
    for start, end in bracket_pairs(line):
        inside = kind[start + 1:end]
        if para in inside:
            side = para
        elif ('L' if rtl else 'R') in inside:
            side = next((k for k in reversed(kind[:start]) if k != 'N'), para)
        else:
            continue
        kind[start] = kind[end] = side
    i = 0
    while i < n:
        if kind[i] != 'N':
            i += 1
            continue
        j = i
        while j < n and kind[j] == 'N':
            j += 1
        before = kind[i - 1] if i else para
        after = kind[j] if j < n else para
        kind[i:j] = [before if before == after else para] * (j - i)
        i = j
    runs = []
    for cl, k in zip(line, kind):
        if k == 'R' and not isinstance(cl, Isolate):
            cl = mirrored(cl, font)
        if runs and runs[-1][0] == k:
            runs[-1][1].append(cl)
        else:
            runs.append((k, [cl]))
    if rtl:
        runs.reverse()
    out = []
    for k, seg in runs:
        for item in (reversed(seg) if k == 'R' else seg):
            if isinstance(item, Isolate):
                out.extend(order(item.items, item.rtl, font))
            else:
                out.append(item)
    return out


def drawn(seq, font):
    """The glyphs of clusters in visual order, as they go into the content stream: each letter
    with its marks before or after it, as the mark's outline asks. A mark drawn before its letter
    also reads back in the right order when a viewer reverses an Arabic line to copy it."""
    out = []
    for cl in seq:
        marks = cl.glyphs[1:]
        lead = [g for g in marks if font.leads(g[0])]
        out.extend(lead[::-1] + cl.glyphs[:1] + [g for g in marks if not font.leads(g[0])])
    return out


def visual(text, rtl=False, font=None):
    """One line of text as the characters drawn, left to right (for tests and debugging)."""
    font = font or load_font()
    return ''.join(g[1] for g in drawn(reorder(clusters(text, font), rtl, font), font))


# ---------------------------------------------------------------- layout

def fmt(value):
    """A number for a content stream: at most two decimals, no trailing zeros."""
    text = ('%.2f' % value).rstrip('0').rstrip('.')
    return '0' if text in ('', '-0') else text


def colour(rgb, op):
    return '%s %s %s %s' % (fmt(rgb[0]), fmt(rgb[1]), fmt(rgb[2]), op)


def fit(natural, floor, total):
    """Column widths in proportion to natural, scaled to total; a column squeezed below its floor
    (its longest word, capped at an even share) keeps the floor and the rest share what is left."""
    count = len(natural)
    if sum(natural) <= 0:
        return [total / count] * count
    floor = [min(f, n, total / count) for f, n in zip(floor, natural)]
    fixed = {}
    while True:
        free = [i for i in range(count) if i not in fixed]
        if not free:
            break
        left = total - sum(fixed.values())
        share = sum(natural[i] for i in free) or 1
        widths = {i: left * natural[i] / share for i in free}
        low = [i for i in free if widths[i] < floor[i]]
        if not low:
            fixed.update(widths)
            break
        for i in low:
            fixed[i] = floor[i]
    return [fixed[i] for i in range(count)]


class Doc:
    """The page layout: blocks placed top to bottom with page breaks, as content operators per page."""

    def __init__(self, font, rtl):
        self.font, self.rtl = font, rtl
        self.pages = []
        self.used = {}           # gid -> the text it stands for (ToUnicode)
        self.memo = {}
        self.asc = font.ascent / float(font.upem)
        self.desc = -font.descent / float(font.upem)
        self.new_page()

    def new_page(self):
        self.out = []
        self.pages.append(self.out)
        self.y = TOP

    def at_top(self):
        return self.y >= TOP

    def need(self, height):
        """A new page unless height still fits above the bottom margin, or the page is still empty."""
        if self.y - height < BOTTOM and not self.at_top():
            self.new_page()

    def clusters(self, text):
        if text not in self.memo:
            self.memo[text] = clusters(text, self.font)
        return self.memo[text]

    def wrap(self, text, size, width):
        """Text wrapped to width points at size: a list of lines of clusters, logical order."""
        lines = []
        for part in str(text).split('\n'):
            lines.extend(carry(wrap(self.clusters(part.strip()), width * 1000.0 / size)))
        return lines

    def text(self, line, x, width, top, size, rgb, bold=False, align=None):
        """Draw one line in the box from x to x + width whose top is at top: aligned to the start
        of the reading direction unless align is 'center'. Bold is fill and a thin stroke."""
        glyphs = drawn(reorder(line, self.rtl, self.font), self.font)
        if not glyphs:
            return
        wide = sum(self.font.widths[g[0]] for g in glyphs) * size / 1000.0
        if align == 'center':
            x += (width - wide) / 2
        elif self.rtl:
            x += width - wide
        base = top - ((LEAD - self.asc - self.desc) / 2 + self.asc) * size
        for g in glyphs:
            if g[0] not in self.used:
                # Viewers copy an Arabic line by reversing it character by character, so a
                # ligature standing for lam and alef is mapped to them in reverse to come out right.
                rtl = len(g[2]) > 1 and unicodedata.bidirectional(g[2][0]) in ('R', 'AL')
                self.used[g[0]] = g[2][::-1] if rtl else g[2]
        show = '/F1 %s Tf %s 1 0 0 1 %s %s Tm <%s> Tj' % (
            fmt(size), colour(rgb, 'rg'), fmt(x), fmt(base), ''.join('%04X' % g[0] for g in glyphs))
        if bold:
            self.out.append('q %s %s w BT 2 Tr %s ET Q' % (colour(rgb, 'RG'), fmt(size * 0.035), show))
        else:
            self.out.append('BT %s ET' % show)

    def rect(self, x, y, w, h, fill=None, stroke=None):
        ops = ['q']
        if fill is not None:
            ops.append('%s g' % fmt(fill))
        if stroke is not None:
            ops.append('%s G 0.6 w' % fmt(stroke))
        ops.append('%s %s %s %s re %s Q' % (fmt(x), fmt(y), fmt(w), fmt(h),
                                            'B' if fill is not None and stroke is not None else 'f' if fill is not None else 'S'))
        self.out.append(' '.join(ops))

    def hline(self, y, gray, width, rgb=None):
        stroke = colour(rgb, 'RG') if rgb else '%s G' % fmt(gray)
        self.out.append('q %s %s w %s %s m %s %s l S Q' % (stroke, fmt(width), LEFT, fmt(y), RIGHT, fmt(y)))

    # -- blocks

    def add(self, block):
        """Place one block."""
        kind = block[0]
        if kind == 'title':
            self.heading(block[1], 16, ACCENT, 0, 3)
        elif kind == 'subtitle':
            self.lines(block[1], 9, MUTED)
            self.y -= 5
            self.hline(self.y, 0, 1.2, ACCENT)
            self.y -= 10
        elif kind == 'h2':
            self.heading(block[1], 13, ACCENT, 14, 7, rule=True)
        elif kind == 'h3':
            self.heading(block[1], 11, TEXT, 10, 4)
        elif kind == 'p':
            rgb, size = STYLES.get(block[2] if len(block) > 2 else 'normal', STYLES['normal'])
            self.lines(block[1], size, rgb)
            self.y -= 4
        elif kind == 'list':
            self.bullets(block[1])
        elif kind == 'kpis':
            self.kpis(block[1])
        elif kind == 'table':
            self.table(block[1], block[2])
        else:
            raise ValueError('unknown block %r' % (kind,))

    def lines(self, text, size, rgb, bold=False):
        """A paragraph: wrapped lines, each moved to a new page if it does not fit."""
        lead = size * LEAD
        for line in self.wrap(text, size, WIDTH):
            self.need(lead)
            self.text(line, LEFT, WIDTH, self.y, size, rgb, bold)
            self.y -= lead

    def heading(self, text, size, rgb, before, after, rule=False):
        """A heading, moved to the next page with what follows it when it would stand alone at the bottom."""
        lines = self.wrap(text, size, WIDTH)
        lead = size * LEAD
        if not self.at_top():
            if self.y - before - len(lines) * lead - after - KEEP < BOTTOM:
                self.new_page()
            else:
                self.y -= before
        for line in lines:
            self.need(lead)
            self.text(line, LEFT, WIDTH, self.y, size, rgb, True)
            self.y -= lead
        if rule:
            self.hline(self.y - 1, RULE, 0.6)
        self.y -= after

    def bullets(self, items):
        """A bulleted list, the bullet on the reading side."""
        indent = 13
        bullet = self.clusters('\u2022')
        for item in items:
            text, style = (item, 'normal') if isinstance(item, str) else (list(item) + ['normal'])[:2]
            rgb, size = STYLES.get(style, STYLES['normal'])
            lead = size * LEAD
            for k, line in enumerate(self.wrap(text, size, WIDTH - indent)):
                self.need(lead)
                if k == 0:
                    self.text(bullet, RIGHT - indent + 4 if self.rtl else LEFT + 2, indent - 6, self.y, size, rgb)
                self.text(line, LEFT if self.rtl else LEFT + indent, WIDTH - indent, self.y, size, rgb)
                self.y -= lead
            self.y -= 1.5
        self.y -= 3

    def kpis(self, items):
        """Figure boxes in rows: the value large, its label under it, a note under that."""
        cols = max(1, int((WIDTH + KPI_GAP) // (KPI_MIN + KPI_GAP)))
        box = (WIDTH - KPI_GAP * (cols - 1)) / cols
        inner = box - 2 * KPI_PAD
        items = list(items)
        for start in range(0, len(items), cols):
            boxes = []
            for item in items[start:start + cols]:
                value, label, note = (list(item) + ['', '', ''])[:3]
                parts = [(self.wrap(value, 14, inner), 14, ACCENT, True), (self.wrap(label, 8, inner), 8, TEXT, False)]
                if str(note).strip():
                    parts.append((self.wrap(note, 7, inner), 7, MUTED, False))
                boxes.append(parts)
            height = max(sum(len(lines) * size * LEAD for lines, size, _, _ in parts) for parts in boxes) + 2 * KPI_PAD
            self.need(height)
            for k, parts in enumerate(boxes):
                x = RIGHT - (k + 1) * box - k * KPI_GAP if self.rtl else LEFT + k * (box + KPI_GAP)
                self.rect(x, self.y - height, box, height, BOX_FILL, BOX_LINE)
                top = self.y - KPI_PAD
                for lines, size, rgb, bold in parts:
                    for line in lines:
                        self.text(line, x + KPI_PAD, inner, top, size, rgb, bold)
                        top -= size * LEAD
            self.y -= height + KPI_GAP
        self.y -= 2

    def table(self, headers, rows):
        """A table: columns sized to their content, the header shaded and repeated on each new page,
        rows kept whole unless one is taller than a page, columns right to left in an RTL report."""
        rows = [[str(c) for c in r] for r in rows]
        count = max([len(headers)] + [len(r) for r in rows])
        if not count:
            return
        headers = [str(h) for h in headers] + [''] * (count - len(headers))
        rows = [r + [''] * (count - len(r)) for r in rows]
        natural, longest = [0.0] * count, [0.0] * count
        for r in [headers] + rows:
            for i, cell in enumerate(r):
                for part in cell.split('\n'):
                    word = 0
                    for cl in self.clusters(part.strip()) + [None]:
                        if cl is None or cl.char == ' ':
                            longest[i] = max(longest[i], word * CELL / 1000.0)
                            word = 0
                        else:
                            word += cl.width
                    natural[i] = max(natural[i], sum(c.width for c in self.clusters(part.strip())) * CELL / 1000.0)
        widths = fit([w + 2 * CELL_PAD for w in natural], [w + 2 * CELL_PAD + 1 for w in longest], WIDTH)
        xs, run = [], 0
        for w in widths:
            xs.append(RIGHT - run - w if self.rtl else LEFT + run)
            run += w
        lead = CELL * LEAD
        head = [self.wrap(h, CELL, widths[i] - 2 * CELL_PAD) for i, h in enumerate(headers)]
        head_h = max(len(c) for c in head) * lead + 2 * CELL_PAD

        def cells_of(row):
            return [self.wrap(c, CELL, widths[i] - 2 * CELL_PAD) for i, c in enumerate(row)]

        def tall(cells):
            return max(len(c) for c in cells) * lead + 2 * CELL_PAD

        def draw(cells, height, shade, bold=False):
            if shade is not None:
                self.rect(LEFT, self.y - height, WIDTH, height, shade)
            for i, cell in enumerate(cells):
                for k, line in enumerate(cell):
                    self.text(line, xs[i] + CELL_PAD, widths[i] - 2 * CELL_PAD, self.y - CELL_PAD - k * lead, CELL, TEXT, bold)
            self.y -= height
            if not bold:
                self.hline(self.y, RULE, 0.4)

        page = TOP - BOTTOM
        repeat = head_h <= page / 3       # a taller header is drawn once, not again on every page

        def turn(header):
            self.new_page()
            if header and repeat:
                draw(head, head_h, HEAD_FILL, True)

        def place(cells, shade, header=False):
            """Draw a row (or the header): moved whole to a new page when it fits there but not
            here, else split across pages, at least one line a page, so this always ends."""
            while True:
                height = tall(cells)
                room = self.y - BOTTOM
                if height <= room:
                    draw(cells, height, shade, header)
                    return
                fresh = page - (head_h if repeat and not header else 0)
                lines = int((room - 2 * CELL_PAD) // lead)
                if (height <= fresh and not self.at_top()) or lines < 1:
                    turn(not header)
                    continue
                draw([c[:lines] for c in cells], tall([c[:lines] for c in cells]), shade, header)
                cells = [c[lines:] for c in cells]
                turn(not header)

        first = tall(cells_of(rows[0])) if rows else 0
        self.need(min(head_h + first, page))
        place(head, HEAD_FILL, header=True)
        for r, row in enumerate(rows):
            place(cells_of(row), STRIPE if r % 2 else None)
        self.y -= 10

    def footers(self):
        """The page number, 'n / total', at the foot of every page."""
        total = len(self.pages)
        for number, out in enumerate(self.pages, 1):
            self.out = out
            self.text(self.clusters('%d / %d' % (number, total)), LEFT, WIDTH, FOOTER_TOP, 7.5, MUTED, align='center')


# ---------------------------------------------------------------- the file

def stream(data, extra=b''):
    """A compressed stream object body."""
    packed = zlib.compress(data, 9)
    return b'<< /Length %d /Filter /FlateDecode%s >>\nstream\n' % (len(packed), extra) + packed + b'\nendstream'


def text_string(text):
    """A PDF text string: literal when plain ASCII, else UTF-16 with its byte-order mark."""
    if all(32 <= ord(c) < 127 for c in text):
        return '(%s)' % text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
    return '<FEFF%s>' % text.encode('utf-16-be').hex().upper()


def width_array(font, gids):
    """The /W array: the widths of the glyphs used, in runs of consecutive glyph ids."""
    parts, run = [], []
    for gid in sorted(gids) + [None]:
        if run and gid is not None and gid == run[-1] + 1:
            run.append(gid)
            continue
        if run:
            parts.append('%d [%s]' % (run[0], ' '.join(str(font.widths[g]) for g in run)))
        run = [gid]
    return '[%s]' % ' '.join(parts)


def to_unicode(used):
    """The ToUnicode CMap: each glyph used, to the characters it was drawn for."""
    entries = ['<%04X> <%s>' % (gid, text.encode('utf-16-be').hex().upper()) for gid, text in sorted(used.items())]
    body = ['/CIDInit /ProcSet findresource begin', '12 dict begin', 'begincmap',
            '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def',
            '/CMapName /Adobe-Identity-UCS def', '/CMapType 2 def',
            '1 begincodespacerange', '<0000> <FFFF>', 'endcodespacerange']
    for start in range(0, len(entries), 100):
        chunk = entries[start:start + 100]
        body += ['%d beginbfchar' % len(chunk)] + chunk + ['endbfchar']
    body += ['endcmap', 'CMapName currentdict /CMapResource defineresource pop', 'end', 'end']
    return '\n'.join(body).encode('ascii')


def checksum(data):
    """The TrueType checksum: the sum of the data's big-endian 32-bit words, zero-padded."""
    data += b'\0' * (-len(data) % 4)
    return sum(struct.unpack('>%dI' % (len(data) // 4), data)) & 0xFFFFFFFF


SUBSET_TABLES = ('cvt ', 'fpgm', 'prep', 'cmap', 'OS/2')    # kept as they are, when the font has them


def subset(font, used):
    """The font file cut down to the glyphs drawn, .notdef and the parts of composite glyphs:
    glyph ids unchanged (so CIDToGIDMap Identity and /W stay right), every other glyph left
    empty, loca rewritten in the long format, post without glyph names, the layout tables
    (GSUB, GPOS, GDEF, kern...) dropped, and the checksums recomputed."""
    data, tables = font.data, font.tables
    keep = {0} | set(used)
    todo = list(keep)
    while todo:
        for part in font.components(todo.pop()):
            if part < len(font.widths) and part not in keep:
                keep.add(part)
                todo.append(part)
    glyf, loca = io.BytesIO(), []
    for gid in range(len(font.widths)):
        loca.append(glyf.tell())
        if gid in keep:
            start, end = font.outline(gid)
            glyf.write(data[start:end])
            glyf.write(b'\0' * (-glyf.tell() % 4))
    loca.append(glyf.tell())
    hmtx_at = tables['hmtx'][0]
    metrics = struct.unpack_from('>H', data, tables['hhea'][0] + 34)[0]
    hmtx = io.BytesIO()
    for gid in range(len(font.widths)):          # metrics of glyphs left out are zeroed
        size = 4 if gid < metrics else 2
        at = hmtx_at + 4 * gid if gid < metrics else hmtx_at + 4 * metrics + 2 * (gid - metrics)
        hmtx.write(data[at:at + size] if gid in keep else b'\0' * size)
    head = bytearray(data[tables['head'][0]:tables['head'][0] + tables['head'][1]])
    struct.pack_into('>I', head, 8, 0)                  # checkSumAdjustment, set below
    struct.pack_into('>h', head, 50, 1)                 # indexToLocFormat: long
    out = {'head': bytes(head), 'glyf': glyf.getvalue(), 'loca': struct.pack('>%dI' % len(loca), *loca),
           'hmtx': hmtx.getvalue()}
    for tag in ('hhea', 'maxp') + SUBSET_TABLES:
        if tag in tables:
            out[tag] = data[tables[tag][0]:tables[tag][0] + tables[tag][1]]
    if 'post' in tables:
        out['post'] = struct.pack('>I', 0x00030000) + data[tables['post'][0] + 4:tables['post'][0] + 32]
    tags = sorted(out)
    power = 1 << (len(tags).bit_length() - 1)
    head_bytes = data[:4] + struct.pack('>HHHH', len(tags), power * 16, power.bit_length() - 1, (len(tags) - power) * 16)
    records, body, offset, head_at = [], [], 12 + 16 * len(tags), 0
    for tag in tags:
        blob = out[tag]
        if tag == 'head':
            head_at = offset
        records.append(struct.pack('>4sIII', tag.encode('latin-1'), checksum(blob), offset, len(blob)))
        body.append(blob + b'\0' * (-len(blob) % 4))
        offset += len(body[-1])
    result = bytearray(head_bytes + b''.join(records) + b''.join(body))
    struct.pack_into('>I', result, head_at + 8, (0xB1B0AFBA - checksum(bytes(result))) & 0xFFFFFFFF)
    return bytes(result), keep


def write(doc, font, title):
    """The finished PDF file: catalogue, pages, the font as Type0 over CIDFontType2, xref and trailer."""
    scale = font.scale
    title = ''.join(c for c in unicodedata.normalize('NFC', str(title))
                    if not dropped(c) and c not in ISOLATE_OPEN and c != PDI)
    program, keep = subset(font, doc.used)
    packed = zlib.compress(program, 9)
    # a subset font's name starts with six capitals and '+': here taken from the glyphs it keeps
    digest = hashlib.md5(repr(sorted(keep)).encode('ascii'), usedforsecurity=False).digest()
    name = '%s+%s' % (''.join(chr(65 + b % 26) for b in digest[:6]), font.name)
    catalog = '<< /Type /Catalog /Pages 2 0 R%s >>' % (' /ViewerPreferences << /Direction /R2L >>' if doc.rtl else '')
    first = 9
    kids = ' '.join('%d 0 R' % (first + 2 * i) for i in range(len(doc.pages)))
    objects = [
        catalog.encode('ascii'),
        ('<< /Type /Pages /Kids [%s] /Count %d >>' % (kids, len(doc.pages))).encode('ascii'),
        ('<< /Title %s /Producer (os-netreport) >>' % text_string(title)).encode('ascii'),
        ('<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H /DescendantFonts [5 0 R] '
         '/ToUnicode 8 0 R >>' % name).encode('ascii'),
        ('<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo << /Registry (Adobe) '
         '/Ordering (Identity) /Supplement 0 >> /FontDescriptor 6 0 R /DW 1000 /W %s /CIDToGIDMap /Identity >>'
         % (name, width_array(font, doc.used))).encode('ascii'),
        ('<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%s] /ItalicAngle %s /Ascent %d '
         '/Descent %d /CapHeight %d /StemV 80 /FontFile2 7 0 R >>'
         % (name, ' '.join(str(scale(v)) for v in font.bbox), fmt(font.italic),
            scale(font.ascent), scale(font.descent), scale(font.cap))).encode('ascii'),
        b'<< /Length %d /Filter /FlateDecode /Length1 %d >>\nstream\n' % (len(packed), len(program))
        + packed + b'\nendstream',
        stream(to_unicode(doc.used)),
    ]
    for i, ops in enumerate(doc.pages):
        objects.append(('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 4 0 R >> >> '
                        '/Contents %d 0 R >>' % (PAGE_W, PAGE_H, first + 2 * i + 1)).encode('ascii'))
        objects.append(stream('\n'.join(ops).encode('ascii')))
    out = io.BytesIO()
    out.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b'%d 0 obj\n' % number + body + b'\nendobj\n')
    xref = out.tell()
    out.write(b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1))
    for offset in offsets:
        out.write(b'%010d 00000 n \n' % offset)
    ident = hashlib.md5(out.getvalue(), usedforsecurity=False).hexdigest().upper().encode('ascii')
    out.write(b'trailer\n<< /Size %d /Root 1 0 R /Info 3 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n'
              % (len(objects) + 1, ident, ident, xref))
    out.write(b'%%EOF\n')
    return out.getvalue()


def render(blocks, direction='ltr', title='', font_path=None):
    """The report as PDF bytes: blocks laid out on A4 pages, right to left when direction is
    'rtl', title in the document information."""
    font = load_font(font_path)
    doc = Doc(font, str(direction).lower() == 'rtl')
    for block in blocks:
        doc.add(block)
    doc.footers()
    return write(doc, font, title)
