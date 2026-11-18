#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The report's PDF writer (pdf.py): Arabic shaping, line order, and the file it writes, read
back here byte by byte - xref offsets, fonts, and the text recovered through ToUnicode.

    python3 tools/test-pdf.py                   prints one line a check, and exits 1 on any failure
    python3 tools/test-pdf.py --samples DIR     also leaves sample-en.pdf and sample-ar.pdf in DIR

Without --samples the two samples are written to a temporary directory and removed.
Arabic and Persian strings are written as escapes: no Arabic letters in code.
"""
import hashlib
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import unicodedata
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), 'src', 'opnsense', 'scripts', 'netreport')
failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


sys.path.insert(0, SCRIPTS)
import pdf  # noqa: E402

FONT = pdf.load_font()

SALAM = '\u0633\u0644\u0627\u0645'
BAYT = '\u0628\u064a\u062a'
LA = '\u0644\u0627'
MUHAMMAD = '\u0645\u062d\u0645\u0651\u062f'
GOFTOGU = '\u06af\u0641\u062a\u06af\u0648'
BADR = '\u0628\u062f\u0631'
DAR = '\u062f\u0627\u0631'
ALAMN = '\u0627\u0644\u0623\u0645\u0646'
TATWEEL_BEH = '\u0640\u0628'
MIKHWA = '\u0645\u06cc\u200c\u062e\u0648\u0627'
PICH = '\u067e\u06cc\u0686'
SERVER = '\u0627\u0644\u062e\u0627\u062f\u0645'
WORKS = '\u064a\u0639\u0645\u0644'
WITH = '\u0645\u0639'
SINCE = '\u0645\u0646\u0630'
PORT = '\u0645\u0646\u0641\u0630'
OPEN = '\u0645\u0641\u062a\u0648\u062d'
AR_TITLE = '\u062a\u0642\u0631\u064a\u0631 \u0627\u0644\u0634\u0628\u0643\u0629 \u0627\u0644\u064a\u0648\u0645\u064a'
AR_SUBTITLE = ('\u062c\u062f\u0627\u0631 \u0627\u0644\u062d\u0645\u0627\u064a\u0629 fw.example \u2014 \u0645\u0646 '
               '2026-11-17 14:24 \u0625\u0644\u0649 2026-11-18 14:24')
AR_SUMMARY = '\U0001f4ca \u0627\u0644\u0645\u0644\u062e\u0635'
AR_K1 = '\u062d\u0631\u0643\u0629 \u0627\u0644\u0628\u064a\u0627\u0646\u0627\u062a'
AR_K1N = '\u0622\u062e\u0631 24 \u0633\u0627\u0639\u0629'
AR_K2 = '\u0627\u0644\u0623\u062c\u0647\u0632\u0629 \u0627\u0644\u0645\u062a\u0635\u0644\u0629'
AR_K3 = '\u0627\u0644\u062a\u0646\u0628\u064a\u0647\u0627\u062a'
AR_K3N = '2 \u062c\u062f\u064a\u062f\u0629'
AR_K4 = '\u0645\u062f\u0629 \u0627\u0644\u062a\u0634\u063a\u064a\u0644'
AR_K4N = '\u0645\u0646\u0630 12 \u064a\u0648\u0645\u0627\u064b'
AR_K5 = '\u0623\u0646\u0641\u0627\u0642 VPN'
AR_K5N = '\u0643\u0644\u0647\u0627 \u062a\u0639\u0645\u0644'
AR_P1 = ('\u0627\u0633\u062a\u062e\u062f\u0645\u062a \u0627\u0644\u0634\u0628\u0643\u0629 \u20661.2 GB\u2069 '
         '\u062e\u0644\u0627\u0644 \u0627\u0644\u064a\u0648\u0645\u060c \u0648\u0623\u0643\u062b\u0631 '
         '\u062c\u0647\u0627\u0632 \u0646\u0634\u0627\u0637\u0627\u064b \u0647\u0648 10.0.0.12 (laptop-01) '
         '\u0628\u0646\u0633\u0628\u0629 45% \u0645\u0646 \u0627\u0644\u062d\u0631\u0643\u0629.')
AR_OK = ('\u2705 \u062c\u0645\u064a\u0639 \u0627\u0644\u0623\u0646\u0641\u0627\u0642 \u062a\u0639\u0645\u0644 '
         '\u0628\u0644\u0627 \u0627\u0646\u0642\u0637\u0627\u0639.')
AR_WARN = ('\u26a0\ufe0f \u0627\u0631\u062a\u0641\u0639 \u0639\u062f\u062f \u0627\u0644\u0637\u0644\u0628\u0627\u062a '
           '\u0627\u0644\u0645\u062d\u062c\u0648\u0628\u0629 \u0628\u0646\u0633\u0628\u0629 40% \u0639\u0646 '
           '\u0627\u0644\u0623\u0645\u0633.')
AR_BAD = ('\u0641\u0634\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0627\u0644\u062e\u0627\u062f\u0645 '
          '203.0.113.5:443 \u062b\u0644\u0627\u062b \u0645\u0631\u0627\u062a \u0628\u064a\u0646 02:10 \u064802:40.')
AR_PURE = ('\u0641\u0634\u0644 \u0627\u0644\u0627\u062a\u0635\u0627\u0644 \u0628\u0627\u0644\u062e\u0627\u062f\u0645 '
           '\u062b\u0644\u0627\u062b \u0645\u0631\u0627\u062a')
AR_APPS = ('\u0627\u0644\u062a\u0637\u0628\u064a\u0642\u0627\u062a \u0627\u0644\u0623\u0643\u062b\u0631 '
           '\u0627\u0633\u062a\u062e\u062f\u0627\u0645\u0627\u064b')
AR_L1 = '\u064a\u0648\u062a\u064a\u0648\u0628 YouTube: 2.4 GB'
AR_L2 = '\u0627\u0644\u062a\u062d\u062f\u064a\u062b\u0627\u062a \u0645\u0646 update.example.org'
AR_L3 = '\u0645\u062d\u0627\u0648\u0644\u0629 \u062f\u062e\u0648\u0644 \u0645\u0631\u0641\u0648\u0636\u0629 \u0645\u0646 198.51.100.23'
AR_L4 = '\U0001f4cc \u0645\u0644\u0641 \u0627\u0644\u062a\u0642\u0631\u064a\u0631 report-2026-11-18.pdf'
AR_DEVICES = '\u0627\u0644\u0623\u062c\u0647\u0632\u0629'
AR_CONNS = '\u0627\u0644\u0627\u062a\u0635\u0627\u0644\u0627\u062a'
AR_H1 = '\u0627\u0644\u062c\u0647\u0627\u0632'
AR_H2 = '\u0627\u0644\u0639\u0646\u0648\u0627\u0646'
AR_H3 = '\u0627\u0644\u062d\u0631\u0643\u0629'
AR_H4 = '\u0645\u0644\u0627\u062d\u0638\u0627\u062a'
AR_D1 = '\u062d\u0627\u0633\u0648\u0628 \u0627\u0644\u0645\u0643\u062a\u0628'
AR_N1 = '\u064a\u0639\u0645\u0644 \u0645\u0646\u0630 \u0627\u0644\u0635\u0628\u0627\u062d'
AR_D2 = '\u0647\u0627\u062a\u0641 \u0623\u062d\u0645\u062f \U0001f4f1'
AR_N2 = '\u0633\u0637\u0631 \u0623\u0648\u0644\n\u0633\u0637\u0631 \u062b\u0627\u0646\u064d'
AR_D3 = '\u0637\u0627\u0628\u0639\u0629 HP LaserJet'
AR_D4 = '\u0627\u0644\u062a\u0644\u0641\u0627\u0632'
AR_N4 = '\u0628\u062b \u0641\u064a\u062f\u064a\u0648 (Netflix)'
AR_D5 = '\U0001f30d \u0632\u0627\u0626\u0631'
AR_N5 = '\u0634\u0628\u0643\u0629 \u0627\u0644\u0636\u064a\u0648\u0641'
AR_ALLOWED = '\u0645\u0633\u0645\u0648\u062d'
AR_BLOCKED = '\u0645\u062d\u062c\u0648\u0628'
AR_DEST = '\u0627\u0644\u0648\u062c\u0647\u0629'
AR_STATE = '\u0627\u0644\u062d\u0627\u0644\u0629'
AR_TIME = '\u0627\u0644\u0648\u0642\u062a'
FA_HEADING = '\u06af\u0632\u0627\u0631\u0634 \u0641\u0627\u0631\u0633\u06cc'
FA_P = ('\u0627\u06cc\u0646 \u06af\u0632\u0627\u0631\u0634 \u0628\u0631\u0627\u06cc \u0634\u0628\u06a9\u0647\u0654 '
        '\u062e\u0627\u0646\u06af\u06cc \u062a\u0647\u06cc\u0647 \u0634\u062f\u0647 \u0627\u0633\u062a \u0648 '
        '\u0647\u0631 \u0631\u0648\u0632 \u0628\u0647\u200c\u0631\u0648\u0632 \u0645\u06cc\u200c\u0634\u0648\u062f.')
AR_MUTED = ('\u0623\u064f\u0646\u0634\u0650\u0626 \u0647\u0630\u0627 \u0627\u0644\u062a\u0642\u0631\u064a\u0631 '
            '\u062a\u0644\u0642\u0627\u0626\u064a\u064b\u0651\u0627.')


def codes(text):
    """Code points as 'FEB3 FEFC ...', the way the checks below are read."""
    return ' '.join('%04X' % ord(c) for c in text)


def shaped(text):
    """Text shaped and cleaned (joiners and marks of direction dropped), logical order."""
    return ''.join(g[1] for cl in pdf.clusters(text, FONT) for g in cl.glyphs)


def rev(word):
    """An Arabic word as drawn: shaped, then right to left."""
    return shaped(word)[::-1]


# ---------------------------------------------------------------- shaping

check('shape: salam - initial seen, lam-alef final ligature, isolated meem',
      codes(shaped(SALAM)), 'FEB3 FEFC FEE1')
check('shape: bayt - initial beh, medial yeh, final teh', codes(shaped(BAYT)), 'FE91 FEF4 FE96')
check('shape: lam-alef alone is the isolated ligature', codes(shaped(LA)), 'FEFB')
check('shape: a shadda does not break joining (meem medial before it, dal final after it)',
      codes(shaped(MUHAMMAD)), 'FEE3 FEA4 FEE4 0651 FEAA')
check('shape: Persian gaf, feh, teh, gaf, waw', codes(shaped(GOFTOGU)), 'FB94 FED4 FE98 FB95 FEEE')
check('shape: Persian peh, farsi yeh, tcheh', codes(shaped(PICH)), 'FB58 FBFF FB7B')
check('shape: right-joining dal ends the joining (reh after it isolated)', codes(shaped(BADR)), 'FE91 FEAA FEAD')
check('shape: dal, alef, reh all isolated', codes(shaped(DAR)), 'FEA9 FE8D FEAD')
check('shape: lam with alef-hamza after a right-joining alef is the isolated ligature',
      codes(shaped(ALAMN)), 'FE8D FEF7 FEE3 FEE6')
check('shape: the tatweel joins the letter after it', codes(shaped(TATWEEL_BEH)), '0640 FE90')
check('shape: a zero-width non-joiner breaks joining and is not drawn',
      codes(shaped(MIKHWA)), 'FEE3 FBFD FEA7 FEEE FE8D')
check('joining types: hamza none, tatweel causing, fatha transparent, waw right, beh dual',
      [pdf.joining(c) for c in '\u0621\u0640\u064e\u0648\u0628'], ['U', 'C', 'T', 'R', 'D'])


class NoForms:
    """A font with no presentation forms at all."""

    def has(self, ch):
        return ord(ch) < 0xFB00


check('shape: a form the font lacks falls back to the plain letter',
      codes(''.join(s for s, _ in pdf.shape(BAYT + ' ' + LA, NoForms()))), '0628 064A 062A 0020 0644 0627')

# ---------------------------------------------------------------- bidi

line = SERVER + ' 10.0.0.1:443 ' + WORKS + ' ' + WITH + ' OPNsense ' + SINCE + ' 2026-11-18 14:24'
check('bidi: Arabic reversed, address, product name and date kept whole and in right-to-left order',
      pdf.visual(line, rtl=True),
      '2026-11-18 14:24 ' + rev(SINCE) + ' OPNsense ' + rev(WITH) + ' ' + rev(WORKS) + ' 10.0.0.1:443 ' + rev(SERVER))
check('bidi: Latin in brackets between Arabic words keeps its brackets the right way round',
      pdf.visual(PORT + ' (HTTPS) ' + OPEN, rtl=True), rev(OPEN) + ' (HTTPS) ' + rev(PORT))
check('bidi: a bracket pair after Latin text joins the Latin run',
      pdf.visual(PORT + ' Port 443 (HTTPS) ' + OPEN, rtl=True), rev(OPEN) + ' Port 443 (HTTPS) ' + rev(PORT))
check('bidi: brackets around Arabic are mirrored',
      pdf.visual(SERVER + ' (' + WORKS + ')', rtl=True), '(' + rev(WORKS) + ') ' + rev(SERVER))
check('bidi: a percent sign stays with its number',
      pdf.visual(SERVER + ' 45% ' + WORKS, rtl=True), rev(WORKS) + ' 45% ' + rev(SERVER))
check('bidi: isolate marks around a number are dropped',
      pdf.visual(SERVER + ' \u206642\u2069 ' + WORKS, rtl=True), rev(WORKS) + ' 42 ' + rev(SERVER))
check('bidi: an Arabic word inside an English line is reversed in place',
      pdf.visual('Host ' + SERVER + ' is up', rtl=False), 'Host ' + rev(SERVER) + ' is up')
check('bidi: an English line is left as it is', pdf.visual('Port 443 (HTTPS), 10.0.0.1', rtl=False),
      'Port 443 (HTTPS), 10.0.0.1')

# Arabic lines with no isolates are drawn exactly as before isolates were honoured: a digest of
# the drawn characters of ten lines (Latin, numbers, brackets, harakat, Persian) taken then.
PLAIN = [AR_BAD, AR_SUBTITLE, AR_N4, AR_L1, AR_L2, AR_L3, FA_P, AR_MUTED, AR_PURE, AR_WARN]
check('isolates: lines without isolates are drawn exactly as before',
      hashlib.sha256('|'.join(pdf.visual(t, rtl=True) for t in PLAIN).encode('utf-8')).hexdigest(),
      '05fb30b964df4bd28ea80c26219eb936894e0f3299909bfd6bf2bc64c6dd8726')


def iso(value, mark=pdf.LRI):
    return mark + value + pdf.PDI


for value in ('[2001:db8::1]:51820', '/api/netreport/settings/set', '-5%', '2026-11-18 14:24'):
    check('isolates: %s in LRI...PDI inside Arabic stays as it is' % value,
          pdf.visual(SERVER + ' ' + iso(value) + ' ' + WORKS, rtl=True), rev(WORKS) + ' ' + value + ' ' + rev(SERVER))
check('isolates: an Arabic run inside an LRI is still reversed within it',
      pdf.visual(SERVER + ' ' + iso('v ' + WORKS + ' 2') + ' ' + OPEN, rtl=True),
      rev(OPEN) + ' v ' + rev(WORKS) + ' 2 ' + rev(SERVER))
check('isolates: an RLI in an English line is laid out right to left as one unit',
      pdf.visual('Host ' + iso(SERVER + ' 10 ' + WORKS, pdf.RLI) + ' up'), 'Host ' + rev(WORKS) + ' 10 ' + rev(SERVER) + ' up')
check('isolates: an FSI opening on an Arabic letter is an RLI',
      pdf.visual('x ' + iso(WORKS + ' 5', pdf.FSI) + ' y'), 'x 5 ' + rev(WORKS) + ' y')
check('isolates: an FSI opening on a Latin letter is an LRI',
      pdf.visual(SERVER + ' ' + iso('abc ' + WORKS, pdf.FSI) + ' ' + OPEN, rtl=True),
      rev(OPEN) + ' abc ' + rev(WORKS) + ' ' + rev(SERVER))
check('isolates: nested isolates each keep their own direction',
      pdf.visual(SERVER + ' ' + iso('a ' + iso(WORKS + ' 7', pdf.RLI) + ' b') + ' ' + OPEN, rtl=True),
      rev(OPEN) + ' a 7 ' + rev(WORKS) + ' b ' + rev(SERVER))
check('isolates: a PDI with nothing open is ignored',
      pdf.visual(SERVER + pdf.PDI + ' -5%', rtl=True), pdf.visual(SERVER + ' -5%', rtl=True))
check('isolates: an isolate left open ends with the line', pdf.visual(SERVER + ' ' + pdf.LRI + '-5%', rtl=True),
      '-5% ' + rev(SERVER))
check('isolates: the marks are never drawn',
      [c for c in pdf.visual(iso('a') + iso(SERVER, pdf.RLI) + iso('b', pdf.FSI) + pdf.PDI, rtl=True)
       if c in (pdf.LRI, pdf.RLI, pdf.FSI, pdf.PDI)], [])
probe = pdf.Doc(FONT, True)
fits = sum(c.width for c in pdf.clusters(SERVER + ' -5%', FONT)) * 9 / 1000.0 + 0.5
broken = probe.wrap(SERVER + ' ' + iso('-5% -7%') + ' ' + WORKS, 9, fits)
check('isolates: an isolate broken across lines keeps its direction on the next line',
      [''.join(g[1] for g in pdf.drawn(pdf.reorder(line, True, FONT), FONT)) for line in broken],
      ['-5% ' + rev(SERVER), rev(WORKS) + ' -7%'])
check('marks: a shadda is drawn before its letter in a right-to-left line (it sits from the letter\'s left edge)',
      codes(pdf.visual(MUHAMMAD, rtl=True)), codes(shaped(MUHAMMAD)[::-1]))
check('marks: a Latin combining accent is drawn after its letter', pdf.visual('x\u0301y'), 'x\u0301y')
check('glyphs: emoji and CJK the font lacks are dropped',
      pdf.visual('a\U0001f4cab\U0001f4ccc\U0001f510d\U0001f30de\U0001f4f1f\u2705g\u4e2dh'), 'abcdefgh')
check('glyphs: a variation selector is dropped with the symbol kept when the font has it',
      pdf.visual('x\u2709\ufe0fy') == 'x\u2709y' if FONT.has('\u2709') else pdf.visual('x\u2709\ufe0fy') == 'xy', True)

# ---------------------------------------------------------------- reading the file back


def parse(data):
    """The PDF read back: (errors, objects {num: (dict text, stream bytes or None)}, trailer text)."""
    errors = []
    found = re.search(rb'startxref\s+(\d+)\s+%%EOF\s*$', data)
    if not found:
        return ['no startxref'], {}, ''
    at = int(found.group(1))
    if not data.startswith(b'xref', at):
        return ['startxref does not point at xref'], {}, ''
    head = re.match(rb'xref\s+0 (\d+)\s+', data[at:])
    size = int(head.group(1))
    table = at + head.end()
    offsets = {}
    for num in range(size):
        entry = data[table + 20 * num: table + 20 * num + 20]
        if num == 0:
            if not entry.startswith(b'0000000000 65535 f'):
                errors.append('entry 0 is %r' % entry)
            continue
        offsets[num] = int(entry[:10])
        if not data.startswith(b'%d 0 obj' % num, offsets[num]):
            errors.append('object %d: offset %d does not point at "%d 0 obj"' % (num, offsets[num], num))
    trailer = data[table + 20 * size:].decode('latin-1')
    if not trailer.startswith('trailer'):
        errors.append('no trailer after the xref entries')
    objects = {}
    for num, off in offsets.items():
        start = off + len(b'%d 0 obj\n' % num)
        s, e = data.find(b'stream\n', start), data.find(b'endobj', start)
        if s != -1 and s < e:
            text = data[start:s].decode('latin-1')
            length = int(re.search(r'/Length (\d+)', text).group(1))
            raw = data[s + 7: s + 7 + length]
            if not data.startswith(b'\nendstream', s + 7 + length):
                errors.append('object %d: /Length does not end at endstream' % num)
            if '/FlateDecode' in text:
                raw = zlib.decompress(raw)
            objects[num] = (text, raw)
        else:
            objects[num] = (data[start:e].decode('latin-1'), None)
    return errors, objects, trailer


class Read:
    """A rendered PDF parsed back: pages, text pieces with positions, glyph widths."""

    def __init__(self, data):
        self.data = data
        self.errors, self.objects, self.trailer = parse(data)
        self.root = int(re.search(r'/Root (\d+) 0 R', self.trailer).group(1))
        self.info = int(re.search(r'/Info (\d+) 0 R', self.trailer).group(1))
        pages = self.objects[int(re.search(r'/Pages (\d+) 0 R', self.objects[self.root][0]).group(1))][0]
        self.kids = [int(k) for k in re.findall(r'(\d+) 0 R', re.search(r'/Kids \[([^\]]*)\]', pages).group(1))]
        self.count = int(re.search(r'/Count (\d+)', pages).group(1))
        type0 = next(t for t, s in self.objects.values() if '/Subtype /Type0' in t)
        self.type0 = type0
        cmap = self.objects[int(re.search(r'/ToUnicode (\d+) 0 R', type0).group(1))][1].decode('ascii')
        self.map = {}
        for section in re.findall(r'beginbfchar(.*?)endbfchar', cmap, re.S):
            for code, uni in re.findall(r'<([0-9A-F]{4})> <([0-9A-F]+)>', section):
                self.map[code] = bytes.fromhex(uni).decode('utf-16-be')
        self.cid = next(t for t, s in self.objects.values() if '/Subtype /CIDFontType2' in t)
        self.widths = {}
        for first, run in re.findall(r'(\d+) \[([\d ]+)\]', re.search(r'/W \[(.*)\] /CIDToGIDMap', self.cid).group(1)):
            for k, w in enumerate(run.split()):
                self.widths[int(first) + k] = int(w)
        self.pieces = []           # (page, x, y, size, [codes])
        self.streams = []
        for page, kid in enumerate(self.kids, 1):
            content = self.objects[int(re.search(r'/Contents (\d+) 0 R', self.objects[kid][0]).group(1))][1].decode('ascii')
            self.streams.append(content)
            for size, x, y, hexs in re.findall(r'/F1 ([\d.]+) Tf [\d. ]+ rg 1 0 0 1 (-?[\d.]+) (-?[\d.]+) Tm <([0-9A-F]*)> Tj',
                                               content):
                self.pieces.append((page, float(x), float(y), float(size), [hexs[i:i + 4] for i in range(0, len(hexs), 4)]))

    def text(self, piece, logical=False):
        """The characters of one piece through ToUnicode, in drawing order, or reversed character
        by character the way a viewer copies a right-to-left line (back to logical order)."""
        found = ''.join(self.map.get(c, '?') for c in piece[4])
        return found[::-1] if logical else found

    def find(self, words, logical=False):
        """The first piece holding words: (page, x, y, size, codes), or None."""
        return next((p for p in self.pieces if words in self.text(p, logical)), None)

    def all_text(self, logical=False):
        return '\n'.join(self.text(p, logical) for p in self.pieces)

    def width(self, piece):
        return sum(self.widths.get(int(c, 16), 1000) for c in piece[4]) * piece[3] / 1000.0


def sfnt_sum(data):
    """The TrueType checksum, written out again here rather than taken from pdf.py."""
    data = data + b'\0' * (-len(data) % 4)
    return sum(struct.unpack('>%dI' % (len(data) // 4), data)) & 0xFFFFFFFF


def parts_of(gids):
    """Every glyph the composite glyphs among gids are built from, at any depth."""
    found, todo = set(), list(gids)
    while todo:
        for part in FONT.components(todo.pop()):
            if part not in found:
                found.add(part)
                todo.append(part)
    return found


def subset_checks(name, doc, fontfile, used):
    """The embedded font: a subset that reads back, keeps every glyph drawn, and adds up."""
    program = fontfile[1]
    check('%s: /Length1 is the length of the embedded font' % name,
          int(re.search(r'/Length1 (\d+)', fontfile[0]).group(1)), len(program))
    check('%s: the font is named as a subset (six capitals and +)' % name,
          bool(re.search(r'/BaseFont /[A-Z]{6}\+DejaVuSans ', doc.type0)), True)
    sub = pdf.Font(None, program)
    check('%s: the subset reads back: glyph count, units, metrics, long loca' % name,
          (len(sub.widths), sub.upem, sub.ascent, sub.descent, sub.long_loca),
          (len(FONT.widths), FONT.upem, FONT.ascent, FONT.descent, True))
    check('%s: every glyph drawn (and .notdef) keeps its width and its outline, byte for byte' % name,
          sorted(g for g in used | {0} if sub.widths[g] != FONT.widths[g]
                 or program[slice(*sub.outline(g))] != FONT.data[slice(*FONT.outline(g))]), [])
    kept = {g for g in range(len(sub.widths)) if sub.outline(g)[1] > sub.outline(g)[0]}
    check('%s: no other glyph keeps an outline but the parts of composite glyphs' % name,
          sorted(kept - used - {0} - parts_of(used)), [])
    check('%s: the parts of composite glyphs are kept' % name,
          sorted(g for g in parts_of(used) if FONT.outline(g)[1] > FONT.outline(g)[0] and g not in kept), [])
    records = [struct.unpack_from('>4sIII', program, 12 + 16 * i) for i in range(struct.unpack_from('>H', program, 4)[0])]
    tags = [r[0].decode('latin-1') for r in records]
    wrong = []
    for tag, stored, offset, length in records:
        blob = bytearray(program[offset:offset + length])
        if tag == b'head':
            struct.pack_into('>I', blob, 8, 0)
        if sfnt_sum(bytes(blob)) != stored:
            wrong.append(tag)
    check('%s: table checksums and head.checkSumAdjustment add up' % name, (wrong, sfnt_sum(program)), ([], 0xB1B0AFBA))
    check('%s: tables sorted, the TrueType ones kept, the layout ones dropped' % name,
          (tags == sorted(tags), {'head', 'hhea', 'hmtx', 'maxp', 'loca', 'glyf', 'cvt ', 'fpgm', 'prep'} <= set(tags),
           sorted(set(tags) & {'GSUB', 'GPOS', 'GDEF', 'kern', 'MATH', 'name'})), (True, True, []))


def structure(name, data, title):
    """The checks every rendered file must pass."""
    doc = Read(data)
    check('%s: header is %%PDF-1.x' % name, data[:7], b'%PDF-1.')
    check('%s: every xref offset points at its "N 0 obj", every stream /Length is exact' % name, doc.errors, [])
    check('%s: trailer /Size is the object count + 1' % name,
          int(re.search(r'/Size (\d+)', doc.trailer).group(1)), len(doc.objects) + 1)
    check('%s: /Root is the catalog, /Info holds the title, no /CreationDate' % name,
          ('/Type /Catalog' in doc.objects[doc.root][0], b'/CreationDate' in data), (True, False))
    info = doc.objects[doc.info][0]
    lit = re.search(r'/Title \((.*?)\) /', info)
    got = lit.group(1) if lit else bytes.fromhex(re.search(r'/Title <FEFF([0-9A-F]*)>', info).group(1)).decode('utf-16-be')
    check('%s: /Info /Title' % name, got, title)
    check('%s: /Count matches the page list' % name, doc.count, len(doc.kids))
    check('%s: Type0 font, Identity-H, CIDFontType2 with CIDToGIDMap Identity' % name,
          ('/Encoding /Identity-H' in doc.type0, '/CIDToGIDMap /Identity' in doc.cid), (True, True))
    descriptor = doc.objects[int(re.search(r'/FontDescriptor (\d+) 0 R', doc.cid).group(1))][0]
    fontfile = doc.objects[int(re.search(r'/FontFile2 (\d+) 0 R', descriptor).group(1))]
    used = {int(c, 16) for p in doc.pieces for c in p[4]}
    subset_checks(name, doc, fontfile, used)
    check('%s: /W gives the font width of every glyph drawn' % name,
          sorted(g for g in used if doc.widths.get(g) != FONT.widths[g]), [])
    check('%s: ToUnicode maps every glyph drawn' % name, sorted(g for g in used if '%04X' % g not in doc.map), [])
    outside = [doc.text(p) for p in doc.pieces
               if p[1] < pdf.LEFT - 0.05 or p[1] + doc.width(p) > pdf.RIGHT + 0.05 or p[2] < 20]
    check('%s: every line lies inside the margins' % name, outside, [])
    check('%s: no isolate marks, variation selectors or emoji in the text' % name,
          [c for c in doc.all_text() if 0x2066 <= ord(c) <= 0x2069 or 0xFE00 <= ord(c) <= 0xFE0F or ord(c) > 0xFFFF], [])
    return doc


def table_rows(count):
    return [['192.0.2.%d' % (i % 250 + 1), 'host-%03d.example' % i, '%d MB' % (i * 7 % 900), 'row %d\nsecond %d' % (i, i)]
            for i in range(count)]


EN_LONG = ('The network moved 1.2 GB today. The busiest device was 10.0.0.12 (laptop-01) with 45% of the traffic; '
           'the quietest was the printer at 10.0.0.20. This paragraph is long so that it wraps across several lines '
           'of the page, which is the point of having it here.')
EN_BLOCKS = [
    ('title', '\U0001f4ca Daily network report'),
    ('subtitle', 'Firewall fw.example \u2014 2026-11-17 14:24 to \u20662026-11-18 14:24\u2069'),
    ('h2', '\U0001f4ca Summary'),
    ('kpis', [('\u20661.2 GB\u2069', 'Traffic', 'last 24 hours'), ('37', 'Devices online', ''),
              ('5', 'Alerts', '2 new'), ('99.9%', 'Uptime', 'for 12 days'), ('3', 'VPN tunnels', 'all up')]),
    ('p', EN_LONG, 'normal'),
    ('p', '\u2705 All tunnels are up.', 'ok'),
    ('p', '\u26a0\ufe0f Blocked lookups rose 40% against yesterday.', 'warn'),
    ('p', 'The server 203.0.113.5:443 could not be reached three times between 02:10 and 02:40.', 'bad'),
    ('h3', 'Most used applications'),
    ('list', [('YouTube: 2.4 GB', 'normal'), ('Updates from update.example.org', 'muted'),
              ('Refused login from 198.51.100.23', 'bad'), ('\U0001f4cc Report file report-2026-11-18.pdf', 'ok')]),
    ('h2', 'Devices'),
    ('table', ['Address', 'Name', 'Traffic', 'Notes'], table_rows(45)),
    ('p', 'Made by os-netreport.', 'muted'),
]

AR_BLOCKS = [
    ('title', AR_TITLE),
    ('subtitle', AR_SUBTITLE),
    ('h2', AR_SUMMARY),
    ('kpis', [('\u20661.2 GB\u2069', AR_K1, AR_K1N), ('37', AR_K2, ''), ('5', AR_K3, AR_K3N),
              ('99.9%', AR_K4, AR_K4N), ('3', AR_K5, AR_K5N)]),
    ('p', AR_P1, 'normal'),
    ('p', AR_OK, 'ok'),
    ('p', AR_WARN, 'warn'),
    ('p', AR_BAD, 'bad'),
    ('p', AR_PURE, 'normal'),
    ('h3', AR_APPS),
    ('list', [(AR_L1, 'normal'), (AR_L2, 'muted'), (AR_L3, 'bad'), (AR_L4, 'ok')]),
    ('h2', AR_DEVICES),
    ('table', [AR_H1, AR_H2, AR_H3, AR_H4],
     [[AR_D1, '10.0.0.10', '820 MB', AR_N1], [AR_D2, '10.0.0.11', '310 MB', AR_N2],
      [AR_D3, '10.0.0.20', '4 MB', ''], [AR_D4, '10.0.0.31', '1.9 GB', AR_N4], [AR_D5, '10.0.0.40', '12 MB', AR_N5]]),
    ('h2', AR_CONNS),
    ('table', [AR_TIME, AR_DEST, AR_STATE],
     [['2026-11-18 %02d:%02d' % (i // 4, i % 4 * 15), '198.51.100.%d:443' % (i + 1), AR_BLOCKED if i % 3 == 0 else AR_ALLOWED]
      for i in range(40)]),
    ('h2', FA_HEADING),
    ('p', FA_P, 'normal'),
    ('p', AR_MUTED, 'muted'),
]

# ---------------------------------------------------------------- the English file

en = pdf.render(EN_BLOCKS, 'ltr', 'Daily network report')
doc = structure('english', en, 'Daily network report')
check('english: the same input gives the same bytes', pdf.render(EN_BLOCKS, 'ltr', 'Daily network report') == en, True)
text = doc.all_text()
check('english: title, headings, figures, addresses and table cells are in the text',
      [w for w in ('Daily network report', 'Summary', '1.2 GB', 'Devices online', '10.0.0.12 (laptop-01)',
                   'All tunnels are up.', '203.0.113.5:443', 'Most used applications', 'Refused login from 198.51.100.23',
                   'Address', 'host-044.example', 'second 44', 'Made by os-netreport.') if w not in text], [])
check('english: the heading lost its emoji and nothing else', doc.find('Summary') and doc.text(doc.find('Summary')), 'Summary')
start = next(i for i, p in enumerate(doc.pieces) if doc.text(p).startswith('The network moved'))
wrapped = [doc.text(p) for p in doc.pieces[start:start + 6]]
lines = next((wrapped[:k] for k in range(1, 7) if ' '.join(wrapped[:k]) == EN_LONG), wrapped)
check('english: a long paragraph wraps to several lines, no word lost', (len(lines) >= 2, ' '.join(lines)), (True, EN_LONG))
check('english: the long table runs to a second page', doc.count >= 2, True)
check('english: the table header is repeated on the second page',
      [p[0] for p in doc.pieces if doc.text(p) == 'Address'], list(range(1, doc.count + 1)))
spread = {}
for p in doc.pieces:
    m = re.match(r'(row|second) (\d+)$', doc.text(p))
    if m:
        spread.setdefault(m.group(2), set()).add(p[0])
check('english: no table row is split across pages', sorted(k for k, v in spread.items() if len(v) != 1), [])
check('english: lines start at the left margin', doc.find('Daily network report')[1], float(pdf.LEFT))
check('english: KPI boxes run left to right', doc.find('Traffic')[1] < doc.find('Devices online')[1], True)
check('english: table columns run left to right', doc.find('Address')[1] < doc.find('Notes')[1], True)
check('english: page numbers at the foot', [doc.text(p) for p in doc.pieces if p[2] < pdf.BOTTOM],
      ['%d / %d' % (n, doc.count) for n in range(1, doc.count + 1)])

# ---------------------------------------------------------------- the Arabic file

ar = pdf.render(AR_BLOCKS, 'rtl', AR_TITLE)
doc = structure('arabic', ar, AR_TITLE)
logical = doc.all_text(logical=True)
check('arabic: pure Arabic lines read back through ToUnicode as the original letters, harakat included',
      [w for w in (AR_TITLE, AR_PURE, AR_DEVICES, AR_CONNS, AR_APPS, AR_H1, AR_ALLOWED, unicodedata.normalize('NFC', AR_MUTED))
       if w not in logical], [])
check('arabic: the lam-alef glyph maps to alef, lam, so a reversed line reads lam-alef',
      (LA[::-1] in doc.map.values(), LA in doc.map.values(), AR_PURE in logical), (True, False, True))
check('arabic: the heading lost its emoji', doc.find(AR_SUMMARY[2:], logical=True) and doc.text(doc.find(AR_SUMMARY[2:], True), True),
      AR_SUMMARY[2:])
drawn = doc.all_text()
check('arabic: Latin and number tokens are drawn whole',
      [w for w in ('10.0.0.12', '(laptop-01)', '45%', '203.0.113.5:443', '1.2 GB', 'update.example.org',
                   'report-2026-11-18.pdf', '2026-11-17 14:24') if w not in drawn], [])
piece = doc.find(AR_PURE, logical=True)
check('arabic: a line is right-aligned', round(piece[1] + doc.width(piece), 2), float(pdf.RIGHT))
check('arabic: the catalog asks for right-to-left page order', '/Direction /R2L' in doc.objects[doc.root][0], True)
x1, x2 = doc.find(AR_K1, True)[1], doc.find(AR_K2, True)[1]
check('arabic: KPI boxes run right to left', x1 > x2, True)
bullet = next(p for p in doc.pieces if doc.text(p) == '\u2022')
item = doc.find(AR_L3, logical=True) or doc.find(AR_L3[:5], logical=True)
check('arabic: the bullet is at the right of its item', bullet[1] > item[1] + doc.width(item) - 0.01, True)
check('arabic: the Persian heading and its zero-width non-joiner text are there',
      FA_HEADING in logical and '\u200c' not in logical, True)

# ---------------------------------------------------------------- tables, right to left and long

rtl = Read(pdf.render([('table', ['Col A', 'Col B', 'Col C'], [['a1', 'b1', 'c1'], ['a2', 'b2', 'c2']])], 'rtl'))
xa, xb, xc = (rtl.find(h)[1] for h in ('Col A', 'Col B', 'Col C'))
check('rtl table: the first column is at the right, the last at the left', xa > xb > xc, True)
check('rtl table: cells follow their header', rtl.find('a2')[1] > rtl.find('b2')[1] > rtl.find('c2')[1], True)
ltr = Read(pdf.render([('table', ['Col A', 'Col B', 'Col C'], [['a1', 'b1', 'c1']])], 'ltr'))
check('ltr table: the first column is at the left', ltr.find('Col A')[1] < ltr.find('Col B')[1] < ltr.find('Col C')[1], True)

wide = Read(pdf.render([('table', ['#', 'Long text'], [['1', ' '.join(['word'] * 400)]])], 'ltr'))
check('table: the narrow column keeps room for its content', wide.find('#')[1] < wide.find('Long text')[1], True)
check('table: a long cell wraps inside its column',
      max(p[1] + wide.width(p) for p in wide.pieces if 'word' in wide.text(p)) <= pdf.RIGHT + 0.05, True)

pages = [len(Read(pdf.render([('table', ['Address', 'Name'], [['192.0.2.1', 'x']] * n)], 'ltr')).kids) for n in (5, 200)]
check('table: page count grows with the rows', pages[0] == 1 and pages[1] > 2, True)
tall = Read(pdf.render([('table', ['Address', 'Lines'], [['192.0.2.1', '\n'.join('line %d' % i for i in range(150))]])], 'ltr'))
check('table: a row taller than a page is split across pages, header on each',
      (tall.count >= 2, len([p for p in tall.pieces if tall.text(p) == 'Address']) == tall.count,
       len([p for p in tall.pieces if tall.text(p).startswith('line ')])), (True, True, 150))

started = time.time()
huge = pdf.render([('table', ['w ' * 8000, 'Second'], [['first row', 'b1'], ['next row', 'b2']])], 'ltr')
took = time.time() - started
huge = Read(huge)
check('table: a header taller than a page is drawn once, across pages, in well under a second',
      (huge.errors, took < 1.0, huge.count >= 2,
       sum(huge.text(p).count('w') for p in huge.pieces if set(huge.text(p)) <= {'w', ' '}),
       [huge.text(p) for p in huge.pieces if huge.text(p) in ('Second', 'first row', 'next row')]),
      ([], True, True, 8000, ['Second', 'first row', 'next row']))
third = Read(pdf.render([('table', ['\n'.join('head %d' % i for i in range(30)), 'B'], [['row %d' % i, 'x'] for i in range(120)])],
                        'ltr'))
check('table: a header over a third of a page is not repeated on later pages',
      (third.count >= 2, len([p for p in third.pieces if third.text(p) == 'head 0']),
       len([p for p in third.pieces if third.text(p).startswith('row ')])), (True, 1, 120))

per = 9 * pdf.LEAD + 4
alone = 14 + 13 * pdf.LEAD + 7
lonely = Read(pdf.render([('p', 'filler %d' % i, 'normal') for i in range(int((pdf.TOP - pdf.BOTTOM - alone - pdf.KEEP / 2) // per))]
                         + [('h2', 'Lonely heading'), ('p', 'Text under it', 'normal')], 'ltr'))
check('heading: one that would stand alone at the foot of a page moves to the next with its text',
      (lonely.find('Lonely heading')[0], lonely.find('Text under it')[0]), (2, 2))

blank = pdf.render([], 'ltr')
empty = Read(blank)
check('empty: no blocks still gives one valid page', (empty.errors, empty.count), ([], 1))
check('size: an empty report is small now the font is cut to the glyphs drawn (under 12 KB)', len(blank) < 12000, True)
check('size: the samples stay under 60 KB each', (len(en) < 60000, len(ar) < 60000), (True, True))
print('size: empty report %d bytes; English sample %d bytes, %d pages; Arabic sample %d bytes, %d pages'
      % (len(blank), len(en), len(Read(en).kids), len(ar), len(Read(ar).kids)))
try:
    pdf.render([('chart', 'x')])
    check('unknown block: refused', False, True)
except ValueError:
    check('unknown block: refused', True, True)

# ---------------------------------------------------------------- samples

target = None
if '--samples' in sys.argv:
    target = sys.argv[sys.argv.index('--samples') + 1]
    os.makedirs(target, exist_ok=True)
scratch = target or tempfile.mkdtemp(prefix='test-pdf.')
for name, data in (('sample-en.pdf', en), ('sample-ar.pdf', ar)):
    with open(os.path.join(scratch, name), 'wb') as fh:
        fh.write(data)
check('samples: both written', sorted(f for f in os.listdir(scratch) if f.startswith('sample-')), ['sample-ar.pdf', 'sample-en.pdf'])
if target:
    print('samples in %s' % os.path.abspath(target))
else:
    shutil.rmtree(scratch)

print('%d checks, %d failure(s)' % (checks, failures))
sys.exit(1 if failures else 0)
