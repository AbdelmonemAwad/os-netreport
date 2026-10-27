#!/usr/local/bin/python3

"""
Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Add the Network Report GUI strings (i18n/ui/<locale>.json) to the OPNsense gettext
catalog of every installed GUI language. Strings the catalog already translates are left
alone, so that OPNsense keeps its own words and running it again is harmless. The one
exception is this script's own earlier text: what it wrote is recorded in OWNED, and an
entry that still holds exactly that text takes a corrected translation from a later
release. Core updates replace the catalogs, which is why this also runs at boot. Prints
two numbers, the strings added and the strings corrected ("3 0"); exit code 0 either way.
"""

import glob
import json
import os
import struct
import sys

LOCALE_DIR = '/usr/local/share/locale'
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'i18n', 'ui')
# What this script wrote into each catalog, {locale: {msgid: text}}. In the plugin's state
# directory, which an upgrade and a reinstall keep; the uninstallers remove this file.
OWNED = '/var/db/netreport/i18n-owned.json'


def read_mo(path):
    """msgid bytes -> msgstr bytes (plural and context entries kept as raw bytes)"""
    data = open(path, 'rb').read()
    magic = struct.unpack('<I', data[:4])[0]
    endian = '<' if magic == 0x950412de else '>'
    _, count, orig_off, trans_off = struct.unpack(endian + '4I', data[4:20])
    entries = {}
    for i in range(count):
        olen, opos = struct.unpack(endian + '2I', data[orig_off + 8 * i:orig_off + 8 * i + 8])
        tlen, tpos = struct.unpack(endian + '2I', data[trans_off + 8 * i:trans_off + 8 * i + 8])
        entries[data[opos:opos + olen]] = data[tpos:tpos + tlen]
    return entries


def write_mo(path, entries):
    """standard little-endian .mo without a hash table (gettext then uses binary search)"""
    keys = sorted(entries)
    count = len(keys)
    orig_off = 28
    trans_off = orig_off + 8 * count
    data_off = trans_off + 8 * count
    ids = strs = b''
    orig_tab, trans_tab = [], []
    for k in keys:
        orig_tab.append((len(k), len(ids)))
        ids += k + b'\0'
    for k in keys:
        trans_tab.append((len(entries[k]), len(strs)))
        strs += entries[k] + b'\0'
    out = struct.pack('<7I', 0x950412de, 0, count, orig_off, trans_off, 0, data_off)
    for length, pos in orig_tab:
        out += struct.pack('<2I', length, data_off + pos)
    for length, pos in trans_tab:
        out += struct.pack('<2I', length, data_off + len(ids) + pos)
    out += ids + strs
    tmp = path + '.netreport.tmp'
    with open(tmp, 'wb') as fh:
        fh.write(out)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def read_owned():
    """locale -> {msgid: text this script wrote there}; empty when there is no readable record"""
    try:
        with open(OWNED, encoding='utf-8') as fh:
            owned = json.load(fh)
        return {locale: {msgid: text for msgid, text in texts.items() if isinstance(text, str)}
                for locale, texts in owned.items() if isinstance(texts, dict)}
    except Exception:
        return {}


def write_owned(owned):
    """replaced whole, like a catalog; a hand install can get here before anything has made the
    directory, so it is made at the 0750 pkg/post-install.sh gives it"""
    os.makedirs(os.path.dirname(OWNED), mode=0o750, exist_ok=True)
    tmp = OWNED + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(owned, fh, indent=1, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, OWNED)


def main():
    owned = read_owned()
    record = {}
    added_total = corrected_total = 0
    for src in sorted(glob.glob(os.path.join(UI_DIR, '*_*.json'))):
        locale = os.path.basename(src)[:-5]
        mo = os.path.join(LOCALE_DIR, locale, 'LC_MESSAGES', 'OPNsense.mo')
        if not os.path.exists(mo):
            continue
        try:
            strings = json.load(open(src, encoding='utf-8'))
            entries = read_mo(mo)
        except Exception as exc:
            print(f'{locale}: skipped ({exc})', file=sys.stderr)
            if locale in owned:
                record[locale] = owned[locale]      # nothing learnt about it this time
            continue
        # This script's own entries: those that still hold exactly the text it recorded writing.
        # Every other entry stays as it is - OPNsense's own translation, or one something else
        # has written since. So does one merged before there was a record: it keeps its first
        # wording until an OPNsense update replaces the catalog and the merge adds it anew.
        mine = {msgid: text for msgid, text in owned.get(locale, {}).items()
                if entries.get(msgid.encode('utf-8')) == text.encode('utf-8')}
        added = corrected = 0
        for msgid, msgstr in strings.items():
            if not msgstr:
                continue
            key = msgid.encode('utf-8')
            if not entries.get(key):
                added += 1
            elif msgid in mine and mine[msgid] != msgstr:
                corrected += 1
            else:
                continue
            entries[key] = msgstr.encode('utf-8')
            mine[msgid] = msgstr
        if added or corrected:
            write_mo(mo, entries)
            read_mo(mo)          # sanity check: the result must parse
        if mine:
            record[locale] = mine
        added_total += added
        corrected_total += corrected
    if record != owned:
        try:
            write_owned(record)
        except OSError as exc:
            print(f'record not written ({exc})', file=sys.stderr)
    print(added_total, corrected_total)


if __name__ == '__main__':
    main()
