#!/usr/bin/env python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Run the GUI-string merge on a catalogue made up for it, correct a translation, and run it again.

merge_ui_translations.py writes a string only where a catalogue has no translation, so that
OPNsense keeps its own words. On its own, that rule also kept the plugin's first wording of a
string on every firewall that had merged it (issue 27); so the merge records what it wrote, and
an entry that still holds exactly that text takes the correction. This checks both halves with
the script's own catalogue reader and writer, and reads the result back through Python's
gettext. It needs no OPNsense: the catalogue, the strings and the record are made up in a
temporary directory.

    tools/check-merge.py

Exit status is 0 when the merge does what it says, 1 when it does not.
"""
import contextlib
import gettext
import io
import json
import os
import sys
import tempfile

# The script under test, from the tree. No __pycache__ is left in src/, which the installer
# copies onto the firewall whole.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'opnsense',
                                'scripts', 'netreport'))
import merge_ui_translations as merge

problems = 0


def expect(what, got, wanted):
    global problems
    if got == wanted:
        print(f'ok: {what}')
    else:
        problems += 1
        print(f'WRONG: {what}: {got!a}, expected {wanted!a}')


def run(strings):
    """The plugin's de_DE strings as given, then one merge; what it printed."""
    with open(os.path.join(merge.UI_DIR, 'de_DE.json'), 'w', encoding='utf-8') as fh:
        json.dump(strings, fh, ensure_ascii=False)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        merge.main()
    return out.getvalue().strip()


def record():
    try:
        with open(merge.OWNED, encoding='utf-8') as fh:
            return json.load(fh)
    except OSError:
        return None


with tempfile.TemporaryDirectory() as tmp:
    merge.LOCALE_DIR = os.path.join(tmp, 'locale')
    merge.UI_DIR = os.path.join(tmp, 'ui')
    merge.OWNED = os.path.join(tmp, 'db', 'i18n-owned.json')
    mo = os.path.join(merge.LOCALE_DIR, 'de_DE', 'LC_MESSAGES', 'OPNsense.mo')
    os.makedirs(os.path.dirname(mo))
    os.makedirs(merge.UI_DIR)
    # OPNsense's catalogue: its header, and its own word for a string the plugin has too
    merge.write_mo(mo, {b'': b'Content-Type: text/plain; charset=UTF-8\n',
                        b'Authentication': b'Authentifizierung'})

    plugin = {'Authentication': 'Anmeldung',
              'Network Report': 'Netzwerk\u00fcbersicht',
              'Send a test message': 'Testnachricht senden',
              'Recipients': ''}
    expect('the first merge adds the two translated strings', run(plugin), '2 0')
    expect('and records them', record(), {'de_DE': {'Network Report': 'Netzwerk\u00fcbersicht',
                                                    'Send a test message': 'Testnachricht senden'}})

    # Something else writes over one of the plugin's strings; then a release corrects all three.
    entries = merge.read_mo(mo)
    entries[b'Send a test message'] = b'Test senden'
    merge.write_mo(mo, entries)
    plugin.update({'Authentication': 'Authentisierung', 'Network Report': 'Netzwerkbericht',
                   'Send a test message': 'Testmail senden'})
    expect('the second merge corrects one string', run(plugin), '0 1')
    expect('a third changes nothing', run(plugin), '0 0')

    entries = merge.read_mo(mo)
    expect("the plugin's own string took the correction", entries.get(b'Network Report'), b'Netzwerkbericht')
    expect("OPNsense's own word is untouched", entries.get(b'Authentication'), b'Authentifizierung')
    expect('a string something else wrote is untouched', entries.get(b'Send a test message'), b'Test senden')
    expect('an empty translation is not written', entries.get(b'Recipients'), None)
    with open(mo, 'rb') as fh:
        expect('gettext returns the correction', gettext.GNUTranslations(fh).gettext('Network Report'),
               'Netzwerkbericht')
    expect("the record holds the correction, and only what is still the plugin's", record(),
           {'de_DE': {'Network Report': 'Netzwerkbericht'}})

sys.exit(1 if problems else 0)
