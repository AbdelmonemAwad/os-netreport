"""Check the Network Report translations: same keys and placeholders as English, 12 months, complete GUI lists."""
import glob
import json
import os
import re
import sys

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src', 'opnsense', 'scripts', 'netreport', 'i18n')
LOCALES = ['en_US', 'ar_SA', 'zh_CN', 'zh_TW', 'cs_CZ', 'fr_FR', 'de_DE', 'el_GR', 'it_IT', 'ja_JP', 'ko_KR', 'no_NO',
           'fa_IR', 'pl_PL', 'pt_BR', 'pt_PT', 'ru_RU', 'es_ES', 'tr_TR', 'uk_UA', 'vi_VN']
PH = re.compile(r'\{[a-z_]*\}')

en = json.load(open(os.path.join(BASE, 'en_US.json'), encoding='utf-8'))
source = json.load(open(os.path.join(BASE, 'ui', 'source.json'), encoding='utf-8'))
problems = 0
for loc in LOCALES:
    msgs = []
    path = os.path.join(BASE, f'{loc}.json')
    if not os.path.exists(path):
        msgs.append('report file missing')
    else:
        tr = json.load(open(path, encoding='utf-8'))
        if set(tr) != set(en):
            msgs.append(f'keys differ: missing {sorted(set(en) - set(tr))} extra {sorted(set(tr) - set(en))}')
        for k, v in en.items():
            if k == 'months':
                if len(tr.get(k, [])) != 12:
                    msgs.append('months != 12')
            elif isinstance(v, str) and sorted(PH.findall(v)) != sorted(PH.findall(tr.get(k, ''))):
                msgs.append(f'placeholders in {k}: {tr.get(k)!r}')
            elif isinstance(v, str) and k != 'list_sep' and not tr.get(k, '').strip():
                msgs.append(f'empty {k}')
    if loc != 'en_US':
        upath = os.path.join(BASE, 'ui', f'{loc}.json')
        if not os.path.exists(upath):
            msgs.append('ui file missing')
        else:
            ui = json.load(open(upath, encoding='utf-8'))
            if set(ui) != set(source):
                msgs.append(f'ui keys differ: missing {len(set(source) - set(ui))} extra {sorted(set(ui) - set(source))[:3]}')
            empty = [k for k in source if not (ui.get(k) or '').strip()]
            if empty:
                msgs.append(f'ui empty: {empty[:3]}')
    problems += len(msgs)
    print(f'{loc}: ' + ('ok' if not msgs else '; '.join(msgs)))
sys.exit(1 if problems else 0)
