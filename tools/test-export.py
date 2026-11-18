#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The report as a file (HTML, PDF, CSV) and in the mail, a schedule's filters (one interface, one
device) and the audit section (netreport.py): on recorded-format input, with no firewall behind it.

    python3 tools/test-export.py        prints one line a check, and exits 1 on any failure
"""
import csv
import datetime
import email
import importlib
import io
import json
import os
import sys
import tempfile
import types

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


for missing in ('fcntl', 'syslog'):
    try:
        importlib.import_module(missing)
    except ImportError:
        stub = types.ModuleType(missing)
        stub.LOCK_EX = stub.LOCK_NB = stub.LOG_USER = stub.LOG_NOTICE = 0
        stub.flock = stub.openlog = stub.syslog = lambda *args, **kwargs: None
        sys.modules[missing] = stub

sys.path.insert(0, SCRIPTS)
import netreport as nr  # noqa: E402

TOP = tempfile.mkdtemp(prefix='test-export.')
nr.CONFIG = os.path.join(TOP, 'config.xml')
nr.STATE_DIR = os.path.join(TOP, 'db')
nr.DEVICES_FILE = os.path.join(nr.STATE_DIR, 'devices.json')
nr.INFECTED_FILE = os.path.join(nr.STATE_DIR, 'infected.json')
os.makedirs(nr.STATE_DIR)
nr.AUDIT_LOGS = os.path.join(TOP, 'audit', 'audit_*.log')
os.makedirs(os.path.join(TOP, 'audit'))
LOGGED = []
nr.log = LOGGED.append

CONFIG = '''<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>lab</domain><language>en_US</language></system>
  <interfaces>
    <lan><if>igc1</if><descr>LAN</descr><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>
    <opt2><if>igc2</if><descr>Guests</descr><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></opt2>
    <opt3><if>igc3</if><descr>Cafe</descr><ipaddr>dhcp</ipaddr></opt3>
  </interfaces>
  <OPNsense>
    <NetReport><general><lan_interface>lan</lan_interface></general><schedules>%s</schedules></NetReport>
  </OPNsense>
</opnsense>
'''


def settings(schedules=''):
    with open(nr.CONFIG, 'w') as fh:
        fh.write(CONFIG % schedules)
    return nr.Settings()


# ---------------------------------------------------------------- the filters' values

check('device filter: an address', nr.device_filter({'filter_device': ' 192.168.1.20 '}), '192.168.1.20')
check('device filter: IPv6 the short way', nr.device_filter({'filter_device': '2001:db8:0::5'}), '2001:db8::5')
check('device filter: empty', nr.device_filter({'filter_device': ''}), None)
check('device filter: not an address', nr.device_filter({'filter_device': '192.168.1.0/24'}), None)
check('device filter: no IPv6 scope (any text may follow the %)',
      nr.device_filter({'filter_device': 'fe80::1%x" + __import__("os").getcwd() + "'}), None)
check('norm: IPv6 written in full', nr.norm('2001:0db8:0000:0000:0000:0000:0000:0001'), '2001:db8::1')
check('norm: a scope left out', nr.norm('fe80::1%igb0'), 'fe80::1')
check('norm: not an address, as it is', nr.norm('host'), 'host')
check('addresses in a line', sorted(nr.addresses_in("from: 192.168.1.20, then [2001:db8::7]:500 and fe80::1%igb0.")),
      ['192.168.1.20', '2001:db8::7', 'fe80::1'])
check('host of an address with its port', nr.host_of('198.51.100.7:51820'), '198.51.100.7')
check('host of [IPv6]:port', nr.host_of('[2001:db8::7]:500'), '2001:db8::7')
check('host of an IPv6 address', nr.host_of('2001:db8::7'), '2001:db8::7')

s = settings('''<schedule uuid="a"><enabled>1</enabled><filter_interface>opt2</filter_interface></schedule>
<schedule uuid="b"><enabled>1</enabled><filter_interface>lan</filter_interface></schedule>
<schedule uuid="c"><enabled>0</enabled><filter_interface>opt9</filter_interface></schedule>
<schedule uuid="d"><enabled>1</enabled><filter_interface>../x</filter_interface></schedule>
<schedule uuid="e"><enabled>1</enabled><filter_interface>opt3</filter_interface></schedule>''')
check('report interfaces: other than the LAN, existing, with an address of their own (a schedule off too)',
      s.report_interfaces(), ['opt2'])
view = s.for_interface('opt2')
check('for_interface: the other network', (view.lan()[1].compressed, view.lan()[2]), ('10.0.0.0/24', '10.0.0.1'))
check('for_interface: the settings themselves untouched', s.lan()[1].compressed, '192.168.1.0/24')
check('for_interface: the LAN is the settings', s.for_interface('lan') is s, True)
check('for_interface: an interface the firewall lacks', s.for_interface('opt7') is s, True)
check('for_interface: empty', s.for_interface('') is s, True)
check('for_interface: an interface on DHCP (no network of its own)', s.for_interface('opt3') is s, True)

# ---------------------------------------------------------------- devices of a filtered interface

SCANS = {'igc1': {'02:00:00:00:01:01': '192.168.1.20'}, 'igc2': {'02:00:00:00:02:01': '10.0.0.30'}}
real_scan = nr.scan_devices
nr.scan_devices = lambda st, vendors=True: (dict(SCANS[st.lan()[0]]), {'02:00:00:00:01:01': 'Acme'} if vendors else {})
nr.hostnames = lambda st: {}
db, new, active = nr.update_devices(s)
check('first scan: nothing new (baseline)', new, [])
check('first scan: the guest device kept as baseline', (db['02:00:00:00:02:01']['if'], db['02:00:00:00:02:01'].get('baseline')), ('opt2', 1))
check('first scan: active is the LAN only', active, {'02:00:00:00:01:01': '192.168.1.20'})
SCANS['igc1']['02:00:00:00:01:02'] = '192.168.1.21'
SCANS['igc2']['02:00:00:00:02:02'] = '10.0.0.31'
db, new, active = nr.update_devices(s)
check('second scan: a new LAN device is new', new, ['02:00:00:00:01:02'])
check('second scan: a new guest device is recorded, not alerted', ('02:00:00:00:02:02' in db, db['02:00:00:00:02:02'].get('baseline')), (True, None))
check('vendor of the LAN scan', db['02:00:00:00:01:01'].get('vendor'), 'Acme')

# ---------------------------------------------------------------- the audit log

DAY = datetime.datetime(2026, 11, 18)


def stamp(hour, minute=0):
    return (DAY + datetime.timedelta(hours=hour, minutes=minute)).astimezone().isoformat()


def aline(hour, minute, program, msg, pri=37):
    return f'<{pri}>1 {stamp(hour, minute)} fw.lab {program} 4242 - [meta sequenceId="1"] {msg}\n'


AUDIT = [
    aline(8, 0, 'audit', "/index.php: Successful login for user 'root' from: 192.168.1.20 (using local)"),
    aline(8, 0, 'audit', 'user root authenticated successfully for WebGui [using OPNsense\\Auth\\Services\\WebGui + OPNsense\\Auth\\Local]'),
    aline(8, 5, 'audit', 'user root@192.168.1.20 changed configuration to /conf/backup/config-1795000000.1234.xml in '
                         '/api/netreport/settings/set /api/netreport/settings/set made changes'),
    aline(8, 6, 'audit', 'user root@192.168.1.20 changed configuration to /conf/backup/config-1795000001.xml in '
                         '/firewall_rules.php Rule "allow guests" added'),
    aline(8, 7, 'audit', 'user (root) changed configuration to /conf/backup/config-1795000002.xml in /usr/local/etc/rc.syshook '),
    aline(8, 8, 'audit', 'user (root) changed configuration to /conf/backup/config-1795000004.xml in Standard input code '
                         'Standard input code made changes'),
    aline(9, 0, 'audit', "user alice@192.168.1.30 (root) changed configuration to /conf/backup/config-1795000003.xml in /ui/x X saved"),
    aline(9, 10, 'audit', 'user Secretpass could not authenticate for WebGui. [using OPNsense\\Auth\\Services\\WebGui + '
                          'OPNsense\\Auth\\Local] at 203.0.113.9', pri=36),
    aline(9, 11, 'audit', "/index.php: Web GUI authentication error for 'Secretpass' from 203.0.113.9"),
    aline(9, 12, 'sshd-session', 'Invalid user oracle from 203.0.113.9 port 50022'),
    aline(9, 12, 'sshd-session', 'Failed password for invalid user oracle from 203.0.113.9 port 50022 ssh2'),
    aline(10, 0, 'sshd-session', 'Accepted publickey for root from 192.168.1.20 port 51000 ssh2: ED25519 SHA256:AbCdEf0123'),
    aline(10, 30, 'sshd-session', 'Accepted publickey for root from 192.168.1.20 port 51002 ssh2: ED25519 SHA256:AbCdEf0123'),
    aline(10, 40, 'sshd-session', 'Accepted password for admin from fe80::1%igb0 port 51003 ssh2'),
    aline(10, 31, 'sshd-session', 'Received disconnect from 192.168.1.20 port 51002:11: disconnected by user'),
    aline(11, 0, 'audit', "/index.php: User logged out for user 'root' from: 192.168.1.20"),
    aline(11, 5, 'audit', 'user labuser could not authenticate for WebGui. [using OPNsense\\Auth\\Services\\WebGui + '
                          'OPNsense\\Auth\\Local] at 192.0.2.10', pri=36),
    aline(11, 5, 'audit', "Last message 'user labuser could n' repeated 4 times, suppressed by syslog-ng on fw.lab", pri=36),
    aline(23, 0, 'audit', "/index.php: Successful login for user 'late' from: 192.0.2.99"),
]
with open(os.path.join(TOP, 'audit', 'audit_20261118.log'), 'w', encoding='utf-8') as fh:
    fh.writelines(AUDIT)
with open(os.path.join(TOP, 'audit', 'audit_20260101.log'), 'w', encoding='utf-8') as fh:
    fh.write(aline(8, 0, 'audit', "/index.php: Successful login for user 'old' from: 192.0.2.98"))
start, end = DAY + datetime.timedelta(hours=7), DAY + datetime.timedelta(hours=22)
check('audit files: the period and the day before', [os.path.basename(p) for p in nr.audit_files(start, end)], ['audit_20261118.log'])
aud = nr.audit_events(start, end)
check('audit: there is a log', aud['ok'], True)
check('audit: sign-ins (GUI once, SSH three times; the second GUI line not counted)', aud['n_signins'], 4)
check('audit: sign-ins per user, address and service, newest first (a key\'s and a link-local one)',
      [(u, a, svc, n) for u, a, svc, n, _, _ in aud['signins']],
      [('admin', 'fe80::1', 'ssh', 1), ('root', '192.168.1.20', 'ssh', 2), ('root', '192.168.1.20', 'WebGui', 1)])
check('audit: failed sign-ins (GUI 1, SSH invalid + failed of one try 1, and 5 more from 192.0.2.10: one line, its fold 4)',
      aud['n_fails'], 7)
check('audit: a folded line counts as its repeats', [(r[0], r[1]) for r in aud['fails']], [('192.0.2.10', 5), ('203.0.113.9', 2)])
row = aud['fails'][1]
check('audit: failures of an address, its services and names cut', (row[0], row[1], row[2], row[3], row[4]),
      ('203.0.113.9', 2, ['WebGui', 'ssh'], 2, ['Se…', 'or…']))
check('audit: configuration changes, newest first',
      [(u, a, w) for _, u, a, w in aud['changes']],
      [('alice (root)', '192.168.1.30', 'X saved'), ('(root)', '', 'Standard input code'), ('(root)', '', '/usr/local/etc/rc.syshook'),
       ('root', '192.168.1.20', 'Rule "allow guests" added'), ('root', '192.168.1.20', '/api/netreport/settings/set')])
check('audit: the other lines of audit (not sshd chatter, not the same sign-in again)',
      [m for _, m in aud['other']], ["/index.php: User logged out for user 'root' from: 192.168.1.20"])
check('audit: nothing outside the period', any(u == 'late' for u, *_ in aud['signins']), False)
one = nr.audit_events(start, end, only='203.0.113.9')
check('audit of one device', (one['n_signins'], one['n_fails'], one['n_changes'], one['n_other']), (0, 2, 0, 0))
one = nr.audit_events(start, end, only='192.168.1.2')
check('audit of one device: not the lines of 192.168.1.20', (one['n_signins'], one['n_other']), (0, 0))
one = nr.audit_events(start, end, only='192.168.1.20')
check('audit of one device: its own other lines', one['n_other'], 1)
one = nr.audit_events(start, end, only='192.168.1.30')
check('audit of one device: its change only', [(u, w) for _, u, _, w in one['changes']], [('alice (root)', 'X saved')])
save_rows, nr.AUDIT_ROWS = nr.AUDIT_ROWS, 2
cut = nr.audit_events(start, end)
nr.AUDIT_ROWS = save_rows
check('audit: the newest AUDIT_ROWS, beside the full count', (len(cut['changes']), cut['n_changes']), (2, 5))
saved = nr.AUDIT_LOGS
nr.AUDIT_LOGS = os.path.join(TOP, 'none', 'audit_*.log')
check('audit: no log at all', nr.audit_events(start, end)['ok'], False)
nr.AUDIT_LOGS = saved

# ---------------------------------------------------------------- build_report with the filters

CALLS = {}


def record(name, value):
    def fn(*args, **kwargs):
        CALLS[name] = args
        return value
    return fn


nr.vnstat_volume = lambda dev, s, e: {'rx': 0, 'tx': 0, 'ok': False}
nr.vnstat_month = lambda dev: (0, 0)
nr.gateway_status = lambda: []
nr.gateway_events = lambda s, e: {}
nr.dns_stats = record('dns', {'total': 10, 'blocked': 1, 'top_blocked': [], 'top_clients': [['192.168.1.20', 4]], 'ok': True})
nr.web_activity = record('web', {'ok': False, 'slow': False, 'devices': []})
nr.suricata_alerts = record('ids', {'total': 0, 'severe': 0, 'inbound': 0, 'inbound_severe': 0, 'out_total': 0,
                                    'out_severe': 0, 'sigs': [], 'srcs': [], 'out_sigs': [], 'out_hosts': []})
nr.crowdsec = lambda s: {'ok': False, 'alerts': 0, 'bans': 0}
nr.top_talkers = record('talkers', [('10.0.0.30', 2000, 1000)])
nr.vpn_report = lambda st, s, e: None
nr.mail_stats = lambda s, e, n: {'ok': False}
nr.suricata_apps = lambda s, e, n: {'ok': False}
nr.ntopng_apps = lambda st, n: ([], '')
nr.system_info = lambda st, t: {'version': '26.7', 'uptime': '1 h', 'load': '0', 'temp': 0, 'mem': '?', 'disk': '?',
                                'disk_pct': 0, 'smart_ok': True, 'smart': '', 'backup_ts': 1, 'backup': 'x', 'tunnels': []}
with open(nr.INFECTED_FILE, 'w') as fh:
    json.dump({'10.0.0.30': {'list': 'c2', 'count': 3, 'first': 1, 'last': 2},
               '10.0.0.31': {'list': 'c2', 'count': 1, 'first': 1, 'last': 2}}, fh)
nr.update_devices = lambda st: ({'02:00:00:00:01:01': {'ip': '192.168.1.20', 'first_seen': 0, 'if': 'lan'},
                                 '02:00:00:00:01:02': {'ip': '192.168.1.21', 'first_seen': start.timestamp() + 60},
                                 '02:00:00:00:02:01': {'ip': '10.0.0.30', 'first_seen': start.timestamp() + 60, 'if': 'opt2'},
                                 '02:00:00:00:02:02': {'ip': '10.0.0.31', 'first_seen': start.timestamp() + 60, 'if': 'opt2'},
                                 '02:00:00:00:02:03': {'ip': '10.0.0.32', 'first_seen': start.timestamp() + 60,
                                                       'baseline': 1, 'if': 'opt2'}}, [], {})
nr.scan_devices = lambda st, vendors=True: ({'02:00:00:00:02:01': '10.0.0.30'}, {})
SCHED = {'uuid': 'u1', 'description': 'Guests', 'language': 'en_US', 'top_n': '5', 'compare': '0', 'period': 'day',
         'sections': 'summary,dns,web,security,devices,audit', 'filter_interface': 'opt2', 'filter_device': '10.0.0.30'}
subject, page, text, issues = nr.build_report(s, SCHED, start, end)
check('filter: DNS asked for the device', CALLS['dns'][3:], ('10.0.0.30',))
check('filter: web activity asked for the device', CALLS['web'][3:], ('10.0.0.30',))
check('filter: alerts asked for the device', CALLS['ids'][3:], ('10.0.0.30',))
check('filter: top talkers on the guest network, for the device',
      (CALLS['talkers'][0].lan()[0], CALLS['talkers'][4:]), ('igc2', ('10.0.0.30',)))
check('filter: the head says both', ('Network: Guests' in page, 'Device: 10.0.0.30' in page), (True, True))
check('filter: new devices counted on the guest network (baseline not)', ('i_new_dev', [x for x in issues if 'new' in x[1].lower()]),
      ('i_new_dev', [('warn', nr.texts('en_US')['i_new_dev'].format(n=2))]))
check('filter: the new devices listed are the one device', ('10.0.0.30' in page, '10.0.0.31</td>' in page), (True, False))
check('filter: the infected list is the one device', ('<td>10.0.0.31' in page, '<td>10.0.0.30' in page), (False, True))
check('the audit section is there', '📋 Audit log' in page and 'Failed sign-ins' in page, True)
CALLS.clear()
cafe = dict(SCHED, filter_interface='opt3', filter_device='')
page3 = nr.build_report(s, cafe, start, end)[1]
check('filter: an interface on DHCP is said, and the Local network shown',
      ('Network Cafe: gone, or without an IPv4 address' in page3, CALLS['talkers'][0].lan()[0]), (True, 'igc1'))
check('filter: the new devices of the Local network then (not the guests\')',
      [x for x in nr.build_report(s, cafe, start, end)[3] if 'new' in x[1].lower()],
      [('warn', nr.texts('en_US')['i_new_dev'].format(n=1))])

# ---------------------------------------------------------------- the page as blocks, CSV, PDF

blocks, lang, direction = nr.report_blocks(page)
check('blocks: language and direction', (lang, direction), ('en-US', 'ltr'))
check('blocks: the title, without its emoji', blocks[0], ('title', 'Network report — Home network'))
check('blocks: a subtitle next', blocks[1][0], 'subtitle')
heads = [b[1] for b in blocks if b[0] == 'h2']
check('blocks: the section headings, in order', heads, ['Needs your attention', 'Ad and malware blocking', 'Web activity by device', 'Security', 'Devices', 'Audit log'])
tables = [b for b in blocks if b[0] == 'table']
check('blocks: tables have their header row', all(t[1] for t in tables), True)
kpi = next(b for b in blocks if b[0] == 'kpis')
check('blocks: key figures as (value, label, note)', kpi[1][0][1], nr.texts('en_US')['queries'])
check('blocks: the footer as a muted line', blocks[-1][0::2], ('p', 'muted'))
page2 = ('<!DOCTYPE html><html dir="rtl" lang="ar"><head><style>x{}</style></head><body><div class="wrap">'
         '<div class="head"><h1>📊 \u062a\u0642\u0631\u064a\u0631</h1><p>\u0623\u0645\u0633 · <span class="ltr">2026-11-18</span></p></div>'
         '<div class="sec"><h2>🔐 VPN</h2><ul class="issues"><li class="bad">🔴 \u0639\u0637\u0644</li><li class="">🔵 \u0645\u0639\u0644\u0648\u0645\u0629</li></ul>'
         '<table><tr><th>A</th><th>B</th></tr><tr><td>x<br>y</td><td>=1+2</td></tr></table>'
         '<p class="muted">\u0645\u0644\u0627\u062d\u0638\u0629</p></div><div class="sec muted">\u062a\u0630\u064a\u064a\u0644</div></div></body></html>')
blocks2, lang2, dir2 = nr.report_blocks(page2)
check('blocks: Arabic is right to left', (lang2, dir2), ('ar', 'rtl'))
check('blocks: whole Arabic page', blocks2, [
    ('title', '\u062a\u0642\u0631\u064a\u0631'), ('subtitle', '\u0623\u0645\u0633 · \u20662026-11-18\u2069'), ('h2', 'VPN'),
    ('list', [('\u0639\u0637\u0644', 'bad'), ('\u0645\u0639\u0644\u0648\u0645\u0629', 'normal')]), ('table', ['A', 'B'], [['x\ny', '=1+2']]),
    ('p', '\u0645\u0644\u0627\u062d\u0638\u0629', 'muted'), ('p', '\u062a\u0630\u064a\u064a\u0644', 'muted')])

name, mime, data = nr.export_file(page2, 'S', 'csv', DAY)
check('csv: name and type', (name, mime), ('network-report-2026-11-18.csv', 'text/csv'))
check('csv: UTF-8 with a byte order mark', data[:3], b'\xef\xbb\xbf')
rows = list(csv.reader(io.StringIO(data.decode('utf-8-sig'))))
check('csv: rows with their section', rows, [
    ['\u062a\u0642\u0631\u064a\u0631'], ['\u0623\u0645\u0633 · 2026-11-18'], ['VPN', '', '\u0639\u0637\u0644'], ['VPN', '', '\u0645\u0639\u0644\u0648\u0645\u0629'], ['VPN', '', 'A', 'B'],
    ['VPN', '', 'x\ny', "'=1+2"], ['VPN', '', '\u0645\u0644\u0627\u062d\u0638\u0629'], ['VPN', '', '\u062a\u0630\u064a\u064a\u0644']])
check('csv: a number stays a number', nr._cell('-5'), '-5')
check('csv: no direction marks', nr._cell('\u20661.2 MB\u2069'), '1.2 MB')
check('csv: a formula is text', [nr._cell(x) for x in ('@SUM(A1)', '+cmd', '-x', '\tx')], ["'@SUM(A1)", "'+cmd", "'-x", "'\tx"])
name, mime, data = nr.export_file(page, 'S', 'html', DAY)
check('html: the page as it is', (name, mime, data), ('network-report-2026-11-18.html', 'text/html', page.encode('utf-8')))
zh = page.replace('lang="en-US"', 'lang="zh-CN"', 1)
check('pdf of a Chinese report is HTML', nr.export_file(zh, 'S', 'pdf', DAY)[:2], ('network-report-2026-11-18.html', 'text/html'))
name, mime, data = nr.export_file(page2, 'S', 'pdf', DAY)
check('pdf: name, type, a PDF', (name, mime, data[:5]), ('network-report-2026-11-18.pdf', 'application/pdf', b'%PDF-'))

# ---------------------------------------------------------------- the mail's file

check('attach: an old "1" is HTML', nr.attachment_of({'attach': '1'}, page, 'S', DAY)[1], 'text/html')
check('attach: an old "0" is none', nr.attachment_of({'attach': '0'}, page, 'S', DAY), None)
check('attach: none', nr.attachment_of({'attach': 'none'}, page, 'S', DAY), None)
check('attach: csv', nr.attachment_of({'attach': 'csv'}, page, 'S', DAY)[1], 'text/csv')
import pdf  # noqa: E402
real_render, pdf.render = pdf.render, lambda *a, **k: 1 / 0
check('attach: a PDF that fails goes as HTML', nr.attachment_of({'attach': 'pdf', 'description': 'D'}, page, 'S', DAY)[1], 'text/html')
check('attach: and says so in the log', any('pdf file failed' in x for x in LOGGED), True)
pdf.render = real_render

SENT = []


class FakeSMTP:
    def __init__(self, *args, **kwargs):
        self.sock = None

    def login(self, *args):
        pass

    def starttls(self, **kwargs):
        pass

    def sendmail(self, sender, rcpt, message):
        SENT.append(message)

    def close(self):
        pass


nr.smtplib.SMTP = nr.smtplib.SMTP_SSL = FakeSMTP
ms = {'host': 'mail.example.com', 'port': 465, 'security': 'ssl', 'user': '', 'password': '', 'sender': 'fw@example.com'}
nr.send_mail(ms, ['a@example.com'], 'Subject', page2, 'text', ('network-report-2026-11-18.pdf', 'application/pdf', b'%PDF-1.4 x'))
msg = email.message_from_string(SENT[-1])
part = [p for p in msg.walk() if p.get_filename()][0]
check('mail: the file\'s type, name and bytes',
      (part.get_content_type(), part.get_filename(), part.get_payload(decode=True)),
      ('application/pdf', 'network-report-2026-11-18.pdf', b'%PDF-1.4 x'))
nr.send_mail(ms, ['a@example.com'], 'Subject', page2, 'text')
check('mail: without a file', [p.get_filename() for p in email.message_from_string(SENT[-1]).walk() if p.get_filename()], [])

print('%d checks, %d failed' % (checks, failures))
sys.exit(1 if failures else 0)
