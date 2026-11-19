#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""General's "Mask addresses" in reports, alerts and files, and the weekly configuration backup by
mail (netreport.py, alerts.py): with stand-ins for the firewall's answers and for the mail server.

    python3 tools/test-privacy.py       prints one line a check, and exits 1 on any failure
"""
import datetime
import importlib
import json
import os
import stat
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
import alerts  # noqa: E402

TOP = tempfile.mkdtemp(prefix='test-privacy.')
nr.CONFIG = os.path.join(TOP, 'config.xml')
nr.STATE_DIR = os.path.join(TOP, 'db')
nr.STATE_FILE = os.path.join(nr.STATE_DIR, 'state.json')
nr.HISTORY_FILE = os.path.join(nr.STATE_DIR, 'history.json')
nr.DEVICES_FILE = os.path.join(nr.STATE_DIR, 'devices.json')
nr.INFECTED_FILE = os.path.join(nr.STATE_DIR, 'infected.json')
nr.ANON_KEY = os.path.join(nr.STATE_DIR, 'anonymize.key')
nr.AUDIT_LOGS = os.path.join(TOP, 'audit', 'audit_*.log')
os.makedirs(nr.STATE_DIR)
LOGGED = []
nr.log = LOGGED.append

CONFIG = '''<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><domain>example.net</domain><language>en_US</language></system>
  <interfaces><lan><if>igc1</if><descr>LAN</descr><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interfaces>
  <OPNsense><NetReport><general>%s</general><schedules/></NetReport></OPNsense>
</opnsense>
'''


def settings(general=''):
    with open(nr.CONFIG, 'w') as fh:
        fh.write(CONFIG % general)
    return nr.Settings()


# ---------------------------------------------------------------- the masker

s = settings('<anonymize>0</anonymize>')
check('off by default: no masker', nr.ANON, None)
s = settings('<anonymize>1</anonymize>')
m = nr.ANON
check('on: a masker', isinstance(m, nr.Masker), True)
first = m.addr('192.168.1.20')
check('an address masked as ip-<6 hex>', (first[:3], len(first)), ('ip-', 9))
check('the key kept beside the state, readable by root only', oct(stat.S_IMODE(os.stat(nr.ANON_KEY).st_mode)), '0o600')
again = settings('<anonymize>1</anonymize>')
check('the same device keeps its value from one run to the next', nr.ANON.addr('192.168.1.20'), first)
check('IPv6 written in full and short: one value', nr.ANON.addr('2001:0db8:0000::0001'), nr.ANON.addr('2001:db8::1'))
check('another device, another value', nr.ANON.addr('192.168.1.21') != first, True)
check('a MAC address, upper or lower case: one value',
      nr.ANON.mac('02:00:00:00:00:AA'), nr.ANON.mac('02:00:00:00:00:aa'))
check('a name masked as name-<6 hex>', nr.ANON.name('laptop')[:5], 'name-')
check('kinds apart: an address and a name of the same text differ',
      nr.ANON.value('ip', 'x') != nr.ANON.value('name', 'x'), True)
line = ('PC 192.168.1.20 at 02:00:00:00:00:aa asked 20.1.168.192.in-addr.arpa and fe80::1%igb0 '
        'at 2026-11-18 18:05:12, OPNsense 26.7.9_1, 999.1.1.1, 10.0.0.300, port 51820')
out = nr.ANON.text(line)
check('a text: the address, the MAC, the reverse name and IPv6 masked',
      [w in out for w in ('192.168.1.20', '02:00:00:00:00:aa', '20.1.168.192', 'fe80::1')], [False] * 4)
check('a text: the reverse name keeps the address\'s value', (nr.ANON.addr('192.168.1.20') + '.in-addr.arpa') in out, True)
check('a text: times, versions and what is no address left alone',
      [w in out for w in ('2026-11-18 18:05:12', '26.7.9_1', '999.1.1.1', '10.0.0.300', '51820')], [True] * 5)
facts = nr.ANON.facts({'address': '203.0.113.9', 'devices': [{'mac': '02:00:00:00:00:01', 'ip': '192.168.1.5',
                                                              'name': 'tablet', 'vendor': 'Acme'}], 'count': 3})
check('facts: addresses, MAC and the name masked; the rest as it was',
      (facts['address'].startswith('ip-'), facts['devices'][0]['mac'].startswith('mac-'),
       facts['devices'][0]['ip'].startswith('ip-'), facts['devices'][0]['name'].startswith('name-'),
       facts['devices'][0]['vendor'], facts['count']), (True, True, True, True, 'Acme', 3))

# the review's cases: IPv6 in the forms a log writes it, its reverse names, and what is no address
for raw in ('src:2001:db8::1', 'udp6:2001:db8::5:1194', 'peer:fe80::1%igb0', 'from 2001:db8::1: bad',
            '[2001:db8::7]:500', '2001:db8:02:00:00:00:00:aa', '::ffff:192.0.2.1'):
    out = nr.ANON.text(raw)
    check('IPv6 masked in %r' % raw, any(part in out for part in ('2001:db8', 'fe80::1', '192.0.2.1')), False)
check('the address before a colon keeps its value', nr.ANON.text('from 2001:db8::1: bad'),
      'from %s: bad' % nr.ANON.addr('2001:db8::1'))
check('a bare :: and a time left alone', nr.ANON.text('x :: y at 18:05:12'), 'x :: y at 18:05:12')
arpa6 = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
check('an IPv6 reverse name: the forward address\'s value', nr.ANON.text(arpa6), nr.ANON.addr('2001:db8::1') + '.ip6.arpa')
check('a connection\'s device masked: WireGuard', nr.ANON.conn('WireGuard Laptop'), 'WireGuard ' + nr.ANON.name('Laptop'))
check('a connection\'s client masked: OpenVPN', nr.ANON.conn('OpenVPN Road warriors: alice'),
      'OpenVPN Road warriors: ' + nr.ANON.name('alice'))
check('an IPsec connection as it is', nr.ANON.conn('IPsec Branch office'), 'IPsec Branch office')
check('a host name in its domain masked; a name that is a word, alone, not',
      nr.ANON.names('johns-iphone.lan asked; Mail section; mail.example.com', {'johns-iphone', 'mail'}),
      nr.ANON.name('johns-iphone') + '.lan asked; Mail section; ' + nr.ANON.name('mail') + '.example.com')
# the key: a short one is made again; two maskers with none agree
with open(nr.ANON_KEY, 'wb') as handle:
    handle.write(b'short')
k1 = nr.Masker().key()
check('a key cut short is made again, whole', len(k1), 32)
os.unlink(nr.ANON_KEY)
m1, m2 = nr.Masker(), nr.Masker()
check('two maskers that found no key end with one', m1.key() == m2.key(), True)
settings('<anonymize>1</anonymize>')

# ---------------------------------------------------------------- a report, masked

DAY = datetime.datetime(2026, 11, 18)
start, end = DAY, DAY + datetime.timedelta(hours=20)
nr.hostnames = lambda st: {'192.168.1.20': 'laptop', '192.168.1.1': 'OPNsense'}
nr.vnstat_volume = lambda dev, a, b: {'rx': 0, 'tx': 0, 'ok': False}
nr.vnstat_month = lambda dev: (0, 0)
nr.gateway_status = lambda: []
nr.gateway_events = lambda a, b: {}
nr.dns_stats = lambda a, b, n, only=None: {'total': 5, 'blocked': 0, 'top_blocked': [], 'top_clients': [['192.168.1.20', 5]], 'ok': True}
nr.web_activity = lambda a, b, n, only=None: {'ok': True, 'slow': False, 'devices': [
    {'client': '192.168.1.20', 'queries': 5, 'blocked': 0, 'domains': [['20.1.168.192.in-addr.arpa', 2]],
     'blocked_domains': [], 'hours': '08'}]}
nr.suricata_alerts = lambda a, b, n, only=None: {'total': 1, 'severe': 1, 'inbound': 1, 'inbound_severe': 1, 'out_total': 0,
                                                  'out_severe': 0, 'sigs': [['ET SCAN', 1]], 'srcs': [['203.0.113.9', 1]],
                                                  'out_sigs': [], 'out_hosts': []}
nr.crowdsec = lambda a: {'ok': False, 'alerts': 0, 'bans': 0}
nr.top_talkers = lambda st, a, b, n, only=None: [('192.168.1.20', 2000, 1000)]
nr.vpn_report = lambda st, a, b: None
nr.mail_stats = lambda a, b, n: {'ok': False}
nr.suricata_apps = lambda a, b, n: {'ok': False}
nr.ntopng_apps = lambda st, n: ([], '')
REAL_SYSTEM_INFO = nr.system_info
nr.system_info = lambda st, t: {'version': '26.7', 'uptime': '1 h', 'load': '0', 'temp': 0, 'mem': '?', 'disk': '?',
                                'disk_pct': 0, 'smart_ok': True, 'smart': '', 'backup_ts': 1, 'backup': 'x', 'tunnels': []}
nr.update_devices = lambda st: ({'02:00:00:00:00:aa': {'ip': '192.168.1.20', 'first_seen': DAY.timestamp() + 60,
                                                       'vendor': 'Acme', 'name': 'laptop'}}, [], {})
SCHED = {'uuid': 'u1', 'description': 'Daily', 'language': 'en_US', 'top_n': '5', 'compare': '0', 'period': 'day',
         'sections': 'summary,dns,web,security,devices,system', 'filter_device': '192.168.1.20'}
real = {'192.168.1.20', '02:00:00:00:00:aa', 'laptop', '203.0.113.9', '20.1.168.192'}

settings('<anonymize>0</anonymize>')
subject, page, text, _ = nr.build_report(nr.Settings(), SCHED, start, end)
check('off: the report names the device', all(w in page for w in ('192.168.1.20', 'laptop')), True)

s = settings('<anonymize>1</anonymize>')
subject, page, text, issues = nr.build_report(s, SCHED, start, end)
check('on: no address, MAC or name in the page', sorted(w for w in real if w in page), [])
check('on: none in the text', sorted(w for w in real if w in text), [])
check('on: the head says it', nr.texts('en_US')['anon_note'] in page, True)
mask = nr.ANON.addr('192.168.1.20')
check('on: the device by its masked value, in the device filter\'s head too', page.count(mask) >= 3, True)
csvdata = nr.export_file(page, subject, 'csv', DAY)[2].decode('utf-8-sig')
check('on: none in the CSV', sorted(w for w in real if w in csvdata), [])
check('on: the same value in the CSV', mask in csvdata, True)
again = nr.build_report(settings('<anonymize>1</anonymize>'), SCHED, start, end)[1]
check('two reports in a row: the same device, the same value', mask in again, True)

# ---------------------------------------------------------------- an alert, masked

SENT = []
alerts.deliver = lambda st, alert, record=None, slow=None, kept=False: SENT.append(alert) or {}
settings('<anonymize>1</anonymize>')
alerts.notify(nr.Settings(), None, 'login', '203.0.113.9', 'Repeated failed logins from 203.0.113.9',
              '5 failed logins from 203.0.113.9', facts={'address': '203.0.113.9'}, page='<p>203.0.113.9</p>')
a = SENT[-1]
check('an alert: subject, text, page and facts masked',
      ['203.0.113.9' in str(a[k]) for k in ('subject', 'text', 'html', 'facts')], [False] * 4)
check('an alert: its key, the state\'s own, as it was', a['key'], '203.0.113.9')
settings('<anonymize>0</anonymize>')
alerts.notify(nr.Settings(), None, 'login', '203.0.113.9', 'from 203.0.113.9', 'x')
check('off: an alert as it was', SENT[-1]['subject'], 'from 203.0.113.9')

# ---------------------------------------------------------------- the weekly backup

MAILS = []


def fake_send_mail(ms, rcpt, subject, page, text, attachment=None, before_send=None, after_send=None):
    MAILS.append((rcpt, subject, attachment))


nr.send_mail = fake_send_mail
nr.mail_settings = lambda st: {'host': 'mail.example.com', 'port': 465, 'security': 'ssl', 'user': '', 'password': '',
                               'sender': 'fw@example.com'}
nr.recipients_for = lambda st, sched, ms: ['ops@example.com']
CALLS = []


def fake_encrypt(password):
    CALLS.append(password)
    return '---- BEGIN config.xml ----\nVersion: OPNsense 26.7\n\nAAAA\n---- END config.xml ----\n'


nr.encrypted_config = fake_encrypt
s = settings('<backup_mail>1</backup_mail>')
r = nr.send_backup(s, DAY)
check('no password: nothing sent, and said', (r['status'], MAILS, CALLS), ('failed', [], []))
check('no password: the history says why', 'no backup password' in nr.load_json(nr.HISTORY_FILE, [])[0]['detail'], True)
s = settings('<backup_mail>1</backup_mail><backup_password>s3cret pass</backup_password>'
             '<backup_recipients>a@example.com,b@example.com</backup_recipients>')
r = nr.send_backup(s, DAY)
rcpt, subj, att = MAILS[-1]
check('a password: sent to the backup\'s recipients', (r['status'], rcpt), ('sent', ['a@example.com', 'b@example.com']))
check('the password goes to the encryption, whole', CALLS[-1], 's3cret pass')
check('the file: named as OPNsense names a backup, encrypted', (att[0], att[1], att[2][:26]),
      ('config-fw.example.net-20261118000000.xml', 'application/xml', b'---- BEGIN config.xml ----'))
check('the password is in neither the mail nor the history',
      ('s3cret' in subj, 's3cret' in json.dumps(nr.load_json(nr.HISTORY_FILE, []))), (False, False))
st = nr.load_json(nr.STATE_FILE, {})['backup']
check('kept: when it was sent', (st['status'], isinstance(st['last_sent'], float)), ('sent', True))
s = settings('<backup_mail>1</backup_mail><backup_password>p</backup_password>')
nr.send_backup(s, DAY)
check('no backup recipients: the default ones', MAILS[-1][0], ['ops@example.com'])

# when it is due
os.unlink(nr.STATE_FILE)
s = settings('<backup_mail>1</backup_mail><backup_password>p</backup_password><backup_day>3</backup_day>'
             '<backup_time>03:00</backup_time>')
wed = datetime.datetime(2026, 11, 18, 3, 0)            # a Wednesday, the day set (3)
check('turned on: counts from now, nothing sent for a time already past', nr.backup_due(s, wed + datetime.timedelta(minutes=5)), False)
check('the next Wednesday at 03:00: due', nr.backup_due(s, wed + datetime.timedelta(days=7)), True)
check('a minute later: not again', nr.backup_due(s, wed + datetime.timedelta(days=7, minutes=1)), False)
check('another day: not due', nr.backup_due(s, wed + datetime.timedelta(days=9)), False)
check('turned off: never due', nr.backup_due(settings('<backup_mail>0</backup_mail>'), wed + datetime.timedelta(days=14)), False)

# a stepped clock, a failed mail tried again hourly, off and on again, a password's spaces
os.unlink(nr.STATE_FILE)
s = settings('<backup_mail>1</backup_mail><backup_password>p</backup_password><backup_day>3</backup_day>'
             '<backup_time>03:00</backup_time>')
st = {'backup': {'last_try': (wed + datetime.timedelta(days=30)).timestamp()}}
nr.save_json(nr.STATE_FILE, st)
check('a last try in the future (a clock that was ahead): counts from now', nr.backup_due(s, wed + datetime.timedelta(days=7)), False)
check('... and the week after is due', nr.backup_due(s, wed + datetime.timedelta(days=14)), True)
st = nr.load_json(nr.STATE_FILE, {})
st['backup'].update(status='failed', failed_at=(wed + datetime.timedelta(days=14)).timestamp())
nr.save_json(nr.STATE_FILE, st)
check('failed: not tried again within the hour', nr.backup_due(s, wed + datetime.timedelta(days=14, minutes=30)), False)
check('failed: tried again an hour later', nr.backup_due(s, wed + datetime.timedelta(days=14, minutes=61)), True)
check('failed: not past the catch-up', nr.backup_due(s, wed + datetime.timedelta(days=14, hours=13)), False)
nr.backup_due(settings('<backup_mail>0</backup_mail>'), wed + datetime.timedelta(days=21, hours=1))
check('turned off: it forgets its last try', 'last_try' in nr.load_json(nr.STATE_FILE, {}).get('backup', {}), False)
check('on again two hours after its time: counts from then, sends nothing',
      nr.backup_due(s, wed + datetime.timedelta(days=21, hours=2)), False)
check('a password\'s spaces kept as typed', settings('<backup_password> p w </backup_password>').get('backup_password'), ' p w ')
if hasattr(nr.time, 'tzset'):
    old = os.environ.get('TZ')
    os.environ['TZ'] = 'America/New_York'
    nr.time.tzset()
    os.unlink(nr.STATE_FILE)
    s = settings('<backup_mail>1</backup_mail><backup_password>p</backup_password><backup_day>0</backup_day>'
                 '<backup_time>02:30</backup_time>')
    nr.backup_due(s, datetime.datetime(2026, 3, 1, 12, 0))          # turned on the Sunday before
    dst = datetime.datetime(2026, 3, 8, 3, 0)                       # 02:00 to 03:00 did not happen
    sent = sum(nr.backup_due(s, dst + datetime.timedelta(minutes=k)) for k in range(0, 60))
    check('the hour summer time skips: sent once, not every minute', sent, 1)
    if old is None:
        del os.environ['TZ']
    else:
        os.environ['TZ'] = old
    nr.time.tzset()

# the system section: its line, its warning, and the age warning counting the backup by mail
SYS = dict(SCHED, sections='summary,system', filter_device='')
s = settings('<backup_mail>1</backup_mail>')
_, page, _, issues = nr.build_report(s, SYS, start, end)
check('on with no password: said under Needs your attention', ('warn', nr.texts('en_US')['i_backup_nopass']) in issues, True)
check('the system section has the line of the backup by mail',nr.texts('en_US')['backup_mail_row'] in page, True)
s = settings('<backup_mail>0</backup_mail>')
_, page, _, issues = nr.build_report(s, SYS, start, end)
check('off: no line, no warning', (nr.texts('en_US')['backup_mail_row'] in page,
                                   any(i[1] == nr.texts('en_US')['i_backup_nopass'] for i in issues)), (False, False))
nr.run = lambda cmd, timeout=60: ''
nr.last_backup = lambda: None
state = nr.load_json(nr.STATE_FILE, {})
state['backup'] = {'last_sent': 1795000000.0, 'status': 'sent'}
nr.save_json(nr.STATE_FILE, state)
check('the age warning counts the backup by mail', REAL_SYSTEM_INFO(s, nr.texts('en_US'))['backup_ts'], 1795000000.0)
nr.system_info = lambda st, t: {'version': '26.7', 'uptime': '1 h', 'load': '0', 'temp': 0, 'mem': '?', 'disk': '?',
                                'disk_pct': 0, 'smart_ok': True, 'smart': '', 'backup': 'x', 'tunnels': [],
                                'backup_ts': nr.time.time() - 4 * 86400}
s = settings('<backup_mail>1</backup_mail><backup_password>p</backup_password><backup_warn>2</backup_warn>')
issues = nr.build_report(s, SYS, start, end)[3]
check('with the weekly backup on, a 4-day-old backup is no warning', any('backup' in i[1].lower() for i in issues), False)
s = settings('<backup_mail>0</backup_mail><backup_warn>2</backup_warn>')
issues = nr.build_report(s, SYS, start, end)[3]
check('without it, it is', any(i[1] == nr.texts('en_US')['i_backup_old'].format(n=4) for i in issues), True)
# a VPN alert: the connection's device masked in every field
settings('<anonymize>1</anonymize>')
alerts.notify(nr.Settings(), None, 'vpn', 'wg|wg0|k', 'VPN down: WireGuard Laptop', 'WireGuard Laptop is down',
              facts={'connection': 'WireGuard Laptop', 'state': 'down'})
a = SENT[-1]
check('a VPN alert: the peer\'s name in none of its fields',
      ['Laptop' in str(a[k]) for k in ('subject', 'text', 'facts')], [False, False, False])
print('%d checks, %d failed' % (checks, failures))
sys.exit(1 if failures else 0)
