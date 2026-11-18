#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The report's VPN, web activity, applications and mail sections (netreport.py), and the tunnel watch's
log they read (alerts.py): each reader on recorded-format input, with no firewall behind it.

    python3 tools/test-sections.py      prints one line a check, and exits 1 on any failure
"""
import datetime
import importlib
import json
import os
import sys
import tempfile
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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

TOP = tempfile.mkdtemp(prefix='test-sections.')
STATE = os.path.join(TOP, 'db')
os.makedirs(STATE)
nr.CONFIG = os.path.join(TOP, 'config.xml')
nr.STATE_DIR = STATE
alerts.STATE_FILE = os.path.join(STATE, 'alerts-state.json')
nr.log = lambda msg: None

CONFIG = '''<?xml version="1.0"?>
<opnsense>
  <system><hostname>fw</hostname><language>en_US</language></system>
  <OPNsense>
    <NetReport><general><alerts>1</alerts><vpn_alert>0</vpn_alert>%s</general></NetReport>
    <Swanctl><Connections><Connection uuid="c1"><description>Branch office</description></Connection></Connections></Swanctl>
    <OpenVPN><Instances><Instance uuid="o1"><enabled>1</enabled><role>server</role><description>Road warriors</description></Instance></Instances></OpenVPN>
    <wireguard><client><clients><client uuid="w1"><name>Laptop</name><pubkey>PUBKEYLAPTOP0000</pubkey></client></clients></client></wireguard>
  </OPNsense>
</opnsense>
'''


def settings(extra=''):
    with open(nr.CONFIG, 'w') as fh:
        fh.write(CONFIG % extra)
    return nr.Settings()


def ts(text):
    return datetime.datetime.fromisoformat(text).timestamp()


# ---------------------------------------------------------------- hour_ranges

check('hour_ranges: runs and single hours', nr.hour_ranges([23, 0, 1, 2, 5, 7, 8]), '00–02, 05, 07–08, 23')
check('hour_ranges: nothing', nr.hour_ranges([]), '')

# ---------------------------------------------------------------- vpn_outages

S, E, NOW = 1000.0, 2000.0, 2500.0
log = [{'key': 'a', 'event': 'down', 'at': 900}, {'key': 'a', 'event': 'back', 'at': 1100},
       {'key': 'a', 'event': 'down', 'at': 1500}, {'key': 'a', 'event': 'back', 'at': 1600},
       {'key': 'b', 'event': 'down', 'at': 1900}, {'key': 'c', 'event': 'down', 'at': 3000}]
check('vpn_outages: a down from before the period counts from its start, not as an outage of it',
      nr.vpn_outages(log, 'a', S, E, NOW), (1, 100 + 100))
check('vpn_outages: a down still running counts up to the period end', nr.vpn_outages(log, 'b', S, E, NOW), (1, 100))
check('vpn_outages: one after the period is not counted', nr.vpn_outages(log, 'c', S, E, NOW), (0, 0))
check('vpn_outages: a down still running in an open period counts up to now',
      nr.vpn_outages([{'key': 'd', 'event': 'down', 'at': 2400}], 'd', S, 3000.0, NOW), (1, 100))

# ---------------------------------------------------------------- the tunnel watch's log (alerts.py)

state = alerts.State()
alerts.vpn_logged(state, 'k', 'IPsec x', ('down', 100.0))
alerts.vpn_logged(state, 'k', 'IPsec x', ('down', 100.0))
alerts.vpn_logged(state, 'k', 'IPsec x', ('back', 160.0, 60))
check('vpn_logged: a change put back and said again is logged once', [(x['event'], x['at']) for x in state.data['vpn_log']],
      [('down', 100.0), ('back', 160.0)])
check('vpn_logged: a back keeps how long it was down', state.data['vpn_log'][-1].get('down'), 60)
alerts.vpn_logged(state, 'k', 'IPsec x', ('down', 160.0 + alerts.VPN_LOG_KEEP + 10))
check('vpn_logged: entries older than VPN_LOG_KEEP go', len(state.data['vpn_log']), 1)

# collect_vpn logs each down and back with its alert off (vpn_alert 0), and sends nothing
reads = []
alerts.vpn_reads = lambda settings_, entries, now: ({'ipsec|c1': ('IPsec Branch office', reads.pop(0))}, ['ipsec|'])
sent = []
alerts.notify = lambda *a, **k: sent.append(a)
s1 = settings()
state = alerts.State()
for i, read in enumerate(['up', 'up', 'down', 'down', 'up', 'up']):
    reads.append(read)
    alerts.collect_vpn(s1, state, 1000.0 + 60 * i)
check('collect_vpn: the log holds the down and the back with the alert off',
      [(x['event'], x['at']) for x in state.data.get('vpn_log', [])], [('down', 1120.0), ('back', 1240.0)])
check('collect_vpn: and no alert was sent', sent, [])
check('collect_vpn: the log says since when it records', state.data.get('vpn_log_since'), 1000.0)

# ---------------------------------------------------------------- vpn_sessions

ANSWERS = {
    ('ipsec', 'list', 'status'): {'c1': {'remote-addrs': '198.51.100.7', 'sas': [
        {'state': 'ESTABLISHED', 'remote-host': '198.51.100.7', 'remote-id': '198.51.100.7', 'established': '120',
         'child-sas': {'c1-1': {'state': 'INSTALLED', 'bytes-in': '1000', 'bytes-out': '500'}}},
        {'state': 'ESTABLISHED', 'remote-host': '203.0.113.9', 'remote-eap-id': 'alice', 'remote-vips': ['10.0.0.2'],
         'established': 60, 'child-sas': [{'state': 'INSTALLED', 'bytes-in': 10, 'bytes-out': 20}]},
        {'state': 'CONNECTING', 'remote-host': '203.0.113.10', 'established': 1}]}},
    ('openvpn', 'connections', 'client,server'): {'server': {'o1': {'status': 'ok', 'client_list': [
        {'common_name': 'bob-laptop', 'username': 'UNDEF', 'real_address': '203.0.113.20:5000',
         'virtual_address': '10.0.0.6', 'connected_since__time_t_': '1700000000', 'bytes_received': '300',
         'bytes_sent': '700'},
        {'common_name': 'carol', 'username': 'carol.s', 'real_address': '203.0.113.21:5001',
         'connected_since__time_t_': 1700000100, 'bytes_received': 1, 'bytes_sent': 2}]}}, 'client': {}},
    ('wireguard', 'show'): {'status': 'ok', 'records': [
        {'type': 'interface', 'if': 'wg0'},
        {'type': 'peer', 'if': 'wg0', 'public-key': 'PUBKEYLAPTOP0000', 'endpoint': '203.0.113.30:51820',
         'latest-handshake': 9900, 'transfer-rx': 40, 'transfer-tx': 2},
        {'type': 'peer', 'if': 'wg0', 'public-key': 'STALEPEER0000000', 'endpoint': '203.0.113.31:51820',
         'latest-handshake': 9000, 'transfer-rx': 1, 'transfer-tx': 1}]},
}
nr.configctl_json = lambda *args, **kw: ANSWERS.get(tuple(args))
rows = nr.vpn_sessions(settings(), 10000.0)
check('vpn_sessions: IPsec, one row an established IKE session, its name from the configuration',
      [r for r in rows if r[0] == 'IPsec'],
      [('IPsec', 'Branch office', '198.51.100.7', '198.51.100.7', 10000.0 - 120, 1500),
       ('IPsec', 'Branch office', 'alice', '10.0.0.2', 10000.0 - 60, 30)])
check('vpn_sessions: OpenVPN, the common name where the user name is UNDEF, the virtual address first',
      [r for r in rows if r[0] == 'OpenVPN'],
      [('OpenVPN', 'Road warriors', 'bob-laptop', '10.0.0.6', 1700000000, 1000),
       ('OpenVPN', 'Road warriors', 'carol.s', '203.0.113.21:5001', 1700000100, 3)])
check('vpn_sessions: WireGuard, a peer by its name, only while its handshake is under 300 s old',
      [r for r in rows if r[0] == 'WireGuard'], [('WireGuard', 'wg0', 'Laptop', '203.0.113.30:51820', None, 42)])
nr.configctl_json = lambda *args, **kw: None
check('vpn_sessions: no service answering is no session', nr.vpn_sessions(settings(), 10000.0), [])

# ---------------------------------------------------------------- vpn_report

with open(alerts.STATE_FILE, 'w') as fh:
    json.dump({'vpn': {'ipsec|c1': {'state': 'down', 'since': 1500.0}},
               'vpn_log': [{'key': 'ipsec|c1', 'event': 'down', 'at': 1500.0}], 'vpn_log_since': 1200.0}, fh)
alerts.vpn_reads = lambda settings_, entries, now: ({
    'ipsec|c1': ('IPsec Branch office', 'down'), 'ovpn|s|o1|': ('OpenVPN Road warriors', 'up'),
    'ovpn|s|o1|bob-laptop': ('OpenVPN Road warriors: bob-laptop', 'up')}, ['ipsec|', 'ovpn|'])
nr.configctl_json = lambda *args, **kw: ANSWERS.get(tuple(args))
period = (datetime.datetime.fromtimestamp(1000.0), datetime.datetime.fromtimestamp(2000.0))
vpn = nr.vpn_report(settings(), *period)
check('vpn_report: tunnels, an OpenVPN server\'s clients left to the sessions',
      [(x['name'], x['up'], x['outages']) for x in vpn['tunnels']],
      [('IPsec Branch office', False, 1), ('OpenVPN Road warriors', True, 0)])
check('vpn_report: the time down within the period', vpn['tunnels'][0]['down'], 500.0)
check('vpn_report: since when the log records, as it began within the period', vpn['log_since'], 1200.0)
check('vpn_report: the sessions', len(vpn['sessions']), 4)
os.remove(alerts.STATE_FILE)
alerts.vpn_reads = lambda settings_, entries, now: ({}, [])
nr.configctl_json = lambda *args, **kw: None
check('vpn_report: no tunnel and no session is no VPN', nr.vpn_report(settings(), *period), None)

# ---------------------------------------------------------------- mail_stats

MAIL = os.path.join(TOP, 'postfix')
os.makedirs(MAIL)
nr.POSTFIX_LOGS = os.path.join(MAIL, 'postfix_*.log')
start, end = datetime.datetime(2026, 11, 18, 0, 0), datetime.datetime(2026, 11, 19, 0, 0)
check('mail_stats: no log is no mail server', nr.mail_stats(start, end, 5)['ok'], False)


def line(when, text):
    return '<22>1 %s fw postfix/smtp 1234 - [meta sequenceId="1"] %s\n' % (
        datetime.datetime.fromisoformat(when).astimezone().isoformat(), text)


with open(os.path.join(MAIL, 'postfix_20261118.log'), 'w') as fh:
    fh.write(line('2026-11-18T08:00:00', 'ABC1: to=<a@example.com>, relay=mx[192.0.2.5]:25, delay=1, status=sent (250 ok)'))
    fh.write(line('2026-11-18T08:01:00', 'ABC2: to=<b@example.com>, relay=mx[192.0.2.5]:25, delay=1, status=sent (250 ok)'))
    fh.write(line('2026-11-18T08:02:00', 'ABC3: to=<c@example.com>, status=deferred (connection timed out)'))
    fh.write(line('2026-11-18T08:03:00', 'ABC4: to=<d@example.com>, status=bounced (user unknown)'))
    fh.write(line('2026-11-18T09:00:00', 'NOQUEUE: reject: RCPT from unknown[198.51.100.44]: 554 5.7.1 rejected'))
    fh.write(line('2026-11-18T09:05:00', 'NOQUEUE: reject: RCPT from spam.example[198.51.100.44]: 450 4.7.1 later'))
    fh.write(line('2026-11-18T09:06:00', 'NOQUEUE: reject: RCPT from other.example[2001:db8::7]: 554 rejected'))
    fh.write(line('2026-11-19T01:00:00', 'ABC5: to=<e@example.com>, status=sent (250 ok)'))
mail = nr.mail_stats(start, end, 5)
check('mail_stats: delivered, deferred, bounced and refused in the period',
      (mail['ok'], mail['sent'], mail['deferred'], mail['bounced'], mail['rejected']), (True, 2, 1, 1, 3))
check('mail_stats: the addresses refused most', mail['rejects'], [('198.51.100.44', 2), ('2001:db8::7', 1)])

# ---------------------------------------------------------------- suricata_apps

EVE = os.path.join(TOP, 'eve')
os.makedirs(EVE)
nr.EVE_LOGS = os.path.join(EVE, 'eve.json*')
check('suricata_apps: no log is no records', nr.suricata_apps(start, end, 5)['ok'], False)


def eve(when, **fields):
    stamp = datetime.datetime.fromisoformat(when).astimezone().strftime('%Y-%m-%dT%H:%M:%S.000000%z')
    return json.dumps(dict(timestamp=stamp, **fields), separators=(',', ':')) + '\n'


with open(os.path.join(EVE, 'eve.json'), 'w') as fh:
    fh.write(eve('2026-11-18T10:00:00', event_type='tls', app_proto='tls', tls={'sni': 'Example.COM'}))
    fh.write(eve('2026-11-18T10:01:00', event_type='tls', app_proto='tls', tls={'sni': 'example.com'}))
    fh.write(eve('2026-11-18T10:02:00', event_type='http', app_proto='http', http={'hostname': 'plain.example'}))
    fh.write(eve('2026-11-18T10:03:00', event_type='alert', app_proto='dns', alert={'severity': 2}))
    fh.write(eve('2026-11-18T10:04:00', event_type='anomaly', app_proto='failed'))
    fh.write(eve('2026-11-17T10:00:00', event_type='tls', app_proto='tls', tls={'sni': 'yesterday.example'}))
apps = nr.suricata_apps(start, end, 5)
check('suricata_apps: protocols, "failed" left out', apps['protos'], [('tls', 2), ('http', 1), ('dns', 1)])
check('suricata_apps: sites by TLS name and HTTP host, in the period only', apps['sites'],
      [('example.com', 2), ('plain.example', 1)])

# ---------------------------------------------------------------- ntopng_apps

ANSWER = {}


class Ntopng(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Authorization') != 'Token good-token' or not self.path.startswith('/lua/rest/v2/get/interface/l7/stats.lua'):
            self.send_response(401)
            self.end_headers()
            return
        body = json.dumps(ANSWER['body']).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(('127.0.0.1', 0), Ntopng)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = 'http://127.0.0.1:%d' % server.server_address[1]
check('ntopng_apps: no token, nothing asked', nr.ntopng_apps(settings(), 5), ([], None))
ANSWER['body'] = {'rc': 0, 'rsp': {'TLS': 5000, 'YouTube': 9000, 'DNS': 10}}
good = settings('<ntopng_url>%s</ntopng_url><ntopng_token>good-token</ntopng_token>' % url)
check('ntopng_apps: an object of name -> bytes, the largest first', nr.ntopng_apps(good, 2),
      ([('YouTube', 9000), ('TLS', 5000)], None))
ANSWER['body'] = {'rc': 0, 'rsp': [{'label': 'Netflix', 'bytes': 70}, {'name': 'Zoom', 'value': 90}, {'label': 'bad'}]}
check('ntopng_apps: a list of objects', nr.ntopng_apps(good, 5), ([('Zoom', 90), ('Netflix', 70)], None))
ANSWER['body'] = {'rc': -2, 'rsp': {}}
check('ntopng_apps: ntopng refusing says so', nr.ntopng_apps(good, 5), ([], 'rc -2'))
bad = settings('<ntopng_url>%s</ntopng_url><ntopng_token>wrong</ntopng_token>' % url)
rows, why = nr.ntopng_apps(bad, 5)
check('ntopng_apps: a token refused is said, not shown as no applications', (rows, 'Unauthorized' in (why or '') or '401' in (why or '')), ([], True))
server.shutdown()

print('%d checks, %d failure(s)' % (checks, failures))
sys.exit(1 if failures else 0)
