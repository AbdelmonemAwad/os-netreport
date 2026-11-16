#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""alerts.py, the alert layer, and the collectors that feed it, without a firewall: the logs, the files
other plugins leave and the state are in a temporary directory, configctl and the gateway status are
stand-ins, and the webhook and ntfy are a small HTTP server on 127.0.0.1. Mail is a stand-in too: what
would have gone out is kept and compared.

    python3 tools/test-alerts.py"""
import base64
import datetime
import importlib
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, HTTPServer

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


# netreport.py takes a lock with fcntl and logs with syslog, neither of which every system has; the
# scheduler's lock is not what is tested here
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

TOP = tempfile.mkdtemp(prefix='test-alerts.')
STATE = os.path.join(TOP, 'db')
os.makedirs(STATE)
nr.CONFIG = os.path.join(TOP, 'config.xml')
nr.STATE_DIR = STATE
nr.STATE_FILE = os.path.join(STATE, 'state.json')
nr.DEVICES_FILE = os.path.join(STATE, 'devices.json')
nr.HISTORY_FILE = os.path.join(STATE, 'history.json')
nr.ARCHIVE_DIR = os.path.join(STATE, 'archive')
nr.LOCK_FILE = os.path.join(TOP, 'netreport.lock')
alerts.STATE_FILE = os.path.join(STATE, 'alerts-state.json')
LOGGED = []
nr.log = LOGGED.append

# ---------------------------------------------------------------- the stand-ins

POSTS = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        POSTS.append({'path': self.path, 'headers': dict(self.headers), 'body': body})
        code = 500 if self.path.startswith('/fail') else 200
        self.send_response(code)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


SERVER = HTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
BASE = 'http://127.0.0.1:%d' % SERVER.server_address[1]

MAILS = []
MAIL = {'fail': None}


def fake_mail_settings(settings):
    if MAIL['fail']:
        raise RuntimeError(MAIL['fail'])
    return {'host': 'mail.example.com', 'port': 465, 'security': 'ssl', 'user': 'fw@example.com', 'password': 'x',
            'sender': 'fw@example.com'}


def fake_send_mail(ms, rcpt, subject, page, text, attach_name=None):
    MAILS.append({'to': rcpt, 'subject': subject, 'html': page, 'text': text})


nr.mail_settings = fake_mail_settings
nr.send_mail = fake_send_mail

EXTRA = {'xml': ''}
GENERAL = {'enabled': '1', 'title': 'Example network', 'recipients': 'admin@example.com', 'language': 'en_US',
           'alerts': '1', 'alert_mail': '1', 'alert_webhook_url': BASE + '/hook',
           'alert_webhook_header': 'Authorization: Bearer example-secret', 'alert_ntfy_server': BASE + '/ntfy/',
           'alert_ntfy_topic': 'example-topic', 'alert_ntfy_token': 'tk_example', 'new_device_alert': '1'}


def config(**changes):
    """write config.xml with the general settings and these changes; returns fresh Settings"""
    general = dict(GENERAL, **changes)
    fields = ''.join('<%s>%s</%s>' % (k, v, k) for k, v in general.items())
    with open(nr.CONFIG, 'w', encoding='utf-8') as fh:
        fh.write('<?xml version="1.0"?><opnsense><system><hostname>fw</hostname><domain>example.com</domain>'
                 '</system><OPNsense><NetReport><general>%s</general><schedules/></NetReport>%s</OPNsense>'
                 '<interfaces><lan><if>em1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan></interfaces>'
                 '</opnsense>' % (fields, EXTRA['xml']))
    return nr.Settings()


def reset():
    del POSTS[:]
    del MAILS[:]
    MAIL['fail'] = None


def posts(prefix):
    return [p for p in POSTS if p['path'].startswith(prefix)]


def history():
    return nr.load_json(nr.HISTORY_FILE, [])


# ---------------------------------------------------------------- 1. the layer

settings = config()
reset()
results = alerts.test_alert(settings)
check('test alert: every channel that is set says sent', results, {'mail': 'sent', 'webhook': 'sent', 'ntfy': 'sent'})
hook = json.loads(posts('/hook')[0]['body'])
check('webhook: the JSON the README describes', sorted(hook), ['at', 'facts', 'host', 'kind', 'source', 'subject', 'text'])
check('webhook: source, host and kind', (hook['source'], hook['host'], hook['kind']), ('os-netreport', 'fw.example.com', 'test'))
check('webhook: the header the user set', posts('/hook')[0]['headers'].get('Authorization'), 'Bearer example-secret')
check('webhook: the time carries its offset', hook['at'][19:20] in ('+', '-') or hook['at'].endswith('Z'), True)
ntfy = posts('/ntfy/')[0]
check('ntfy: posted to <server>/<topic>', ntfy['path'], '/ntfy/example-topic')
check('ntfy: title, priority and token', (ntfy['headers'].get('Title'), ntfy['headers'].get('Priority'),
                                          ntfy['headers'].get('Authorization')),
      ('=?UTF-8?B?' + base64.b64encode('Test alert — Example network'.encode('utf-8')).decode() + '?=',
       'default', 'Bearer tk_example'))
check('ntfy: the plain text is the body', ntfy['body'].decode('utf-8'), 'This is a test alert from fw.example.com. '
      'If it arrived, alerts reach this channel.')
check('mail: to the default recipients, with HTML', (MAILS[0]['to'], '<html' in MAILS[0]['html']), (['admin@example.com'], True))
check('history: one line with the result per channel', (history()[0]['status'], history()[0]['detail']),
      ('alert', 'mail: sent; webhook: sent; ntfy: sent'))

settings = config(alert_webhook_url='', alert_ntfy_server='', alert_mail='0')
reset()
check('no channel set: each says not set', alerts.test_alert(settings), {'mail': 'not set', 'webhook': 'not set', 'ntfy': 'not set'})
check('no channel set: said in the history', (history()[0]['status'], history()[0]['detail']), ('failed', 'no alert channel is set'))
settings = config(alert_ntfy_topic='')
check('ntfy without a topic is not set', alerts.test_alert(settings)['ntfy'], 'not set')

settings = config(alert_webhook_url=BASE + '/fail')
reset()
MAIL['fail'] = 'No mail server: configure Services: Monit or a custom SMTP server.'
results = alerts.test_alert(settings)
check('a failing channel does not stop the others', (results['mail'], results['webhook'][:8], results['ntfy']),
      ('No mail server: configure Services: Monit or a custom SMTP server.', 'HTTP 500', 'sent'))
check('one channel sent: the try is an alert in the history', history()[0]['status'], 'alert')

settings = config(alert_webhook_header='not a header')
reset()
check('a header that is not Name: value is the webhook error', alerts.test_alert(settings)['webhook'],
      'the webhook header must be one line, Name: value')

settings = config()
reset()
state = alerts.State()
NOW = float(int(time.time()))
first = alerts.notify(settings, state, 'example', 'k1', 'Subject one', 'Text one', now=NOW)
again = alerts.notify(settings, state, 'example', 'k1', 'Subject one', 'Text one', now=NOW + 60)
other = alerts.notify(settings, state, 'example', 'k2', 'Subject two', 'Text two', now=NOW + 60)
later = alerts.notify(settings, state, 'example', 'k1', 'Subject one', 'Text one', now=NOW + alerts.QUIET_DEFAULT + 1)
check('quiet time: the same key is held back within it', (first is not None, again, other is not None, later is not None),
      (True, None, True, True))
check('quiet time: kept in alerts-state.json', sorted(nr.load_json(alerts.STATE_FILE, {}).get('sent', {})),
      ['example|k1', 'example|k2'])
check('the state file is written whole (no temporary file left)', sorted(os.listdir(STATE)),
      ['alerts-state.json', 'history.json'])

reset()
settings = config(language='ar_SA')
alerts.test_alert(settings)
check('ntfy: a title outside ASCII goes RFC 2047 encoded', posts('/ntfy/')[0]['headers'].get('Title', '')[:10], '=?UTF-8?B?')
check('the alert speaks the alert language', MAILS[0]['subject'],
      nr.texts('ar_SA')['test_alert_subject'].format(title='Example network'))

reset()
settings = config()
db = {'02:00:00:00:00:01': {'ip': '192.0.2.50', 'vendor': 'Example Corp', 'first_seen': NOW}}
nr.new_device_alert(settings, db, ['02:00:00:00:00:01'])
hook = json.loads(posts('/hook')[0]['body'])
check('new device: through the layer, to the webhook too', (hook['kind'], hook['facts']['devices'][0]['mac']),
      ('new_device', '02:00:00:00:00:01'))
check('new device: its own HTML mail', 'Example Corp' in MAILS[0]['html'] and '02:00:00:00:00:01' in MAILS[0]['html'], True)
check('new device: and ntfy', len(posts('/ntfy/')), 1)

# ---------------------------------------------------------------- 2. gateways

GATEWAYS = {}
nr.gateway_status = lambda: [{'name': n, 'status': s, 'delay': '~' if s == 'nomon' else '1.0 ms', 'loss': '0.0 %'}
                             for n, s in GATEWAYS.items()]


def minute(collect, n=1, **reads):
    """n reads, a minute apart, of the given states; returns the webhook kinds/subjects sent"""
    global CLOCK
    sent = []
    for _ in range(n):
        CLOCK += 60
        GATEWAYS.update(reads)
        before = len(posts('/hook'))
        state = alerts.State()
        collect(config(), state, CLOCK)
        state.save()
        sent += [json.loads(p['body']) for p in posts('/hook')[before:]]
    return sent


CLOCK = NOW + 3600
reset()
GATEWAYS.clear()
GATEWAYS.update({'WAN_DHCP': 'none', 'WAN2_GW': 'down', 'LINKLOCAL': 'nomon'})
check('gateways: the first run sends nothing', minute(alerts.collect_gateways), [])
check('gateways: one bad minute is not an alert', minute(alerts.collect_gateways, WAN_DHCP='down') +
      minute(alerts.collect_gateways, WAN_DHCP='none'), [])
minute(alerts.collect_gateways, 15, WAN_DHCP='none')     # the bad minute out of the flapping window
down_at = CLOCK + 60
sent = minute(alerts.collect_gateways, 2, WAN_DHCP='down')
check('gateways: down on two reads in a row: one alert', [s['subject'] for s in sent],
      ['Gateway WAN_DHCP is down — Example network'])
check('gateways: down since the first read that saw it', sent[0]['text'],
      'Gateway WAN_DHCP has been down since %s.' % alerts.local_time(down_at))
check('gateways: down says so in its facts', (sent[0]['kind'], sent[0]['facts']['state']), ('gateway', 'down'))
check('gateways: still down, nothing more', minute(alerts.collect_gateways, 3), [])
back_at = CLOCK + 60
sent = minute(alerts.collect_gateways, 2, WAN_DHCP='none')
check('gateways: back, with how long it was down', [s['text'] for s in sent],
      ['Gateway WAN_DHCP came back at %s, after 5 min down.' % alerts.local_time(back_at)])
check('gateways: a gateway down when first seen is not reported back', minute(alerts.collect_gateways, 2, WAN2_GW='none'), [])
check('gateways: ... but its next outage is', [s['facts']['gateway'] for s in minute(alerts.collect_gateways, 2, WAN2_GW='down')],
      ['WAN2_GW'])
minute(alerts.collect_gateways, 2, WAN2_GW='none')
check('gateways: monitoring off is never an alert', [s for s in POSTS if b'LINKLOCAL' in s['body']], [])

minute(alerts.collect_gateways, 15, WAN_DHCP='none')
reset()
sent = []
for state_now in ['down', 'none', 'down', 'none', 'down', 'none', 'down', 'none']:
    sent += minute(alerts.collect_gateways, WAN_DHCP=state_now)
check('flapping: more than 3 changes in 15 minutes: one alert instead', [s['facts']['state'] for s in sent], ['flapping'])
check('flapping: says how many changes', sent[0]['text'], 'Gateway WAN_DHCP changed state 4 times in 15 minutes. '
      'No more alerts for it until it holds one state for 15 minutes.')
check('flapping: nothing while it has not held a state for 15 minutes', minute(alerts.collect_gateways, 14, WAN_DHCP='none'), [])
sent = minute(alerts.collect_gateways, 1, WAN_DHCP='none')
check('flapping: steady again after 15 minutes in one state', [s['facts']['state'] for s in sent], ['steady'])
check('flapping: then down and back as before', [s['facts']['state'] for s in minute(alerts.collect_gateways, 2, WAN_DHCP='down') +
                                                 minute(alerts.collect_gateways, 2, WAN_DHCP='none')], ['down', 'back'])

reset()
minute(alerts.collect_gateways, 2, WAN_DHCP='down')
GENERAL['gateway_alert'] = '0'
check('gateways: with gateway_alert off, nothing', minute(alerts.collect_gateways, 2, WAN_DHCP='none'), [])
GENERAL['gateway_alert'] = '1'
GENERAL['alerts'] = '0'
check('gateways: with the master switch off, nothing', minute(alerts.collect_gateways, 2, WAN_DHCP='down'), [])
GENERAL['alerts'] = '1'
check('gateways: turned on again, it goes on from where things are', minute(alerts.collect_gateways, 2, WAN_DHCP='down'), [])

# ---------------------------------------------------------------- 3. logins, IPS, VPN, watchdog


def stamp(at):
    return datetime.datetime.fromtimestamp(at).astimezone().isoformat(timespec='seconds')


def syslog_line(at, app, message):
    return '<38>1 %s fw.example.com %s 4242 - [meta sequenceId="1"] %s\n' % (stamp(at), app, message)


def append(path, text):
    with open(path, 'a', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def sent_by(collect, n=1):
    return [s for s in minute(collect, n)]


alerts.AUDIT_LOG = os.path.join(TOP, 'audit_{day}.log')
CLOCK = float(int(time.time()) // 86400 * 86400 + 6 * 3600 - time.localtime().tm_gmtoff)   # 06:00 local, today
audit = lambda: alerts.day_file(alerts.AUDIT_LOG, CLOCK + 60)
reset()
append(audit(), ''.join(syslog_line(CLOCK - 30, 'audit', 'user admin failed authentication for WebGui on Local '
                                    'Database via Local Database at 203.0.113.5') for _ in range(10)))
check('logins: the first run sends nothing (old lines are history)', sent_by(alerts.collect_logins), [])


def gui_failures(n, address='203.0.113.5', user='admin'):
    append(audit(), ''.join(syslog_line(CLOCK + 30, 'audit', 'user %s failed authentication for WebGui on Local Database '
                                        'via Local Database at %s' % (user, address)) for _ in range(n)))


gui_failures(3)
gui_failures(1, user='root')
check('logins: under the count, nothing', sent_by(alerts.collect_logins), [])
gui_failures(1, user='root')
sent = sent_by(alerts.collect_logins)
check('logins: at the count, one alert for the address', [s['subject'] for s in sent],
      ['Repeated failed logins from 203.0.113.5 — Example network'])
check('logins: the user names, the count and the services', (sent[0]['facts']['users'], sent[0]['facts']['count'],
                                                             sent[0]['facts']['services']), (['admin', 'root'], 5, ['WebGui']))
gui_failures(5)
check('logins: then quiet for that address', sent_by(alerts.collect_logins), [])
for port in range(50001, 50006):
    append(audit(), syslog_line(CLOCK + 30, 'sshd', 'Invalid user guest from 198.51.100.7 port %d' % port) +
           syslog_line(CLOCK + 30, 'sshd', 'Failed password for invalid user guest from 198.51.100.7 port %d ssh2' % port))
sent = sent_by(alerts.collect_logins)
check('logins: sshd, one try counted once although two lines say it', [(s['facts']['address'], s['facts']['count'])
                                                                       for s in sent], [('198.51.100.7', 5)])
for _ in range(4):
    append(audit(), syslog_line(CLOCK + 30, 'sshd', 'error: PAM: Authentication error for illegal user test from 198.51.100.8'))
    CLOCK += 5
check('logins: PAM errors count too, and four are under the count', sent_by(alerts.collect_logins), [])
append(audit(), syslog_line(CLOCK + 30, 'audit', '[203.0.113.9] authentication failed for api key EXAMPLEKEYexamplesecret1') * 5)
sent = sent_by(alerts.collect_logins)
check('logins: an API key shows its first 4 characters only', sent[0]['facts']['users'] if sent else None, ['API key EXAM…'])
check('logins: and the key is in no alert and no state', any(b'EXAMPLEKEYexample' in p['body'] for p in POSTS) or
      'EXAMPLEKEYexample' in open(alerts.STATE_FILE, encoding='utf-8').read(), False)
check('logins: older than 10 minutes, a failure no longer counts', (minute(alerts.collect_logins, 11),
                                                                    nr.load_json(alerts.STATE_FILE, {})['login']['fails']), ([], {}))

old = audit()
os.replace(old, old + '.0')
gui_failures(5, address='203.0.113.20')
check('logins: a new inode starts again at 0', [s['facts']['address'] for s in sent_by(alerts.collect_logins)],
      ['203.0.113.20'])
MIDNIGHT = datetime.datetime.combine(datetime.date.fromtimestamp(CLOCK) + datetime.timedelta(days=1),
                                     datetime.time()).timestamp()
CLOCK = MIDNIGHT - 120
minute(alerts.collect_logins)
append(alerts.day_file(alerts.AUDIT_LOG, MIDNIGHT - 60), syslog_line(MIDNIGHT - 30, 'audit', 'user admin failed '
       'authentication for WebGui on Local Database via Local Database at 203.0.113.21') * 2)
append(alerts.day_file(alerts.AUDIT_LOG, MIDNIGHT + 60), syslog_line(MIDNIGHT + 10, 'audit', 'user admin failed '
       'authentication for WebGui on Local Database via Local Database at 203.0.113.21') * 3)
check('logins: a new day: the rest of the old file, then the new one', [(s['facts']['address'], s['facts']['count'])
                                                                       for s in sent_by(alerts.collect_logins)],
      [('203.0.113.21', 5)])

# syslog-ng's suppress(): five identical lines within seconds are the first, then "repeated 4 times"
FOLD = "Last message '%s' repeated %d times, suppressed by syslog-ng on fw.example.com"
GUI_FAIL = 'user labuser failed authentication for WebGui on Local Database via Local Database at 203.0.113.22'
append(audit(), syslog_line(CLOCK + 20, 'audit', GUI_FAIL) + syslog_line(CLOCK + 25, 'audit', FOLD % (GUI_FAIL[:20], 4)))
check('logins: a line syslog-ng folded counts as many times as it was repeated',
      [(s['facts']['address'], s['facts']['count']) for s in sent_by(alerts.collect_logins)], [('203.0.113.22', 5)])
append(audit(), syslog_line(CLOCK + 20, 'audit', GUI_FAIL.replace('.22', '.23')))
sent_by(alerts.collect_logins)
append(audit(), syslog_line(CLOCK + 20, 'audit', FOLD % (GUI_FAIL[:20], 4)))
check('logins: ... also when the fold is read the minute after its line',
      [(s['facts']['address'], s['facts']['count']) for s in sent_by(alerts.collect_logins)], [('203.0.113.23', 5)])
append(audit(), syslog_line(CLOCK + 20, 'audit', GUI_FAIL.replace('.22', '.24')) +
       syslog_line(CLOCK + 21, 'sshd', 'Connection closed by 192.0.2.9 port 50000') +
       syslog_line(CLOCK + 25, 'audit', FOLD % ('something else entire', 4)) +
       syslog_line(CLOCK + 26, 'sshd', FOLD % (GUI_FAIL[:20], 4)))
check('logins: a fold of another message, or of another program, counts nothing', sent_by(alerts.collect_logins), [])

# IPS
alerts.EVE_LOG = os.path.join(TOP, 'eve.json')


def eve(signature, src='203.0.113.40', dst='192.0.2.10', severity=1, action='allowed', sid=2000001):
    return json.dumps({'timestamp': stamp(CLOCK + 30).replace('+00:00', '+0000'), 'event_type': 'alert', 'src_ip': src,
                       'dest_ip': dst, 'alert': {'action': action, 'signature': signature, 'signature_id': sid,
                                                 'severity': severity}}) + '\n'


reset()
append(alerts.EVE_LOG, eve('ET EXAMPLE old') * 3)
check('IPS: the first run sends nothing', sent_by(alerts.collect_ips), [])
append(alerts.EVE_LOG, eve('ET EXAMPLE probe', dst='192.0.2.10') + eve('ET EXAMPLE probe', dst='192.0.2.11', action='blocked') +
       eve('ET EXAMPLE probe', dst='192.0.2.10') + eve('ET EXAMPLE low', severity=3, sid=3) +
       eve('ET EXAMPLE medium', severity=2, sid=2) + json.dumps({'event_type': 'flow'}) + '\n')
sent = sent_by(alerts.collect_ips)
check('IPS: one alert per signature and source, high only by default', [s['facts']['signature'] for s in sent],
      ['ET EXAMPLE probe'])
check('IPS: count, action, source and destinations', (sent[0]['facts']['count'], sent[0]['facts']['actions'],
                                                      sent[0]['facts']['src'], sent[0]['facts']['dst']),
      (3, ['blocked', 'allowed'], '203.0.113.40', ['192.0.2.10', '192.0.2.11']))
check('IPS: the text', sent[0]['text'], '“ET EXAMPLE probe” (severity 1) from 203.0.113.40 to 192.0.2.10, 192.0.2.11: '
      '3 times, first at %s. Action: blocked, allowed (alert only).' % alerts.local_time(CLOCK - 30))
append(alerts.EVE_LOG, eve('ET EXAMPLE probe'))
check('IPS: the same pair is quiet for 30 minutes', sent_by(alerts.collect_ips), [])
append(alerts.EVE_LOG, eve('ET EXAMPLE probe', src='203.0.113.41'))
check('IPS: another source is another alert', [s['facts']['src'] for s in sent_by(alerts.collect_ips)], ['203.0.113.41'])
GENERAL['ips_severity'] = '2'
append(alerts.EVE_LOG, eve('ET EXAMPLE medium', severity=2, sid=2))
check('IPS: severity 2 adds medium', [s['facts']['severity'] for s in sent_by(alerts.collect_ips)], [2])
GENERAL['ips_severity'] = '1'
os.replace(alerts.EVE_LOG, alerts.EVE_LOG + '.0')
append(alerts.EVE_LOG, eve('ET EXAMPLE after rotation', sid=7))
check('IPS: a rotated eve.json is read from its start', [s['facts']['signature'] for s in sent_by(alerts.collect_ips)],
      ['ET EXAMPLE after rotation'])

# VPN
ANSWERS = {}
alerts.configctl = lambda *args: ANSWERS.get(args[0])
EXTRA['xml'] = ('<Swanctl><Connections><Connection uuid="00000000-0000-4000-8000-000000000001"><description>Office'
                '</description></Connection></Connections></Swanctl><wireguard><client><clients><client uuid="x">'
                '<name>Laptop</name><pubkey>EXAMPLEPUBKEY=</pubkey></client></clients></client></wireguard>')


def ike(state='ESTABLISHED', child='INSTALLED'):
    """one IKE SA as list_status.py puts it under a connection's "sas" (strongSwan's list-sas)"""
    return [{'uniqueid': '1', 'version': '2', 'state': state, 'remote-host': '198.51.100.1',
             'child-sas': {'example-1': {'name': 'example', 'state': child, 'mode': 'TUNNEL'}} if child else {}}]


def vpn(office=True, branch=False, handshake=10, alice=True, ipsec=True):
    def sas(value):
        return ike() if value is True else [] if value is False else value

    ANSWERS['ipsec'] = {'00000000-0000-4000-8000-000000000001': {'remote-addrs': '198.51.100.1', 'sas': sas(office)},
                        '00000000-0000-4000-8000-000000000002': {'remote-addrs': '198.51.100.2', 'sas': sas(branch)}
                        } if ipsec else None
    ANSWERS['wireguard'] = {'status': 'ok', 'records': [
        {'if': 'wg0', 'type': 'interface', 'public-key': 'SERVERKEY='},
        {'if': 'wg0', 'type': 'peer', 'public-key': 'EXAMPLEPUBKEY=', 'latest-handshake': int(CLOCK + 60 - handshake)}]}
    ANSWERS['openvpn'] = {'server': {'srv1': {'status': 'ok', 'client_list': [{'common_name': 'alice'}] if alice else []}}}


reset()
vpn()
check('VPN: the first run sends nothing', sent_by(alerts.collect_vpn), [])
check('VPN: a connection never up is not reported down', sent_by(alerts.collect_vpn, 3), [])
vpn(office=False)
sent = sent_by(alerts.collect_vpn, 2)
check('VPN: IPsec down on two reads, by its description', [s['subject'] for s in sent],
      ['VPN IPsec Office is down — Example network'])
vpn(office=False, ipsec=False)
check('VPN: a command that fails is unknown, not down or back', sent_by(alerts.collect_vpn, 2), [])
vpn()
sent = sent_by(alerts.collect_vpn, 2)
check('VPN: back, with how long it was down', [s['text'] for s in sent], ['VPN connection IPsec Office came back at %s, '
                                                                       'after 4 min down.' % alerts.local_time(CLOCK - 60)])
vpn(handshake=400)
check('VPN: a WireGuard peer with an old handshake is down', [s['facts']['connection'] for s in sent_by(alerts.collect_vpn, 2)],
      ['WireGuard Laptop'])
vpn(alice=False)
sent = sent_by(alerts.collect_vpn, 2)
check('VPN: an OpenVPN client gone from its server is down; the peer is back',
      sorted((s['facts']['connection'], s['facts']['state']) for s in sent),
      [('OpenVPN srv1: alice', 'down'), ('WireGuard Laptop', 'back')])
vpn()
check('VPN: and back when it returns', [s['facts']['state'] for s in sent_by(alerts.collect_vpn, 2)], ['back'])
vpn(branch=ike('CONNECTING', child=None))
check('VPN: an IKE session still connecting is not up', sent_by(alerts.collect_vpn, 3), [])
vpn(branch=[])
check('VPN: ... so when strongSwan gives up, a tunnel never up is not reported down', sent_by(alerts.collect_vpn, 3), [])
vpn(branch=ike(child='INSTALLING'))
sent_by(alerts.collect_vpn, 3)
check('VPN: established without an installed child SA is not up either', alerts.State().get('vpn')[
    'ipsec|00000000-0000-4000-8000-000000000002']['seen_up'], False)
vpn(branch=ike())
sent_by(alerts.collect_vpn, 2)
vpn(branch=ike('CONNECTING', child=None))
check('VPN: up is ESTABLISHED with an INSTALLED child SA; then connecting again is down',
      [(s['facts']['connection'], s['facts']['state']) for s in sent_by(alerts.collect_vpn, 2)],
      [('IPsec 198.51.100.2', 'down')])
vpn()
sent_by(alerts.collect_vpn, 2)
EXTRA['xml'] = ''

# watchdog
alerts.RESET_REASON = os.path.join(TOP, 'reset-reason.json')
reset()


def reset_record(boot, bits=(), watchdog=None):
    record = {'boot': boot, 'read_at': stamp(CLOCK), 'value': '0x02000000', 'cleared': True, 'after': 0,
              'read_by': 'os-watchdog', 'bits': [{'bit': b, 'reason': r} for b, r in bits]}
    if watchdog is not None:
        record['watchdog'] = watchdog
    alerts.save_json(alerts.RESET_REASON, record)


WD = (25, 'the hardware watchdog expired')
reset_record('boot-1', [WD])
check('watchdog: the first run only records the boot', sent_by(alerts.collect_watchdog), [])
os.replace(alerts.RESET_REASON, alerts.RESET_REASON + '.away')
check('watchdog: no record, nothing', sent_by(alerts.collect_watchdog), [])
reset_record('boot-2', [WD, (3, 'example reason')])
sent = sent_by(alerts.collect_watchdog, 2)
check('watchdog: a reset by the watchdog: one alert per boot', [s['facts']['reasons'] for s in sent],
      [['the hardware watchdog expired', 'example reason']])
reset_record('boot-3', [], watchdog=True)
check('watchdog: "watchdog": true is enough', [s['facts']['boot'] for s in sent_by(alerts.collect_watchdog)], ['boot-3'])
reset_record('boot-4', [(3, 'example reason')])
check('watchdog: another reset is not an alert', sent_by(alerts.collect_watchdog), [])

# ---------------------------------------------------------------- 4. command-and-control lists

alerts.FILTER_LOG = os.path.join(TOP, 'filter_{day}.log')
alerts.RULES_DEBUG = os.path.join(TOP, 'rules.debug')
alerts.FEEDS_FILE = os.path.join(TOP, 'feeds.json')
nr.INFECTED_FILE = os.path.join(STATE, 'infected.json')
REAL_LOCAL_NETWORKS = nr.local_networks
nr.local_networks = lambda: [ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('2001:db8:1::/64')]
alerts.own_addresses = lambda: {'192.0.2.1'}
RID = {'feodo out': 'a' * 32, 'feodo in': 'b' * 32, 'spamhaus_drop out': 'c' * 32, 'et_compromised out': 'd' * 32}


def rules(rid=RID):
    with open(alerts.RULES_DEBUG, 'w', encoding='utf-8') as fh:
        fh.write('# example ruleset\npass in quick on em1 inet from any to any label "%s" # Default allow LAN\n' % ('e' * 32))
        for what, label in rid.items():
            feed, way = what.split()
            fh.write('block drop %s log quick inet from any to <blocklists_%s> label "%s" # Block Lists: blocklists_%s %s\n'
                     % (way, feed, label, feed, way))


def blocked(src, dst='198.51.100.66', rule='feodo out', n=1, action='block', rid=None):
    label = rid or RID[rule]
    line = syslog_line(CLOCK + 30, 'filterlog', '85,,,%s,igb0,match,%s,out,4,0x0,,63,0,0,DF,6,tcp,60,%s,%s,51515,443,0,S,'
                       '1,,64240,,mss' % (label, action, src, dst))
    append(alerts.day_file(alerts.FILTER_LOG, CLOCK + 60), line * n)


rules()
nr.save_json(nr.DEVICES_FILE, {'02:00:00:00:00:02': {'ip': '192.0.2.50', 'name': 'laptop', 'first_seen': NOW, 'last_seen': NOW}})
reset()
blocked('192.0.2.50', n=2)
check('C2: the first run sends nothing', sent_by(alerts.collect_c2), [])
check('C2: and writes no infected.json', os.path.exists(nr.INFECTED_FILE), False)
blocked('192.0.2.50', n=3)
blocked('192.0.2.1')                                    # the firewall's own address names no device
blocked('203.0.113.7')                                  # not one of the firewall's networks
blocked('192.0.2.60', rule='feodo in')                  # the inbound rule
blocked('192.0.2.61', rule='spamhaus_drop out')         # a list that is not command-and-control
blocked('192.0.2.62', action='pass')
blocked('192.0.2.63', rid='f' * 32)                     # a rule this ruleset does not know
sent = sent_by(alerts.collect_c2)
check('C2: a device of the local network on a C2 list: one alert at once', [s['facts']['address'] for s in sent], ['192.0.2.50'])
check('C2: its name, MAC, list and destination', sent[0]['text'] if sent else None,
      'laptop (192.0.2.50) (MAC 02:00:00:00:00:02) tried to connect to 198.51.100.66, an address on feodo, at %s. The '
      'firewall blocked it. The device may be infected: check it.' % alerts.local_time(CLOCK - 30))
infected = nr.load_json(nr.INFECTED_FILE, {})
check('C2: infected.json, as its docstring says', (sorted(infected), sorted(infected['192.0.2.50']),
                                                   infected['192.0.2.50']['count'], infected['192.0.2.50']['mac']),
      (['192.0.2.50'], ['count', 'first', 'last', 'list', 'mac', 'name'], 3, '02:00:00:00:00:02'))
blocked('192.0.2.50', n=2)
check('C2: the same device again: counted, no second alert', (sent_by(alerts.collect_c2),
                                                              nr.load_json(nr.INFECTED_FILE, {})['192.0.2.50']['count']), ([], 5))
alerts.save_json(alerts.FEEDS_FILE, {'feodo': {'name': 'abuse.ch Feodo Tracker', 'c2': False},
                                     'et_compromised': {'name': 'Example C2 list', 'c2': True}})
blocked('192.0.2.70')
blocked('192.0.2.71', rule='et_compromised out')
check('C2: feeds.json marking "c2" decides the lists, by their names', [(s['facts']['address'], s['facts']['list_name'])
                                                                     for s in sent_by(alerts.collect_c2)],
      [('192.0.2.71', 'Example C2 list')])
os.unlink(alerts.FEEDS_FILE)
rules(dict(RID, **{'feodo out': '1' * 32}))
os.utime(alerts.RULES_DEBUG, (time.time() + 5, time.time() + 5))
blocked('192.0.2.72', rid='1' * 32)
check('C2: a changed ruleset is read again', [s['facts']['address'] for s in sent_by(alerts.collect_c2)], ['192.0.2.72'])
check('C2: the report lists the infected devices', [x in nr.infected_table(nr.texts('en_US'), {}) for x in
                                                    ('Infected devices', 'laptop (192.0.2.50)', '02:00:00:00:00:02')],
      [True, True, True])
infected = nr.load_json(nr.INFECTED_FILE, {})
infected['192.0.2.50']['last'] = int(CLOCK - 8 * 86400)
alerts.save_json(nr.INFECTED_FILE, infected)
minute(alerts.collect_c2)
check('C2: an entry older than 7 days is dropped', sorted(nr.load_json(nr.INFECTED_FILE, {})), ['192.0.2.71', '192.0.2.72'])
alerts.save_json(nr.INFECTED_FILE, {})
check('C2: no infected device, no table', nr.infected_table(nr.texts('en_US'), {}), '')
GENERAL['c2_alert'] = '0'
blocked('192.0.2.80', rid='1' * 32)
check('C2: with c2_alert off, no alert, but the device is listed', (sent_by(alerts.collect_c2),
                                                                    sorted(nr.load_json(nr.INFECTED_FILE, {}))),
      ([], ['192.0.2.80']))
GENERAL['c2_alert'] = '1'

# behind outbound NAT pf matches the "out" rule after NAT; os-blocklists' "from inside" rule sees the device
INSIDE = '2' * 32
with open(alerts.RULES_DEBUG, 'a', encoding='utf-8') as fh:
    for family in ('inet', 'inet6'):
        fh.write('block in log quick %s from any to <blocklists_feodo> label "%s" # Block Lists: blocklists_feodo from inside\n'
                 % (family, INSIDE))
os.utime(alerts.RULES_DEBUG, (time.time() + 10, time.time() + 10))
blocked('192.0.2.90', rid=INSIDE)
append(alerts.day_file(alerts.FILTER_LOG, CLOCK + 60), syslog_line(
    CLOCK + 30, 'filterlog', '86,,,%s,igb1,match,block,in,6,0x00,0x00000,64,tcp,6,80,2001:db8:1::50,2001:db8:ff::66,'
    '51515,443,0,S,1,,64800,,mss' % INSIDE))
check('C2: the "from inside" rule names the device, IPv4 and IPv6',
      sorted(s['facts']['address'] for s in sent_by(alerts.collect_c2)), ['192.0.2.90', '2001:db8:1::50'])
blocked('192.0.2.91', rule='feodo in')
check('C2: ... the inbound rule still does not', sent_by(alerts.collect_c2), [])

IFCONFIG = ('em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n'
            '\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255\n'
            '\tinet6 fe80::1%em1 prefixlen 64 scopeid 0x2\n'
            '\tinet6 2001:db8:1::1 prefixlen 64\n'
            'lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384\n'
            '\tinet6 ::1 prefixlen 128\n'
            '\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x5\n'
            '\tinet 127.0.0.1 netmask 0xff000000\n')
saved_run = nr.run
nr.run = lambda cmd, *args, **kwargs: IFCONFIG
check('local_networks(): IPv4 and IPv6 prefixes, never fe80::/10 or ::1', [str(n) for n in REAL_LOCAL_NETWORKS()],
      ['192.0.2.0/24', '2001:db8:1::/64', '127.0.0.0/8'])
nr.run = saved_run

# ---------------------------------------------------------------- 5. what other XGS plugins leave

alerts.XGS_OUTBOX = os.path.join(TOP, 'xgs', 'alerts')
alerts.XGS_ANOMALY = os.path.join(TOP, 'xgs', 'anomaly', 'alerts.jsonl')
reset()
check('XGS: neither directory: nothing, and no error', sent_by(alerts.collect_xgs), [])
state = alerts.State()                  # the anomaly file's first run is the one that finds it
del state.data['xgs']
state.save()


def outbox(name, **item):
    record = {'source': 'os-xgs-npu', 'kind': 'npu_fault', 'at': stamp(CLOCK), 'subject': 'Example NPU fault',
              'text': 'The example NPU stopped answering.', 'facts': {'port': 'example0'}}
    record.update(item)
    alerts.save_json(os.path.join(alerts.XGS_OUTBOX, name), record)


def anomaly(*ids):
    os.makedirs(os.path.dirname(alerts.XGS_ANOMALY), exist_ok=True)
    with open(alerts.XGS_ANOMALY, 'w', encoding='utf-8', newline='\n') as fh:
        for i in ids:
            fh.write(json.dumps({'id': i, 'at': stamp(CLOCK), 'host': 'fw.example.com', 'kind': 'traffic spike',
                                 'message': 'Example message %d.' % i, 'source': 'os-xgs-npu'}) + '\n')


outbox('0001.json')
anomaly(1, 2, 3)
sent = sent_by(alerts.collect_xgs)
check('XGS: an alert file left for this plugin is sent, as it is', [(s['kind'], s['subject'], s['facts']) for s in sent],
      [('npu_fault', 'Example NPU fault', {'port': 'example0', 'source': 'os-xgs-npu'})])
check('XGS: and removed once sent', os.listdir(alerts.XGS_OUTBOX), [])
check('XGS: the anomaly file\'s first run only records its last id', nr.load_json(alerts.STATE_FILE, {})['xgs']['last_id'], 3)
anomaly(1, 2, 3, 4)
sent = sent_by(alerts.collect_xgs)
check('XGS: an anomaly above the last id is sent', [(s['subject'], s['text']) for s in sent],
      [('Unusual traffic from fw.example.com — Example network', 'os-xgs-npu reported at %s: Example message 4.'
        % alerts.local_time(CLOCK - 60))])
check('XGS: the anomaly\'s kind is in its facts, not its subject', sent[0]['facts']['kind'], 'traffic spike')
anomaly(1, 2, 3, 4, 5, 6)
check('XGS: each new one once', [s['facts']['id'] for s in sent_by(alerts.collect_xgs, 2)], [5, 6])
anomaly(1, 2)
check('XGS: ids below the kept one: the file was started again, read from 0', [s['facts']['id'] for s in sent_by(alerts.collect_xgs)],
      [1, 2])

GENERAL.update(alert_webhook_url=BASE + '/fail', alert_ntfy_server='')
reset()
MAIL['fail'] = 'example mail failure'
outbox('0002.json')
minute(alerts.collect_xgs)
check('XGS: every channel failed: the file is kept', os.listdir(alerts.XGS_OUTBOX), ['0002.json'])
minute(alerts.collect_xgs)
check('XGS: and tried again the next minute', len(posts('/fail')), 2)
os.utime(os.path.join(alerts.XGS_OUTBOX, '0002.json'), (CLOCK - 25 * 3600, CLOCK - 25 * 3600))
minute(alerts.collect_xgs)
check('XGS: after 24 hours it is removed, with a line in the history', (os.listdir(alerts.XGS_OUTBOX), history()[0]['detail']),
      ([], '%s/0002.json dropped: not sent within 24 hours' % alerts.XGS_OUTBOX))
GENERAL.update(alert_webhook_url=BASE + '/hook', alert_ntfy_server=BASE + '/ntfy/')
reset()
GENERAL['xgs_alert'] = '0'
anomaly(1, 2, 3)
outbox('0003.json')
check('XGS: with xgs_alert off, nothing is sent', sent_by(alerts.collect_xgs), [])
check('XGS: ... the file waits, and the anomaly id moves on', (os.listdir(alerts.XGS_OUTBOX),
                                                                nr.load_json(alerts.STATE_FILE, {})['xgs']['last_id']),
      (['0003.json'], 3))
GENERAL['xgs_alert'] = '1'
check('XGS: on again, the waiting file goes', ([s['kind'] for s in sent_by(alerts.collect_xgs)], os.listdir(alerts.XGS_OUTBOX)),
      (['npu_fault'], []))

# One collector failing stops neither the others nor the reports: the scheduler with a collector that
# raises before one that records.
RAN = []


def broken(settings, state, now):
    raise RuntimeError('example failure')


saved = alerts.COLLECTORS
alerts.COLLECTORS = [('broken', broken), ('works', lambda settings, state, now: RAN.append(now))]
nr.update_devices = lambda settings: ({}, [], {})
del LOGGED[:]
config()
nr.scheduler()
alerts.COLLECTORS = saved
check('a collector that fails does not stop the next one', len(RAN), 1)
check('... and is logged', LOGGED[:1], ['alert collector broken failed: example failure'])
check('... and the reports still ran (their state written)', os.path.exists(nr.STATE_FILE), True)

# ---------------------------------------------------------------- end

SERVER.shutdown()
shutil.rmtree(TOP, ignore_errors=True)
print('%d checks, %d failure(s)' % (checks, failures))
sys.exit(1 if failures else 0)
