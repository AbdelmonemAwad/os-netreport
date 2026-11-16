#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""alerts.py, the alert layer, and the collectors that feed it, without a firewall: the logs, the files
other plugins leave and the state are in a temporary directory, configctl and the gateway status are
stand-ins, and the webhook and ntfy are a small HTTP server on 127.0.0.1. Mail is a stand-in too: what
would have gone out is kept and compared.

    python3 tools/test-alerts.py"""
import base64
import importlib
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
                 '</system><OPNsense><NetReport><general>%s</general><schedules/></NetReport></OPNsense>'
                 '<interfaces><lan><if>em1</if><ipaddr>192.0.2.1</ipaddr><subnet>24</subnet></lan></interfaces>'
                 '</opnsense>' % fields)
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

# ---------------------------------------------------------------- end

SERVER.shutdown()
shutil.rmtree(TOP, ignore_errors=True)
print('%d checks, %d failure(s)' % (checks, failures))
sys.exit(1 if failures else 0)
