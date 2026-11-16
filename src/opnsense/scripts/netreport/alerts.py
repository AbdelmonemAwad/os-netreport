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

The alert layer of the network report: every alert the plugin sends goes through notify(), which
hands it to each channel that is set - mail (the report's own mail settings and recipients), a
webhook (a JSON POST) and ntfy - and writes the try, with the result per channel, to the history.

  alerts.py test      send one test alert to every channel that is set; prints
                      {"mail": ..., "webhook": ..., "ntfy": ...}, each "sent", "not set" or the error

An alert is a kind, a key, a time, a subject, a plain text, an optional HTML body and a few facts.
The same kind and key are not sent again within the kind's quiet time (30 minutes unless QUIET
says otherwise), so a condition that holds is one alert and not one a minute. What the layer
remembers between runs - the quiet times, and each collector's place - is in
/var/db/netreport/alerts-state.json, one key per collector, written atomically.

A channel that fails does not stop the others. ntfy has no default server: it is off until a
server and a topic are set, because a public server by default would send the firewall's events
out by itself.
"""

import datetime
import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

import netreport as nr

STATE_FILE = os.path.join(nr.STATE_DIR, 'alerts-state.json')
QUIET_DEFAULT = 30 * 60
QUIET = {}                      # kind -> seconds, where a kind wants other than QUIET_DEFAULT
QUIET_KEEP = 2 * 86400          # how long a sent key is remembered at all
HTTP_TIMEOUT = 10
NOT_SET = 'not set'
SENT = 'sent'

# ntfy's priorities by name; https://docs.ntfy.sh/publish/#message-priority
PRIORITIES = ('min', 'low', 'default', 'high', 'urgent')


# ---------------------------------------------------------------- state

def save_json(path, data):
    """write JSON so that a reader sees the old file or the new one, never half of one"""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=1, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class State:
    """alerts-state.json: {"sent": {"<kind>|<key>": time}, "<collector>": {...}, ...}"""

    def __init__(self, path=None):
        self.path = path or STATE_FILE
        data = nr.load_json(self.path, {})
        self.data = data if isinstance(data, dict) else {}

    def first(self, name):
        """whether this collector has never run: its first run only records where things are"""
        return not isinstance(self.data.get(name), dict)

    def get(self, name):
        if not isinstance(self.data.get(name), dict):
            self.data[name] = {}
        return self.data[name]

    def save(self):
        sent = self.data.get('sent')
        if isinstance(sent, dict):
            cutoff = time.time() - QUIET_KEEP
            self.data['sent'] = {k: v for k, v in sent.items() if isinstance(v, (int, float)) and v >= cutoff}
        save_json(self.path, self.data)


# ---------------------------------------------------------------- helpers

def local_time(ts):
    """a time as the reports print it: the firewall's local time"""
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')


def iso_time(ts):
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec='seconds')


def duration(seconds, t):
    seconds = max(0, int(seconds))
    days, hours, minutes = seconds // 86400, (seconds % 86400) // 3600, (seconds % 3600) // 60
    if days:
        return t['days_hours'].format(d=days, h=hours)
    if hours:
        return t['dur_hm'].format(h=hours, m=minutes)
    return t['dur_min'].format(m=max(1, minutes))


def error_text(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f'HTTP {exc.code} {exc.reason}'.strip()
    if isinstance(exc, urllib.error.URLError):
        return str(exc.reason)
    if isinstance(exc, socket.timeout):
        return 'timed out'
    return str(exc) or exc.__class__.__name__


def wanted(settings, name):
    """whether one kind of alert is to be sent: the master switch and its own"""
    return settings.get('alerts') == '1' and settings.get(name) == '1'


def page_of(t, subject, text):
    """the HTML of an alert that brings none of its own: its lines, under its subject"""
    lines = ''.join(f'<p>{nr.esc(line)}</p>' for line in text.split('\n') if line.strip())
    return (f'<!DOCTYPE html><html dir="{t["dir"]}" lang="{t["lang"]}"><head><meta charset="utf-8">'
            f'<style>{nr.CSS}</style></head><body><div class="wrap"><div class="head"><h1>🔔 {nr.esc(subject)}</h1>'
            f'</div><div class="sec">{lines}</div></div></body></html>')


# ---------------------------------------------------------------- channels

def post(url, body, headers):
    if not url.lower().startswith(('https://', 'http://')):
        raise ValueError('the address must start with https:// or http://')
    request = urllib.request.Request(url, data=body, headers=headers, method='POST')
    # TLS is verified: the default context checks the certificate and the name
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        response.read(4096)
        return response.status


def header_line(value):
    """the one header line the user sets for the webhook, as (name, value)"""
    name, sep, rest = (value or '').partition(':')
    name = name.strip()
    if not sep or not name or any(c in value for c in '\r\n') or not all(c.isalnum() or c in '-_' for c in name):
        raise ValueError('the webhook header must be one line, Name: value')
    return name, rest.strip()


def header_text(value):
    """a header value: as it is in ASCII, else RFC 2047 encoded (ntfy decodes it)"""
    value = ' '.join(str(value).split())
    try:
        value.encode('ascii')
        return value
    except UnicodeEncodeError:
        return '=?UTF-8?B?' + b64encode(value.encode('utf-8')).decode('ascii') + '?='


def by_mail(settings, alert):
    if settings.get('alert_mail') != '1':
        return NOT_SET, []
    ms = nr.mail_settings(settings)
    rcpt = nr.recipients_for(settings, None, ms)
    t = nr.texts(settings.get('language'))
    nr.send_mail(ms, rcpt, alert['subject'], alert.get('html') or page_of(t, alert['subject'], alert['text']),
                 alert['text'])
    return SENT, rcpt


def by_webhook(settings, alert):
    url = settings.get('alert_webhook_url')
    if not url:
        return NOT_SET
    headers = {'Content-Type': 'application/json; charset=utf-8', 'User-Agent': 'os-netreport'}
    if settings.get('alert_webhook_header'):
        name, value = header_line(settings.get('alert_webhook_header'))
        headers[name] = value
    body = json.dumps({'source': 'os-netreport', 'host': settings.hostname(), 'kind': alert['kind'],
                       'at': iso_time(alert['at']), 'subject': alert['subject'], 'text': alert['text'],
                       'facts': alert.get('facts') or {}}, ensure_ascii=False).encode('utf-8')
    post(url, body, headers)
    return SENT


def by_ntfy(settings, alert):
    server, topic = settings.get('alert_ntfy_server'), settings.get('alert_ntfy_topic')
    if not server or not topic:
        return NOT_SET
    priority = alert.get('priority') if alert.get('priority') in PRIORITIES else 'default'
    headers = {'Title': header_text(alert['subject']), 'Priority': priority, 'User-Agent': 'os-netreport',
               'Content-Type': 'text/plain; charset=utf-8'}
    tags = [tag for tag in alert.get('tags') or () if tag]
    if tags:
        headers['Tags'] = header_text(','.join(tags))
    if settings.get('alert_ntfy_token'):
        headers['Authorization'] = 'Bearer ' + settings.get('alert_ntfy_token').strip()
    post(server.rstrip('/') + '/' + urllib.parse.quote(topic.strip(), safe=''), alert['text'].encode('utf-8'),
         headers)
    return SENT


def deliver(settings, alert):
    """hand one alert to every channel; returns {"mail": ..., "webhook": ..., "ntfy": ...}"""
    results, rcpt = {}, []
    try:
        results['mail'], rcpt = by_mail(settings, alert)
    except Exception as exc:
        results['mail'] = error_text(exc)
    for name, channel in (('webhook', by_webhook), ('ntfy', by_ntfy)):
        try:
            results[name] = channel(settings, alert)
        except Exception as exc:
            results[name] = error_text(exc)
    tried = [name for name, result in results.items() if result != NOT_SET]
    sent = [name for name, result in results.items() if result == SENT]
    recipients = list(rcpt) + [name for name in ('webhook', 'ntfy') if name in tried]
    if not tried:
        detail = 'no alert channel is set'
    else:
        detail = '; '.join(f'{name}: {result}' for name, result in results.items())
    nr.add_history({'schedule': alert['subject'], 'subject': alert['subject'], 'recipients': ', '.join(recipients),
                    'archive': '', 'status': 'alert' if sent else 'failed', 'detail': detail})
    if not sent:
        nr.log(f'alert "{alert["subject"]}" was not sent: {detail}')
    return results


def notify(settings, state, kind, key, subject, text, facts=None, page=None, at=None, now=None,
           quiet=None, priority='default', tags=()):
    """Send one alert, unless the same kind and key went out within its quiet time.

    Returns the result per channel, or None when the quiet time held it back. The time of the try is
    remembered whatever the channels answered, so that a channel that is down is tried again after
    the quiet time and not every minute.
    """
    now = time.time() if now is None else now
    quiet = QUIET.get(kind, QUIET_DEFAULT) if quiet is None else quiet
    mark = f'{kind}|{key}'
    sent = state.get('sent') if state is not None else {}
    last = sent.get(mark)
    if quiet and isinstance(last, (int, float)) and now - last < quiet:
        return None
    alert = {'kind': kind, 'key': str(key), 'at': now if at is None else at, 'subject': subject, 'text': text,
             'html': page, 'facts': facts or {}, 'priority': priority, 'tags': list(tags)}
    results = deliver(settings, alert)
    if state is not None:
        sent[mark] = now
        state.save()
    return results


def subject_of(t, settings, key, **values):
    return t[key].format(title=settings.get('title') or 'OPNsense', **values)


# ---------------------------------------------------------------- collectors

# (name, function(settings, state, now)): run each minute by netreport.py's scheduler, each on its
# own, so that one failing stops neither the others nor the reports
COLLECTORS = []


# ---------------------------------------------------------------- commands

def test_alert(settings):
    t = nr.texts(settings.get('language'))
    host = settings.hostname()
    alert = {'kind': 'test', 'key': 'test', 'at': time.time(), 'subject': subject_of(t, settings, 'test_alert_subject'),
             'text': t['test_alert_text'].format(host=host), 'html': None, 'facts': {'test': True},
             'priority': 'default', 'tags': ['white_check_mark']}
    return deliver(settings, alert)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    os.makedirs(nr.STATE_DIR, exist_ok=True)
    if cmd == 'test':
        try:
            results = test_alert(nr.Settings())
        except Exception as exc:
            results = {'mail': error_text(exc), 'webhook': error_text(exc), 'ntfy': error_text(exc)}
        print(json.dumps(results, ensure_ascii=False))
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
