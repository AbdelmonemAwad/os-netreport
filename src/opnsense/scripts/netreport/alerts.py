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

The collectors, run each minute by netreport.py's scheduler: gateways down and back, repeated
failed logins, Suricata alerts, VPN tunnels down and back, a reset the hardware watchdog caused,
a device reaching a command-and-control list, and the alerts other XGS plugins leave for this one.
Each one's first run only records where things are, so an install does not alert on old history.

/var/db/netreport/infected.json - written here, read by os-portguard to isolate a device:

    {"<address>": {"first": <unix time>, "last": <unix time>, "count": <blocked connections>,
                   "list": "<os-blocklists feed id>", "mac": "<mac or empty>", "name": "<name or empty>"}}

    one entry per address of the firewall's own networks (never one of the firewall's own addresses)
    that os-blocklists blocked on its way to a command-and-control list; "first" and "last" are
    the times of the first and the latest blocked connection, and an entry whose "last" is older
    than 7 days is dropped. Written whole (a temporary file renamed over it).

Taken from os-xgs-npu, when it is installed (neither existing is normal):

    /var/db/os-xgs-npu/alerts/*.json - one alert a file, {"source", "kind", "at", "subject", "text",
    "facts"}: sent, then removed; kept while every channel fails and tried again the next minute,
    and removed with a line in the history after 24 hours.

    /var/db/os-xgs-npu/anomaly/alerts.jsonl - one {"id", "at", "host", "kind", "message", "source"} a
    line, "id" counting up from 1 and never reused: what is above the last id sent is sent; ids all
    below it mean the file was started again, and it is read from 0.
"""

import datetime
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from collections import Counter

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


# ---------------------------------------------------------------- up and down: gateways and tunnels

FLAP_WINDOW = 15 * 60           # a gateway that changes more than FLAP_CHANGES times in this is flapping,
FLAP_CHANGES = 3                # and says nothing more until it has held one state this long


def track(entries, key, read, now, flapping=False):
    """Follow one thing that is 'up' or 'down', read once a minute; returns what to say, or None.

    A new state counts once it has held on two reads in a row, so that one bad minute is not an
    alert: ('down', first seen) or ('back', first seen, how long it was down). A thing is reported
    down only after it has been up since it was first followed, and back only when its down was
    reported. With flapping, more than FLAP_CHANGES changes within FLAP_WINDOW are ('flapping', n)
    instead, once, and then nothing until one state has held for FLAP_WINDOW: then ('steady', since)
    when it is up, or its down as above.
    """
    e = entries.get(key)
    if not isinstance(e, dict):
        entries[key] = {'state': read, 'since': now, 'last': read, 'changed': now, 'cand': None, 'cand_at': now,
                        'changes': [], 'flapping': False, 'seen_up': read == 'up', 'reported': False}
        return None
    if read != e.get('last'):
        e['changes'] = list(e.get('changes') or []) + [now]
        e['changed'] = now
        e['last'] = read
    e['changes'] = [c for c in e.get('changes') or [] if now - c < FLAP_WINDOW]
    if e.get('flapping'):
        if now - e.get('changed', now) < FLAP_WINDOW:
            return None
        e.update(flapping=False, state=read, since=e['changed'], cand=None)
        if read == 'up':
            e.update(seen_up=True, reported=False)
            return ('steady', e['changed'])
        e['reported'] = bool(e.get('seen_up'))
        return ('down', e['changed']) if e['reported'] else None
    if flapping and len(e['changes']) > FLAP_CHANGES:
        e.update(flapping=True, cand=None)
        return ('flapping', len(e['changes']))
    if read == e.get('state'):
        e['cand'] = None
        return None
    if e.get('cand') != read:
        e.update(cand=read, cand_at=now)
        return None
    first, down_since = e.get('cand_at', now), e.get('since', now)
    e.update(state=read, since=first, cand=None)
    if read == 'down':
        if not e.get('seen_up'):
            return None
        e['reported'] = True
        return ('down', first)
    e['seen_up'] = True
    if not e.get('reported'):
        return None
    e['reported'] = False
    return ('back', first, first - down_since)


def gateway_reads():
    """{gateway: 'up' or 'down'} as dpinger reports it (System: Gateways); a gateway whose monitoring is
    off - "none" with no delay measured - or that is forced down is left out"""
    reads = {}
    for g in nr.gateway_status():
        name, status = g.get('name'), str(g.get('status', '')).lower()
        if not name:
            continue
        if status == 'down':
            reads[name] = 'down'
        elif status in ('none', 'online', 'delay', 'loss', 'delay+loss') and g.get('delay') not in ('~', '', None):
            reads[name] = 'up'
    return reads


def collect_gateways(settings, state, now):
    first = state.first('gateway')
    entries = state.get('gateway')
    reads = gateway_reads()
    if reads:
        for gone in [name for name in entries if name not in reads]:
            del entries[gone]
    send = wanted(settings, 'gateway_alert') and not first
    t = nr.texts(settings.get('language'))
    for name, read in sorted(reads.items()):
        said = track(entries, name, read, now, flapping=True)
        if not said or not send:
            continue
        facts = {'gateway': name, 'state': said[0]}
        if said[0] == 'down':
            facts['since'] = iso_time(said[1])
            notify(settings, state, 'gateway', f'{name}|down|{int(said[1])}', subject_of(t, settings, 'gw_down_subject', name=name),
                   t['gw_down_text'].format(name=name, time=local_time(said[1])), facts, now=now, priority='high',
                   tags=['warning'])
        elif said[0] == 'back':
            facts.update(at=iso_time(said[1]), down_seconds=int(said[2]))
            notify(settings, state, 'gateway', f'{name}|back|{int(said[1])}', subject_of(t, settings, 'gw_back_subject', name=name),
                   t['gw_back_text'].format(name=name, time=local_time(said[1]), duration=duration(said[2], t)), facts,
                   now=now, tags=['white_check_mark'])
        elif said[0] == 'flapping':
            facts['changes'] = said[1]
            notify(settings, state, 'gateway', f'{name}|flapping|{int(now)}', subject_of(t, settings, 'gw_flap_subject', name=name),
                   t['gw_flap_text'].format(name=name, n=said[1]), facts, now=now, priority='high', tags=['warning'])
        elif said[0] == 'steady':
            facts['since'] = iso_time(said[1])
            notify(settings, state, 'gateway', f'{name}|steady|{int(said[1])}', subject_of(t, settings, 'gw_steady_subject', name=name),
                   t['gw_steady_text'].format(name=name, time=local_time(said[1])), facts, now=now,
                   tags=['white_check_mark'])


# ---------------------------------------------------------------- logs followed by their place

AUDIT_LOG = '/var/log/audit/audit_{day}.log'
EVE_LOG = '/var/log/suricata/eve.json'
MAX_READ = 32 * 1024 * 1024     # a log grown more than this in a minute is read from its last part


def day_file(pattern, now):
    return pattern.format(day=datetime.datetime.fromtimestamp(now).strftime('%Y%m%d'))


def read_from(place, path):
    """the complete lines of path written since place = {"inode", "offset"}, which moves past them;
    a new inode (the file was rotated) or a shorter file starts again at 0"""
    try:
        info = os.stat(path)
    except OSError:
        return []
    offset = place.get('offset', 0) if isinstance(place.get('offset'), int) else 0
    if place.get('inode') != info.st_ino or info.st_size < offset:
        place['inode'], offset = info.st_ino, 0
    partial = info.st_size - offset > MAX_READ
    if partial:
        offset = info.st_size - MAX_READ
    with open(path, 'rb') as fh:
        fh.seek(offset)
        data = fh.read(info.st_size - offset)
    end = data.rfind(b'\n')
    if end < 0:
        place['offset'] = offset
        return []
    place['offset'] = offset + end + 1
    lines = data[:end].decode('utf-8', 'replace').split('\n')
    if partial:
        lines = lines[1:]           # the first line read from the middle is not a whole one
    return lines


def follow(place, path):
    """New lines of a log followed by name: on the first run only where it ends is recorded; when the
    name changes (a new day's file), the rest of the old file is read and the new one from 0."""
    if 'path' not in place:
        try:
            info = os.stat(path)
            place.update(path=path, inode=info.st_ino, offset=info.st_size)
        except OSError:
            place.update(path=path, inode=None, offset=0)
        return []
    lines = []
    if place['path'] != path:
        lines += read_from(place, place['path'])
        place.update(path=path, inode=None, offset=0)
    return lines + read_from(place, path)


def message_of(line):
    """the message of an RFC 5424 line (after "<pri>1 time host app procid msgid sd"), or the line"""
    parts = line.split(' ', 7)
    if len(parts) == 8 and parts[0].startswith('<') and parts[0].endswith('>1'):
        sd = parts[7]
        if sd.startswith('- '):
            return sd[2:]
        if sd.startswith('['):
            end = sd.find('] ')
            return sd[end + 2:] if end >= 0 else sd
        return sd
    return line


# ---------------------------------------------------------------- repeated failed logins

LOGIN_WINDOW = 10 * 60
LOGIN_QUIET = 30 * 60
QUIET['login'] = LOGIN_QUIET
IP = r'(?P<address>[0-9A-Fa-f:.]*[0-9A-Fa-f])'
LOGIN_PATTERNS = [
    # OPNsense 26.7, web GUI and API logins (level debug, program "audit")
    (re.compile(r'user (?P<user>\S+) failed authentication for (?P<service>.+?) on .+? via .+? at ' + IP), None),
    # sshd
    (re.compile(r'Failed \S+ for (?:invalid user )?(?P<user>\S*) from ' + IP + r' port (?P<port>\d+)'), 'ssh'),
    (re.compile(r'Invalid user (?P<user>\S*) from ' + IP + r' port (?P<port>\d+)'), 'ssh'),
    (re.compile(r'error: PAM: Authentication error for (?:illegal user )?(?P<user>\S*) from ' + IP), 'ssh'),
]
API_KEY = re.compile(r'authentication failed for api key (\S+)')


def an_address(text):
    for word in re.findall(r'[0-9A-Fa-f:.]{3,}', text):
        try:
            return str(ipaddress.ip_address(word.strip('.:')))
        except ValueError:
            continue
    return ''


def login_failure(line):
    """(address, user, service, port) of a failed login line, or None; an API key is never kept whole"""
    msg = message_of(line)
    found = API_KEY.search(msg)
    if found:
        key = found.group(1)
        return (an_address(msg[:found.start()] + ' ' + msg[found.end():]) or '?', 'api-key:' + key[:4], 'api', '')
    for pattern, service in LOGIN_PATTERNS:
        found = pattern.search(msg)
        if found:
            try:
                address = str(ipaddress.ip_address(found.group('address')))
            except ValueError:
                continue
            return (address, found.group('user'), service or found.group('service'),
                    found.groupdict().get('port') or '')
    return None


def collect_logins(settings, state, now):
    first = state.first('login')
    st = state.get('login')
    place = st.setdefault('log', {})
    lines = follow(place, day_file(AUDIT_LOG, now))
    fails = st.get('fails') if isinstance(st.get('fails'), dict) else {}
    for line in lines:
        failure = login_failure(line)
        if not failure:
            continue
        address, user, service, port = failure
        stamp = nr.line_time(line) or now
        seen = fails.setdefault(address, [])
        # sshd says "Invalid user" and then "Failed password for invalid user" of one try, and PAM may
        # add its own line: the same address, user and port, or no port within 2 seconds, is one try
        if service == 'ssh' and any(f[2] == 'ssh' and f[1] == user and
                                    ((port and f[3] == port) or (not (port and f[3]) and abs(f[0] - stamp) <= 2))
                                    for f in seen):
            continue
        seen.append([stamp, user, service, port])
    for address in list(fails):
        fails[address] = [f for f in fails[address] if now - f[0] < LOGIN_WINDOW]
        if not fails[address]:
            del fails[address]
    st['fails'] = fails
    if first or not wanted(settings, 'login_alert'):
        return
    limit = max(2, settings.num('login_fail_count') or 5)
    t = nr.texts(settings.get('language'))
    sep = t.get('list_sep', ', ')
    for address, seen in sorted(fails.items()):
        if len(seen) < limit:
            continue
        users = sorted({t['login_api_key'].format(key=f[1][8:]) if f[1].startswith('api-key:') else f[1] for f in seen})
        services = sorted({f[2] for f in seen})
        last = max(f[0] for f in seen)
        facts = {'address': address, 'count': len(seen), 'users': users, 'services': services, 'last': iso_time(last)}
        notify(settings, state, 'login', address, subject_of(t, settings, 'login_subject', address=address),
               t['login_text'].format(n=len(seen), address=address, time=local_time(last), services=sep.join(services),
                                      users=sep.join(users)), facts, now=now, priority='high', tags=['lock'])


# ---------------------------------------------------------------- intrusion prevention (Suricata)

QUIET['ips'] = 30 * 60


def collect_ips(settings, state, now):
    first = state.first('ips')
    st = state.get('ips')
    lines = follow(st.setdefault('log', {}), EVE_LOG)
    if first or not wanted(settings, 'ips_alert'):
        return
    worst = 2 if settings.get('ips_severity') == '2' else 1
    groups = {}
    for line in lines:
        if '"alert"' not in line:
            continue
        try:
            ev = json.loads(line)
            alert = ev['alert']
            severity = int(alert.get('severity', 3))
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        if ev.get('event_type') != 'alert' or severity > worst:
            continue
        signature = str(alert.get('signature') or alert.get('signature_id') or '?')
        source = str(ev.get('src_ip') or '?')
        g = groups.setdefault((str(alert.get('signature_id') or signature), source),
                              {'signature': signature, 'severity': severity, 'src': source, 'dst': Counter(),
                               'actions': set(), 'count': 0, 'first': None})
        g['count'] += 1
        g['dst'][str(ev.get('dest_ip') or '?')] += 1
        g['actions'].add('blocked' if alert.get('action') == 'blocked' else 'allowed')
        g['severity'] = min(g['severity'], severity)
        try:
            stamp = datetime.datetime.fromisoformat(re.sub(r'([+-]\d\d)(\d\d)$', r'\1:\2', ev['timestamp'])).timestamp()
        except (KeyError, ValueError, TypeError):
            stamp = now
        g['first'] = stamp if g['first'] is None else min(g['first'], stamp)
    t = nr.texts(settings.get('language'))
    sep = t.get('list_sep', ', ')
    for (sid, source), g in sorted(groups.items()):
        actions = [a for a in ('blocked', 'allowed') if a in g['actions']]
        dst = sep.join(d for d, _ in g['dst'].most_common(3))
        facts = {'signature': g['signature'], 'signature_id': sid, 'severity': g['severity'], 'src': source,
                 'dst': [d for d, _ in g['dst'].most_common(10)], 'count': g['count'], 'actions': actions,
                 'first': iso_time(g['first'])}
        notify(settings, state, 'ips', f'{sid}|{source}', subject_of(t, settings, 'ips_subject', signature=g['signature']),
               t['ips_text'].format(signature=g['signature'], severity=g['severity'], src=source, dst=dst, n=g['count'],
                                    time=local_time(g['first']), action=sep.join(t['ips_' + a] for a in actions)),
               facts, now=now, priority='high', tags=['rotating_light'])


# ---------------------------------------------------------------- VPN tunnels

CONFIGCTL = '/usr/local/sbin/configctl'
CONFIGCTL_TIMEOUT = 30
WG_HANDSHAKE = 180


def configctl(*args):
    """configd's answer as JSON, or None - a command that fails is unknown, never down"""
    try:
        out = subprocess.run([CONFIGCTL] + list(args), capture_output=True, text=True, timeout=CONFIGCTL_TIMEOUT)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None


def description(settings, uuid):
    """what config.xml calls the item with this uuid"""
    if not uuid:
        return ''
    for item in settings.root.iter():
        if item.get('uuid') == uuid:
            return (item.findtext('description') or item.findtext('descr') or item.findtext('name') or '').strip()
    return ''


def vpn_reads(settings, entries, now):
    """({key: (name, 'up' or 'down')} of every connection this read could see, the key prefixes of the
    sources that answered, and the prefixes to leave as they are - a server that did not answer)"""
    reads, answered, keep = {}, [], []
    ipsec = configctl('ipsec', 'list', 'status')
    if isinstance(ipsec, dict):
        answered.append('ipsec|')
        for cid, conn in ipsec.items():
            if isinstance(conn, dict):
                name = description(settings, cid) or str(conn.get('remote-addrs') or cid)
                reads[f'ipsec|{cid}'] = ('IPsec ' + name, 'up' if conn.get('sas') else 'down')
    wg = configctl('wireguard', 'show')
    if isinstance(wg, dict) and wg.get('status') == 'ok':
        answered.append('wg|')
        peers = {}
        for item in settings.root.iter('client'):
            if item.findtext('pubkey'):
                peers[item.findtext('pubkey').strip()] = (item.findtext('name') or '').strip()
        for rec in wg.get('records') or []:
            if not isinstance(rec, dict) or rec.get('type') != 'peer':
                continue
            key = str(rec.get('public-key') or '')
            handshake = rec.get('latest-handshake') or 0
            up = isinstance(handshake, int) and handshake > 0 and now - handshake < WG_HANDSHAKE
            reads[f'wg|{rec.get("if")}|{key}'] = ('WireGuard ' + (peers.get(key) or f'{rec.get("if")} {key[:8]}…'),
                                                 'up' if up else 'down')
    ovpn = configctl('openvpn', 'connections', 'client,server')
    if isinstance(ovpn, dict):
        answered.append('ovpn|')
        for iid, inst in (ovpn.get('client') or {}).items():
            if isinstance(inst, dict) and inst.get('status') != 'failed':
                name = description(settings, iid) or iid
                reads[f'ovpn|c|{iid}'] = ('OpenVPN ' + name, 'up' if inst.get('status') == 'connected' else 'down')
        for sid, srv in (ovpn.get('server') or {}).items():
            if not isinstance(srv, dict) or srv.get('status') == 'failed':
                keep.append(f'ovpn|s|{sid}|')
                continue
            name = description(settings, sid) or sid
            if 'client_list' not in srv and 'timestamp' in srv:
                # a peer-to-peer instance: its own state
                reads[f'ovpn|s|{sid}|'] = ('OpenVPN ' + name, 'up' if srv.get('status') == 'connected' else 'down')
                continue
            for client in srv.get('client_list') or []:
                cn = client.get('common_name') or client.get('username') or client.get('real_address') or '?'
                reads[f'ovpn|s|{sid}|{cn}'] = (f'OpenVPN {name}: {cn}', 'up')
            # a client that has left the server's list is down
            for key, entry in entries.items():
                if key.startswith(f'ovpn|s|{sid}|') and key != f'ovpn|s|{sid}|' and key not in reads:
                    reads[key] = (entry.get('name') or key, 'down')
    return reads, answered, keep


def collect_vpn(settings, state, now):
    first = state.first('vpn')
    entries = state.get('vpn')
    reads, answered, keep = vpn_reads(settings, entries, now)
    for key in list(entries):
        if key in reads or any(key.startswith(p) for p in keep):
            continue
        if any(key.startswith(p) for p in answered):
            del entries[key]            # gone from what answered: removed from the configuration
    send = wanted(settings, 'vpn_alert') and not first
    t = nr.texts(settings.get('language'))
    for key, (name, read) in sorted(reads.items()):
        said = track(entries, key, read, now)
        entries[key]['name'] = name
        if not said or not send:
            continue
        facts = {'connection': name, 'state': said[0]}
        if said[0] == 'down':
            facts['since'] = iso_time(said[1])
            notify(settings, state, 'vpn', f'{key}|down|{int(said[1])}', subject_of(t, settings, 'vpn_down_subject', name=name),
                   t['vpn_down_text'].format(name=name, time=local_time(said[1])), facts, now=now, priority='high',
                   tags=['warning'])
        elif said[0] == 'back':
            facts.update(at=iso_time(said[1]), down_seconds=int(said[2]))
            notify(settings, state, 'vpn', f'{key}|back|{int(said[1])}', subject_of(t, settings, 'vpn_back_subject', name=name),
                   t['vpn_back_text'].format(name=name, time=local_time(said[1]), duration=duration(said[2], t)), facts,
                   now=now, tags=['white_check_mark'])


# ---------------------------------------------------------------- a reset the hardware watchdog caused

RESET_REASON = '/var/db/os-watchdog/reset-reason.json'
WATCHDOG_BIT = 25               # AMD: "the hardware watchdog expired"


def collect_watchdog(settings, state, now):
    first = state.first('watchdog')
    st = state.get('watchdog')
    record = nr.load_json(RESET_REASON, None)
    if not isinstance(record, dict) or 'boot' not in record:
        return
    boot = str(record.get('boot'))
    if st.get('boot') == boot:
        return
    st['boot'] = boot
    bits = [b for b in record.get('bits') or [] if isinstance(b, dict)]
    by_watchdog = record.get('watchdog') is True or any(str(b.get('bit')) == str(WATCHDOG_BIT) for b in bits)
    if first or not by_watchdog or not wanted(settings, 'watchdog_alert'):
        return
    t = nr.texts(settings.get('language'))
    reasons = [str(b.get('reason') or b.get('bit')) for b in bits] or [t['unknown']]
    read_at = record.get('read_at')
    try:
        when = float(read_at) if isinstance(read_at, (int, float)) else \
            datetime.datetime.fromisoformat(str(read_at).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        when = now
    facts = {'boot': boot, 'reasons': reasons, 'value': record.get('value'), 'read_at': read_at}
    notify(settings, state, 'watchdog', boot, subject_of(t, settings, 'wd_subject'),
           t['wd_text'].format(time=local_time(when), reasons=t.get('list_sep', ', ').join(reasons)), facts, now=now,
           quiet=0, priority='high', tags=['warning'])


# ---------------------------------------------------------------- a device reaching a command-and-control list

FILTER_LOG = '/var/log/filter/filter_{day}.log'
RULES_DEBUG = '/tmp/rules.debug'
FEEDS_FILE = '/usr/local/opnsense/scripts/blocklists/feeds.json'
C2_FALLBACK = ('feodo',)        # until os-blocklists marks its feeds with "c2": abuse.ch Feodo Tracker
INFECTED_DAYS = 7
HEX_DIGITS = set('0123456789abcdef')
# filterlog's CSV, as OPNsense's own reader (scripts/filter/read_log.py) names its fields
FILTER_GENERAL = 'rulenr,subrulenr,anchorname,rid,interface,reason,action,dir,ipversion'.split(',')
FILTER_V4 = FILTER_GENERAL + 'tos,ecn,ttl,id,offset,ipflags,protonum,protoname,length,src,dst'.split(',')
FILTER_V6 = FILTER_GENERAL + 'class,flow,hoplimit,protoname,protonum,length,src,dst'.split(',')
BLOCKLIST_OUT = re.compile(r'^Block Lists: blocklists_(\S+) out$')
_rules = {'mtime': None, 'labels': {}}


def rule_labels():
    """rule label (its hash or uuid) -> description, from the running ruleset, the way OPNsense's
    read_log.py fetch_rule_details() reads it; read again when the file changes"""
    try:
        mtime = os.stat(RULES_DEBUG).st_mtime
    except OSError:
        return {}
    if _rules['mtime'] != mtime:
        labels = {}
        with open(RULES_DEBUG, 'rt', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                if ' label ' not in line:
                    continue
                lbl = line.split(' label ')[-1]
                if lbl.count('"') >= 2:
                    rid = lbl.split('"')[1]
                    if len(rid) >= 32 and set(rid.replace('-', '')).issubset(HEX_DIGITS):
                        labels[rid] = ''.join(lbl.split('"')[2:]).strip().strip('# : ')
        _rules.update(mtime=mtime, labels=labels)
    return _rules['labels']


def filter_record(line):
    """one filterlog line as a dict of its fields, and the last field (where an older format puts the rule)"""
    if 'filterlog' not in line:
        return None
    found = re.search(r'filterlog[^:]*:', line)
    if found and re.search(r'filterlog\[\d*\]:', line):
        parts = line[found.end():].strip().split(',')          # RFC 3164
    else:
        parts = line.split()[-1].strip().split(',')             # RFC 5424
    if len(parts) < len(FILTER_GENERAL):
        return None
    rec = dict(zip(FILTER_GENERAL, parts))
    fields = {'4': FILTER_V4, '6': FILTER_V6}.get(rec['ipversion'])
    if not fields:
        return None
    rec.update(zip(fields[len(FILTER_GENERAL):], parts[len(FILTER_GENERAL):len(fields)]))
    rec['_last'] = parts[-1]
    return rec


def rule_label(rec, labels):
    if rec.get('rid', '0') != '0':
        return labels.get(rec['rid'], '')
    last = rec.get('_last', '')
    if len(last) >= 32 and set(last.replace('-', '')).issubset(HEX_DIGITS):
        return labels.get(last, '')
    return ''


def c2_lists():
    """{feed id: its name} of the command-and-control lists: the feeds of os-blocklists' feeds.json marked
    "c2": true, or, while none carries that key, feodo"""
    feeds = nr.load_json(FEEDS_FILE, None)
    feeds = feeds if isinstance(feeds, dict) else {}
    if any(isinstance(f, dict) and 'c2' in f for f in feeds.values()):
        ids = [i for i, f in feeds.items() if isinstance(f, dict) and f.get('c2') is True]
    else:
        ids = list(C2_FALLBACK)
    return {i: str((feeds.get(i) or {}).get('name') or i) for i in ids}


def own_addresses():
    """the firewall's own addresses: a blocked connection from one of them names no device"""
    found = set()
    for word in re.findall(r'inet6? ([0-9A-Fa-f:.]+)', nr.run('/sbin/ifconfig -a')):
        try:
            found.add(str(ipaddress.ip_address(word)))
        except ValueError:
            continue
    return found


def device_of(settings, address):
    """(name, mac) of an address of the local network, as the device scan and the host names know it"""
    name = nr.hostnames(settings).get(address, '')
    mac, seen = '', -1
    devices = nr.load_json(nr.DEVICES_FILE, {})
    for m, d in (devices.items() if isinstance(devices, dict) else []):
        if isinstance(d, dict) and d.get('ip') == address and (d.get('last_seen') or 0) > seen:
            mac, seen = m, d.get('last_seen') or 0
            name = name or d.get('name') or ''
    return name, mac


def collect_c2(settings, state, now):
    first = state.first('c2')
    st = state.get('c2')
    lines = follow(st.setdefault('log', {}), day_file(FILTER_LOG, now))
    infected = nr.load_json(nr.INFECTED_FILE, {})
    infected = infected if isinstance(infected, dict) else {}
    kept = {a: e for a, e in infected.items() if isinstance(e, dict) and now - (e.get('last') or 0) < INFECTED_DAYS * 86400}
    changed = len(kept) != len(infected)
    infected = kept
    hits = {}
    lists = labels = nets = own = None
    for line in ([] if first else lines):
        if 'block' not in line:
            continue
        rec = filter_record(line)
        if not rec or rec.get('action') != 'block':
            continue
        if labels is None:
            labels, lists = rule_labels(), c2_lists()
        found = BLOCKLIST_OUT.match(rule_label(rec, labels))
        if not found or found.group(1) not in lists:
            continue
        if nets is None:
            nets, own = nr.local_networks(), own_addresses()
        source = rec.get('src', '')
        if source in own or not nr.started_inside(source, nets):
            continue
        stamp = nr.line_time(line) or now
        hit = hits.setdefault(source, {'count': 0, 'first': stamp, 'last': stamp})
        hit['count'] += 1
        hit.update(last=max(hit['last'], stamp), first=min(hit['first'], stamp), list=found.group(1), dst=rec.get('dst', ''))
    t = nr.texts(settings.get('language'))
    for source, hit in sorted(hits.items()):
        name, mac = device_of(settings, source)
        entry = infected.get(source)
        new = entry is None
        if new:
            entry = infected[source] = {'first': int(hit['first']), 'last': 0, 'count': 0}
        entry.update(last=int(max(entry.get('last') or 0, hit['last'])), count=int(entry.get('count') or 0) + hit['count'],
                     list=hit['list'], mac=mac or entry.get('mac', ''), name=name or entry.get('name', ''))
        changed = True
        if not new or not wanted(settings, 'c2_alert'):
            continue
        device = nr.label(source, {source: entry['name']} if entry['name'] else {})
        facts = {'address': source, 'name': entry['name'], 'mac': entry['mac'], 'list': hit['list'],
                 'list_name': lists[hit['list']], 'destination': hit['dst'], 'count': hit['count'],
                 'first': iso_time(hit['first'])}
        notify(settings, state, 'c2', source, subject_of(t, settings, 'c2_subject'),
               t['c2_text'].format(device=device, mac=entry['mac'] or t['unknown'], dst=hit['dst'], list=lists[hit['list']],
                                   time=local_time(hit['first'])), facts, now=now, priority='urgent', tags=['skull'])
    if changed:
        save_json(nr.INFECTED_FILE, infected)


# ---------------------------------------------------------------- alerts other XGS plugins leave for this one

XGS_OUTBOX = '/var/db/os-xgs-npu/alerts'
XGS_ANOMALY = '/var/db/os-xgs-npu/anomaly/alerts.jsonl'
OUTBOX_MAX_AGE = 86400


def time_of(value, default):
    """an ISO 8601 time or Unix seconds, as Unix seconds"""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        return datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return default


def channels_set(settings):
    return (settings.get('alert_mail') == '1' or bool(settings.get('alert_webhook_url')) or
            bool(settings.get('alert_ntfy_server') and settings.get('alert_ntfy_topic')))


def collect_xgs_outbox(settings, state, now, send):
    """(a) one JSON file per alert - {"source", "kind", "at", "subject", "text", "facts"} - taken and
    removed once a channel has it; kept while every channel fails, and dropped after 24 hours"""
    if not os.path.isdir(XGS_OUTBOX):
        return
    for name in sorted(os.listdir(XGS_OUTBOX)):
        path = os.path.join(XGS_OUTBOX, name)
        if not name.endswith('.json') or not os.path.isfile(path):
            continue
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            continue
        item = nr.load_json(path, None)
        usable = isinstance(item, dict) and bool(item.get('subject') or item.get('text'))
        if usable and send and channels_set(settings):
            facts = item.get('facts') if isinstance(item.get('facts'), dict) else {}
            facts = dict(facts, source=str(item.get('source') or ''))
            results = notify(settings, state, str(item.get('kind') or 'xgs'), name,
                             str(item.get('subject') or item.get('text'))[:300], str(item.get('text') or item.get('subject')),
                             facts, at=time_of(item.get('at'), mtime), now=now, quiet=0, priority='high', tags=['warning'])
            if results and SENT in results.values():
                os.unlink(path)
                continue
        if now - mtime >= OUTBOX_MAX_AGE:
            os.unlink(path)
            subject = str(item.get('subject') or name) if isinstance(item, dict) else name
            nr.add_history({'schedule': subject, 'subject': subject, 'recipients': '', 'archive': '', 'status': 'failed',
                            'detail': f'{XGS_OUTBOX}/{name} dropped: not sent within 24 hours'})


def collect_xgs_anomaly(settings, state, now, send, first):
    """(b) one JSON object a line - {"id", "at", "host", "kind", "message", "source"} - "id" counting up
    from 1: what is above the last id sent is sent; a file whose ids are all below it was started again"""
    st = state.get('xgs')
    try:
        with open(XGS_ANOMALY, encoding='utf-8', errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError:
        return
    records = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and isinstance(rec.get('id'), int) and not isinstance(rec.get('id'), bool):
            records.append(rec)
    top = max((r['id'] for r in records), default=0)
    last = st.get('last_id')
    if first:
        st['last_id'] = top
        return
    last = last if isinstance(last, int) else 0
    if top < last:
        last = 0                        # the file was started again
    t = nr.texts(settings.get('language'))
    for rec in sorted(records, key=lambda r: r['id']):
        if rec['id'] <= last:
            continue
        last = rec['id']
        st['last_id'] = last
        if not send:
            continue
        at = time_of(rec.get('at'), now)
        kind, host = str(rec.get('kind') or 'anomaly'), str(rec.get('host') or settings.hostname())
        source = str(rec.get('source') or 'os-xgs-npu')
        notify(settings, state, 'anomaly', f'{source}|{rec["id"]}', subject_of(t, settings, 'xgs_anomaly_subject', kind=kind, host=host),
               t['xgs_anomaly_text'].format(source=source, time=local_time(at), message=str(rec.get('message') or '')),
               {'id': rec['id'], 'kind': kind, 'host': host, 'source': source}, at=at, now=now, quiet=0, priority='high',
               tags=['warning'])
    st['last_id'] = last


def collect_xgs(settings, state, now):
    first = state.first('xgs')
    state.get('xgs')
    send = wanted(settings, 'xgs_alert')
    collect_xgs_outbox(settings, state, now, send)
    collect_xgs_anomaly(settings, state, now, send, first)


# ---------------------------------------------------------------- collectors

# (name, function(settings, state, now)): run each minute by netreport.py's scheduler, each on its
# own, so that one failing stops neither the others nor the reports
COLLECTORS = [
    ('gateway', collect_gateways),
    ('login', collect_logins),
    ('ips', collect_ips),
    ('vpn', collect_vpn),
    ('watchdog', collect_watchdog),
    ('c2', collect_c2),
    ('xgs', collect_xgs),
]


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
