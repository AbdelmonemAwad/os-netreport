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
run_collectors() caps each at 10 alerts a run, gives the pass 45 seconds, and after a pause of
more than 10 minutes starts the log readers again from the end of their logs.

/var/db/netreport/infected.json - written here, read by os-portguard to isolate a device:

    {"<address>": {"first": <unix time>, "last": <unix time>, "count": <blocked connections>,
                   "list": "<os-blocklists feed id>", "mac": "<mac or empty>", "name": "<name or empty>"}}

    one entry per address of the firewall's own networks, IPv4 or IPv6 (never one of the firewall's
    own addresses), that os-blocklists blocked on its way to a command-and-control list - on its rule
    "Block Lists: blocklists_<id> out" or "... from inside". For a device behind the firewall's
    outbound NAT only the second names it: pf matches the "out" rule after NAT and logs the firewall's
    own address there, so such a device is seen only with os-blocklists' "from inside" rule (its next
    release adds one for every command-and-control feed); "first" and "last" are
    the times of the first and the latest blocked connection, and an entry whose "last" is older
    than 7 days is dropped. Written whole (a temporary file renamed over it).

Taken from os-xgs-npu, when it is installed (neither existing is normal):

    /var/db/os-xgs-npu/alerts/*.json - one alert a file, {"source", "kind", "at", "subject", "text",
    "facts"}: sent, then removed; kept while every channel fails and tried again each minute
    (silently: a history line at the first failure, on the send that succeeds, and when it is
    dropped), and removed after 24 hours. One held at the collector's cap is not removed: it waits
    for the next minute. Only regular files are taken (a symbolic link is not followed), and one is
    removed only while it is still the file that was read.

    /var/db/os-xgs-npu/anomaly/alerts.jsonl - one {"id", "at", "host", "kind", "message", "source"} a
    line, "id" counting up from 1 and never reused: what is above the last id sent is sent; ids all
    below it mean the file was started again, and it is read from 0.
"""

import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
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
HTTP_TIMEOUT = 10               # seconds, each socket operation of a request
REQUEST_LIMIT = 15              # seconds, a channel's whole try: connecting, sending, the reply (limited())
MAIL_LIMIT = 60                 # seconds for a mail server to take the message, from the moment it is sent
                                # (by_mail: the connect, TLS and login have REQUEST_LIMIT like any try)
SLOW_LIMIT = 3                  # seconds, a channel that already ran out of time in this pass, for an alert
                                # that is not kept until sent (one that is skips it: deliver())
TIMER_REPEAT = 0.5              # seconds, the timer again while a try past its limit unwinds
NOT_SET = 'not set'
SENT = 'sent'
HELD = 'held'                   # past a collector's cap this run: in the history only, or left for the next minute
SKIPPED_SLOW = 'skipped: it did not answer earlier this minute'
COLLECTOR_CAP = 10              # alerts one collector sends in one run; the rest are summed up in one more
PASS_DEADLINE = 45              # seconds: collectors not yet run by then wait for the next minute
STALE_AFTER = 10 * 60           # a pass older than this, or a log line older than this, is not alerted on
LOG_READERS = ('login', 'ips', 'c2')

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
            # ASCII: a lone surrogate (a \ud800 escape in a record read) stays an escape; in UTF-8
            # it could not be written, and the state would never be saved again
            json.dump(data, fh, indent=1, ensure_ascii=True)
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
        # this run only: the collector running, how many alerts it has handed on, and how many held
        self.running, self.handed, self.held, self.held_subjects = None, 0, 0, []
        # this run only: the channels that timed out, not tried again in it
        self.slow = set()
        # this run only: whether a save of the state failed (a full /var: the state on disk is behind),
        # and whether a save was tried at all (can_keep())
        self.unsaved, self.save_tried = False, False

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


def site_of(url, base=''):
    """scheme://host[:port] of a URL (relative to base), or '': a path may carry a secret (a webhook's
    token), and user:password@ is never shown"""
    try:
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(base or '', url or ''))
        if not parts.scheme or not parts.hostname:
            return ''
        host = f'[{parts.hostname}]' if ':' in parts.hostname else parts.hostname
        return f'{parts.scheme}://{host}' + (f':{parts.port}' if parts.port else '')
    except ValueError:
        return ''


def error_text(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if 300 <= exc.code < 400:
            # where it pointed, as scheme://host only: the history and the system log keep this text
            where = site_of(exc.headers.get('Location', ''), exc.filename) if exc.headers else ''
            return f'the server answered with a redirect to {where or "(no address)"} (HTTP {exc.code})'
        return f'HTTP {exc.code} {exc.reason}'.strip()
    if isinstance(exc, RequestTimeout):
        return str(exc)
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

class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is not followed: urllib would follow 301/302/303 with a GET that still carries the
    webhook's header or ntfy's token, to whatever host the redirect names, and count its 200 as sent.
    Without a handler for it, any 3xx is an HTTPError, and a failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RequestTimeout(Exception):
    pass


def timer_usable():
    """whether limited() can use a real-time timer: it exists here (not on Windows) and this is the
    main thread (a signal handler runs only there)"""
    return hasattr(signal, 'setitimer') and threading.current_thread() is threading.main_thread()


TIMER = {'on': False, 'limit': None, 'done': False}    # the timer limited() runs: rearm() moves it


def rearm(seconds):
    """Inside limited(): the running try's timer set to end seconds from now. 0 stops it for good:
    the try is done (the mail server took the message), and a tick already on its way does nothing.
    Outside limited(), or where there is no timer, nothing happens."""
    if not (TIMER['on'] and timer_usable()):
        return
    if not seconds:
        TIMER['done'] = True
        signal.setitimer(signal.ITIMER_REAL, 0)
        return
    signal.setitimer(signal.ITIMER_REAL, seconds, TIMER_REPEAT)
    TIMER['limit'] = seconds


def limited(what, *args, limit=None):
    """what(*args), a channel's whole try, with limit seconds to end (REQUEST_LIMIT when not given).

    A real-time timer (SIGALRM) raises RequestTimeout in this thread when the time is up. A signal
    handler's exception interrupts a blocking call (PEP 475): the connect, the TLS handshake, a send
    or a recv - every step of HTTP, HTTPS and mail - and the code that was running goes no further,
    so nothing of the try is sent after it was counted a failure. After the first, the timer goes
    off again every TIMER_REPEAT seconds while the try is still unwinding, should anything on the
    way out catch the first and go on. rearm() moves it, or stops it for good (by_mail(), once the
    mail server took the message). The previous handler and timer are put back. One thing the timer
    cannot cut: the system's name lookup, which goes on to its own resolver timeouts before the
    timer's exception is raised.

    Where there is no setitimer (Windows: the tests there) or this is not the main thread, what runs
    without it: each socket operation then has its own timeout (HTTP_TIMEOUT, the mail's 60 s), but
    not the whole try."""
    limit = REQUEST_LIMIT if limit is None else limit
    if not timer_usable():
        return what(*args)
    live = [True]

    def on_alarm(signum, frame):
        if live[0] and not TIMER['done']:
            raise RequestTimeout(f'no answer within {TIMER["limit"]:g} s')

    previous = signal.signal(signal.SIGALRM, on_alarm)
    TIMER.update(on=True, limit=limit, done=False)
    old_delay, old_interval = signal.setitimer(signal.ITIMER_REAL, limit, TIMER_REPEAT)
    started = time.monotonic()
    try:
        try:
            return what(*args)
        finally:
            live[0] = False
    finally:
        live[0] = False
        TIMER.update(on=False, limit=None, done=False)
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if old_delay:
            signal.setitimer(signal.ITIMER_REAL, max(old_delay - (time.monotonic() - started), 0.001), old_interval)


def post(url, body, headers):
    """POST body; the HTTP status, or an exception. Redirects are not followed. TLS is verified: the
    default context checks the certificate and the name. The reply's body is not read - the status
    is enough - so a server that trickles it cannot hold the run. The time limit on the whole try is
    limited()'s; HTTP_TIMEOUT is on each socket operation."""
    if not url.lower().startswith(('https://', 'http://')):
        raise ValueError('the address must start with https:// or http://')
    request = urllib.request.Request(url, data=body, headers=headers, method='POST')
    try:
        response = urllib.request.build_opener(NoRedirect).open(request, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError as exc:
        # an HTTPError holds the reply open, and the traceback a cycle that keeps it until the garbage
        # collector closes it (http.client then printed "I/O operation on closed file"): its status
        # and headers are kept, its body is not needed
        try:
            exc.close()
        except Exception:
            pass
        raise
    try:
        status = response.status
    finally:
        response.close()
    if not 200 <= status < 300:
        raise urllib.error.HTTPError(request.full_url, status, response.reason, response.headers, None)
    return status


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
        return '=?UTF-8?B?' + b64encode(value.encode('utf-8', 'replace')).decode('ascii') + '?='


def by_mail(settings, alert, data_limit=None):
    """The connect, TLS and login run under limited()'s time; from the moment the message goes the
    timer has data_limit (MAIL_LIMIT unless given) for the server to take it, and once it did the timer
    stops for good: the QUIT after that has QUIT_TIMEOUT in all, and cannot make the mail a
    failure."""
    if settings.get('alert_mail') != '1':
        return NOT_SET, []
    ms = nr.mail_settings(settings)
    rcpt = nr.recipients_for(settings, None, ms)
    t = nr.texts(settings.get('language'))
    data_limit = MAIL_LIMIT if data_limit is None else data_limit
    nr.send_mail(ms, rcpt, alert['subject'], alert.get('html') or page_of(t, alert['subject'], alert['text']),
                 alert['text'], before_send=lambda: rearm(data_limit), after_send=lambda: rearm(0))
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
                       'facts': alert.get('facts') or {}}, ensure_ascii=False).encode('utf-8', 'replace')
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
    post(server.rstrip('/') + '/' + urllib.parse.quote(topic.strip(), safe=''), alert['text'].encode('utf-8', 'replace'),
         headers)
    return SENT


def was_sent(results):
    """whether at least one channel took the alert"""
    return bool(results) and SENT in results.values()


def waits(results):
    """whether the alert was held past its collector's cap: it was not tried"""
    return bool(results) and HELD in results.values()


def room(state):
    """whether the running collector may still hand on an alert this run"""
    return state is None or not state.running or state.handed < COLLECTOR_CAP


def may_hand_on(state):
    """whether an alert kept until sent can still be handed on: room under the collector's cap, and
    the pass not past its deadline (notify() holds it otherwise)"""
    past = getattr(state, 'past_deadline', None)
    return room(state) and not (callable(past) and past())


HELD_SHOWN = 5                  # subjects of held alerts named in their history line


def held_line(subject, held, subjects):
    """the one history line of a collector's pass for the alerts it held past its cap: one line however
    many, so that a storm cannot push the rest of the history (500 lines) out"""
    names = '; '.join(subjects[:HELD_SHOWN]) + ('; …' if len(subjects) > HELD_SHOWN else '')
    try:
        nr.add_history({'schedule': subject, 'subject': subject, 'recipients': '', 'archive': '', 'status': 'skipped',
                        'detail': f'{held} alerts of this kind held this minute (more than {COLLECTOR_CAP}): {names}'})
    except Exception as exc:
        nr.log(f'alert "{subject}": the history could not be written: {exc}')


def timed_out(exc):
    """whether a channel's error is that it did not answer in time: the error itself, a URLError's
    reason, or what it was raised from or while handling (smtplib says a read that timed out is
    SMTPServerDisconnected, the timeout its context)"""
    seen, todo = set(), [exc]
    while todo:
        exc = todo.pop()
        if not isinstance(exc, BaseException) or id(exc) in seen:
            continue
        seen.add(id(exc))
        if isinstance(exc, (RequestTimeout, socket.timeout, TimeoutError)):
            return True
        if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
            todo.append(exc.reason)
        todo += [exc.__cause__, exc.__context__]
    return False


def deliver(settings, alert, record=None, slow=None, kept=False):
    """Hand one alert to every channel; returns {"mail": ..., "webhook": ..., "ntfy": ...}.

    The try is a line in the history (and, when nothing took it, in the system log) unless record,
    given the results, says no: a retry that fails again is silent.

    slow is the pass's set of channels that timed out. An alert kept until it is sent (kept: an
    outbox file, an anomaly, a watchdog reset) is not tried in that pass on a channel in it (SKIPPED_SLOW, a failure:
    it stays kept for the next pass), so that ten of them to a server that does not answer cannot
    take ten times REQUEST_LIMIT. Any other alert - a gateway down, failed logins... - would be lost
    by a skip: it is tried on every channel, but on a channel in slow with SLOW_LIMIT seconds, so a
    server that does not answer costs each of them seconds, not REQUEST_LIMIT. The mail has
    MAIL_LIMIT from the moment its message goes (a mail server may take long to say 250 after it,
    while it holds it); its connect, TLS and login have REQUEST_LIMIT like the others."""
    results, rcpt = {}, []
    for name, channel in (('mail', by_mail), ('webhook', by_webhook), ('ntfy', by_ntfy)):
        limit, data_limit = REQUEST_LIMIT, MAIL_LIMIT
        if slow is not None and name in slow:
            if kept:
                results[name] = SKIPPED_SLOW
                continue
            limit = data_limit = min(REQUEST_LIMIT, SLOW_LIMIT)
        try:
            if name == 'mail':
                results[name], rcpt = limited(channel, settings, alert, data_limit, limit=limit)
            else:
                results[name] = limited(channel, settings, alert, limit=limit)
        except Exception as exc:
            results[name] = error_text(exc)
            if slow is not None and timed_out(exc):
                slow.add(name)
    if record is not None and not record(results):
        return results
    tried = [name for name, result in results.items() if result != NOT_SET]
    sent = was_sent(results)
    recipients = list(rcpt) + [name for name in ('webhook', 'ntfy') if name in tried]
    if not tried:
        detail = 'no alert channel is set'
    else:
        detail = '; '.join(f'{name}: {result}' for name, result in results.items())
    try:
        nr.add_history({'schedule': alert['subject'], 'subject': alert['subject'], 'recipients': ', '.join(recipients),
                        'archive': '', 'status': 'alert' if sent else 'failed', 'detail': detail})
    except Exception as exc:
        nr.log(f'alert "{alert["subject"]}": the history could not be written: {exc}')
    if not sent:
        nr.log(f'alert "{alert["subject"]}" was not sent: {detail}')
    return results


def save_or_log(state, what):
    """state.save(), a failure (a full /var) logged, not raised: what was delivered stays delivered.
    Returns whether it saved. A failure stays in state.unsaved for the rest of the run: the
    anomalies, which the state keeps until they are sent, wait for the next (can_keep())."""
    state.save_tried = True
    try:
        state.save()
    except Exception as exc:
        state.unsaved = True
        nr.log(f'{what}: the alert state could not be saved: {exc}')
        return False
    return True


def can_keep(state, what, first=False):
    """Whether an alert kept until it is sent (an anomaly, a watchdog reset) may go out, or one kept
    for a retry be dropped, and whether a gateway's or a VPN tunnel's change may be said: only while
    the alert state can be saved. One sent while it cannot would be sent again each minute, the next
    run reading the state as it was; once a save failed in a run, none goes for the rest of it.

    first, before a new one is first tried: the state is saved as it will be if the send goes and the
    save after it fails - the anomaly pending and the last id past it, the reset kept and its boot
    recorded, the gateway's or tunnel's new state recorded - so that a disk full by then holds it
    back. The save after the send (the caller's, as it takes the alert off its list: notify() saves
    nothing for an alert kept until sent) holds no more than the one before it, but it can still
    fail: the file it replaces may be smaller (the state grew earlier in the pass), and other writes -
    the send's history line, a log on /var - take room in between. An anomaly or a reset in flight
    then goes again once there is room; a gateway's or a tunnel's change, its new state kept, is not
    said again. Before a retry or a drop one save a run is made, the first if nothing has saved it:
    where a later save fails, a retried alert may go again, and a drop's history line be written
    again, once there is room."""
    if state.unsaved:
        return False
    if first or not state.save_tried:
        return save_or_log(state, what)
    return True


def notify(settings, state, kind, key, subject, text, facts=None, page=None, at=None, now=None,
           quiet=None, priority='default', tags=(), record=None, defer=False):
    """Send one alert, unless the same kind and key went out within its quiet time.

    Returns the result per channel, or None when the quiet time held it back. The time of the try is
    remembered whatever the channels answered, so that a channel that is down is tried again after
    the quiet time and not every minute. record is as deliver()'s.

    Past the running collector's cap the alert is not tried: HELD for every channel. An alert the
    collector keeps until it is sent (defer: an outbox file, an anomaly, a watchdog reset) is then left for the
    next minute - no history line, no quiet time; any other is counted, and named, in the collector's
    one history line and summary alert for what it held (run_collectors).

    An alert kept until it is sent leaves no quiet-time mark (it has no quiet time) and is not saved
    here: its caller saves the state as it takes the alert off its list, so that the save after a send
    is smaller than the one before it (can_keep()), and a failed retry writes nothing.
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
    if state is not None and state.running:
        past = getattr(state, 'past_deadline', None)
        if defer and callable(past) and past():
            # the pass is past PASS_DEADLINE: what is kept until sent waits for the next minute, with no
            # history line; any other alert is still tried (with SLOW_LIMIT on a slow channel)
            return {name: HELD for name in ('mail', 'webhook', 'ntfy')}
        if state.handed >= COLLECTOR_CAP:
            if defer:
                return {name: HELD for name in ('mail', 'webhook', 'ntfy')}
            # an alert storm: past the cap, an alert is not sent; the collector's one history line and
            # its summary alert say how many (run_collectors)
            state.held += 1
            state.held_subjects.append(subject)
            sent[mark] = now
            return {name: HELD for name in ('mail', 'webhook', 'ntfy')}
        state.handed += 1
    results = deliver(settings, alert, record, getattr(state, 'slow', None), kept=defer)
    if state is not None and not defer:
        sent[mark] = now
        # a full disk must not make every caller take the alert for a failure and send it again
        save_or_log(state, f'alert "{subject}"')
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


def kept_before(state, entries, key, before, what):
    """Whether a change track() has just found may be said: the state is saved first (can_keep()), as
    one said while it cannot be saved would be said again each minute, each run reading the reads
    before it. When that save fails, the entry is put back as it was before this read (before: a copy,
    or None for one followed from this read on), so that the change is said once there is room - when
    its new state has held on two reads."""
    if can_keep(state, what, first=True):
        return True
    if before is None:
        entries.pop(key, None)
    else:
        entries[key] = before
    return False


def entry_copy(entries, key):
    """a copy of a followed thing's entry, to put back (kept_before()); None for one not followed yet"""
    return json.loads(json.dumps(entries[key])) if isinstance(entries.get(key), dict) else None


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
        before = entry_copy(entries, name)
        said = track(entries, name, read, now, flapping=True)
        if not said or not send or not kept_before(state, entries, name, before, 'gateway'):
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


def read_from(place, path, where=False):
    """the complete lines of path written since place = {"inode", "offset"}, which moves past them;
    a new inode (the file was rotated) or a shorter file starts again at 0. With where, each line
    comes as (line, file, start, end): the file as path|inode, and the byte offsets where the line
    starts and where the next one does. A read of this file that does not go on from where the last
    one ended - a new inode, a log grown past MAX_READ - forgets the line kept for unfolding, when
    that line is this file's: one of the file read before (the day before's) stays, so that a fold
    at the start of the rest of that file still finds it."""
    try:
        info = os.stat(path)
    except OSError:
        return []
    offset = place.get('offset', 0) if isinstance(place.get('offset'), int) else 0

    def forget():
        prev = place.get('prev')
        if not isinstance(prev, dict) or str(prev.get('file', '')).startswith(path + '|'):
            place.pop('prev', None)
    if place.get('inode') != info.st_ino or info.st_size < offset:
        place['inode'], offset = info.st_ino, 0
        forget()
    partial = info.st_size - offset > MAX_READ
    if partial:
        offset = info.st_size - MAX_READ
        forget()
    with open(path, 'rb') as fh:
        fh.seek(offset)
        data = fh.read(info.st_size - offset)
    end = data.rfind(b'\n')
    if end < 0:
        place['offset'] = offset
        return []
    place['offset'] = offset + end + 1
    lines, at, src = [], offset, f'{path}|{info.st_ino}'
    for raw in data[:end].split(b'\n'):
        lines.append((raw.decode('utf-8', 'replace'), src, at, at + len(raw) + 1))
        at += len(raw) + 1
    if partial:
        lines = lines[1:]           # the first line read from the middle is not a whole one
    return lines if where else [line[0] for line in lines]


def follow(place, path, unfold=False):
    """New lines of a log followed by name: on the first run only where it ends is recorded; when the
    name changes (a new day's file), the rest of the old file is read and the new one from 0. With
    unfold, the lines syslog-ng folded into "Last message '...' repeated N times" are given back
    (see unfolded())."""
    if 'path' not in place:
        place.pop('prev', None)
        try:
            info = os.stat(path)
            place.update(path=path, inode=info.st_ino, offset=info.st_size)
        except OSError:
            place.update(path=path, inode=None, offset=0)
        return []
    lines = []
    if place['path'] != path:
        lines += read_from(place, place['path'], where=True)
        place.update(path=path, inode=None, offset=0)
    lines += read_from(place, path, where=True)
    return unfolded(place, lines) if unfold else [line[0] for line in lines]


def rfc5424(line):
    """(time, program, message) of an RFC 5424 line ("<pri>1 time host app procid msgid sd msg"), or None"""
    parts = line.split(' ', 6)
    if len(parts) < 7 or not parts[0].startswith('<') or not parts[0].endswith('>1'):
        return None
    rest = parts[6]
    if rest == '-' or rest.startswith('- '):
        return parts[1], parts[3], rest[2:]
    # structured data: [id name="value" ...] elements, where a value may hold \" \] and spaces
    i, quoted = 0, False
    while i < len(rest) and rest[i] == '[':
        i += 1
        while i < len(rest):
            c = rest[i]
            if quoted and c == '\\':
                i += 2
                continue
            if c == '"':
                quoted = not quoted
            elif c == ']' and not quoted:
                break
            i += 1
        i += 1
    msg = rest[i:]
    return parts[1], parts[3], msg[1:] if msg.startswith(' ') else msg


def message_of(line):
    """the message of an RFC 5424 line (after "<pri>1 time host app procid msgid sd"), or the line"""
    parsed = rfc5424(line)
    return parsed[2] if parsed else line


# syslog-ng's suppress(): OPNsense's log destinations write a line repeated within seconds once, then
# "Last message '<its first 20 characters>' repeated N times, suppressed by syslog-ng on <host>", with
# the folded line's program
FOLDED = re.compile(r"^Last message '(?P<prefix>.*)' repeated (?P<n>\d+) times?, suppressed by syslog-ng on \S+\s*$")
UNFOLD_MAX = 1000               # a folded count is given back up to this many times
API_KEY = re.compile(r'(authentication failed for api key )(\S{0,4})\S*')


def without_key(line):
    """a line as it may be kept in the state: an API key OPNsense logged cut to its first 4 characters"""
    return API_KEY.sub(lambda found: found.group(1) + found.group(2), line)


def unfolded(place, lines):
    """The lines, given as (line, file, start, end) by read_from(), with each one syslog-ng folded
    given back: a "Last message '...' repeated N times" line stands for N more of the line just
    before it in the same file - its program's, and the quoted part beginning its message - and
    carries the time of the fold. syslog-ng writes the fold right after the line it folds, so a fold
    that does not start where that line ended (another line between, another file, a read that
    restarted or skipped) gives back nothing: it cannot multiply a line read long before. The last
    line is kept in place["prev"] with its file and where it ended, so a fold read the minute after
    its line is given back too."""
    prev = place.get('prev') if isinstance(place.get('prev'), dict) and 'end' in place['prev'] else None
    out = []
    for line, src, start, end in lines:
        parsed = rfc5424(line)
        folded = FOLDED.match(parsed[2]) if parsed else None
        if not folded:
            out.append(line)
            prev = {'line': line, 'file': src, 'end': end}
            continue
        earlier, prev = prev, None
        if not earlier or earlier.get('file') != src or earlier.get('end') != start:
            continue
        before = rfc5424(earlier['line'])
        if not before or before[1] != parsed[1] or not before[2].startswith(folded.group('prefix')):
            continue
        head, _, rest = earlier['line'].partition(' ')
        again = ' '.join([head, parsed[0], rest.partition(' ')[2]])
        out += [again] * min(int(folded.group('n')), UNFOLD_MAX)
    if prev:
        place['prev'] = dict(prev, line=without_key(prev['line'])[:4096])
    else:
        place.pop('prev', None)
    return out


# ---------------------------------------------------------------- repeated failed logins

LOGIN_WINDOW = 10 * 60
LOGIN_QUIET = 30 * 60
QUIET['login'] = LOGIN_QUIET
IP = r'(?P<address>[0-9A-Fa-f:.]*[0-9A-Fa-f])'
GUI_PROGRAMS = ('audit',)
SSH_PROGRAMS = ('sshd', 'sshd-session')     # sshd-session: OpenSSH's per-connection process (OPNsense 26.7)
# Each pattern is anchored at the end of the message and the address taken from there: a user name is
# what the other side typed, and one like "x from 192.0.2.77 port 22" must not put that address in
# the alert. A pattern is tried only on the lines of its programs. (kind, programs, service, pattern);
# a user name may hold spaces.
LOGIN_PATTERNS = [
    # OPNsense 26.7 (Auth/AuthenticationFactory.php): every failed authentication of any service - the
    # web GUI, the API's user and password, others - ends in one warning, "user <name> could not
    # authenticate for <service>. [using <service class> + <authenticator class>] at <address>". Not
    # counted: the debug line before it per authenticator ("... failed authentication for ..."), which
    # is not always written; the login page's "Web GUI authentication error for '<name>' from
    # <address>", the same try; and "... could not authenticate for <service>, failed constraints on
    # ...", a right password for an account disabled or expired. A failed API key is logged without
    # the caller's address ("uri ... authentication failed for api key ..."), so it is not counted.
    ('gui', GUI_PROGRAMS, None,
     re.compile(r'user (?P<user>.+) could not authenticate for (?P<service>\S+?)\. \[using [^\[\]]* \+ [^\[\]]*\] at ' +
                IP + '$')),
    # sshd: every failed try is a line of its own; "publickey" is not counted, since an agent offering
    # several keys to a valid user logs it routinely
    ('failed', SSH_PROGRAMS, 'ssh', re.compile(r'Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*) from ' + IP +
                                               r' port (?P<port>\d+)(?: ssh2)?$')),
    ('invalid', SSH_PROGRAMS, 'ssh', re.compile(r'Invalid user (?P<user>.*) from ' + IP + r' port (?P<port>\d+)$')),
    ('pam', SSH_PROGRAMS, 'ssh', re.compile(r'error: PAM: Authentication error for (?:illegal user )?(?P<user>.*) from ' +
                                            IP + '$')),
]
PAM_PAIR = 2                    # seconds: a PAM error and sshd's "Failed" line of one try
# OPNsense's "System" authentication also answers for the PAM services when an owner lets passwords
# log in, and then audit may write its "could not authenticate for sshd" beside sshd's own "Failed
# password" line of the same try: the audit line is not counted for these, SSH is counted from sshd's
# lines alone (sshd's names for itself among them)
PAM_SERVICES = frozenset(('sshd', 'login', 'su', 'sudo', 'ssh') + SSH_PROGRAMS)


def login_failure(line):
    """(address, user, service, port, kind) of a failed login line, or None; a line is read only by
    the patterns of its program"""
    parsed = rfc5424(line)
    if not parsed:
        return None
    program, msg = parsed[1], parsed[2].strip()
    for kind, programs, service, pattern in LOGIN_PATTERNS:
        if program not in programs:
            continue
        found = pattern.search(msg)
        if not found or (kind == 'failed' and found.group('method') == 'publickey'):
            continue
        if kind == 'gui' and found.group('service').lower() in PAM_SERVICES:
            continue
        try:
            address = str(ipaddress.ip_address(found.group('address')))
        except ValueError:
            continue
        return (address, found.group('user'), service or found.group('service'), found.groupdict().get('port') or '',
                kind)
    return None


def user_id(user):
    """A user name tried is kept as a digest, to count the names, and its first two characters, to
    show them: people type a password into the user field, and the names are never sent whole."""
    return hashlib.sha256(user.encode('utf-8', 'replace')).hexdigest()[:16], user[:2] + '…'


def count_failure(seen, stamp, uid, shown, service, port, kind):
    """Add one failed login to an address's list [stamp, uid, service, port, kind, paired, shown].

    Every sshd "Failed" line is a try. Its "Invalid user" line (the same port) and PAM's error (the
    same user within PAM_PAIR seconds) are the same try and are not counted beside it, whichever comes
    first; without a "Failed" line they count as one try each."""
    def pairs(f, other):
        if other == 'invalid':
            return f[3] == port and port != ''
        return f[1] == uid and abs(f[0] - stamp) <= PAM_PAIR
    if kind == 'failed':
        paired = ''
        for other in ('invalid', 'pam'):
            for f in seen:
                if f[4] == other and not f[5] and pairs(f, other):
                    seen.remove(f)
                    paired += other[0]
                    break
        seen.append([stamp, uid, service, port, kind, paired, shown])
        return
    if kind in ('invalid', 'pam'):
        for f in seen:
            if f[4] == 'failed' and kind[0] not in f[5] and pairs(f, kind):
                f[5] += kind[0]
                return
    seen.append([stamp, uid, service, port, kind, '', shown])


def failures_of(fails):
    """the per-address lists as they are now kept; a list an older version kept is converted"""
    out = {}
    for address, seen in (fails.items() if isinstance(fails, dict) else []):
        kept = []
        for f in seen if isinstance(seen, list) else []:
            if isinstance(f, list) and len(f) == 4:
                uid, shown = user_id(str(f[1]))
                f = [f[0], uid, f[2], f[3], '', '', shown]
            if isinstance(f, list) and len(f) == 7 and isinstance(f[0], (int, float)):
                kept.append(f)
        if kept:
            out[address] = kept
    return out


def collect_logins(settings, state, now):
    first = state.first('login')
    st = state.get('login')
    place = st.setdefault('log', {})
    lines = follow(place, day_file(AUDIT_LOG, now), unfold=True)
    fails = failures_of(st.get('fails'))
    for line in lines:
        failure = login_failure(line)
        if not failure:
            continue
        address, user, service, port, kind = failure
        stamp = nr.line_time(line) or now
        uid, shown = user_id(user)
        count_failure(fails.setdefault(address, []), stamp, uid, shown, service, port, kind)
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
        names = len({f[1] for f in seen})
        shown = sorted({f[6] for f in seen})[:3]
        services = sorted({f[2] for f in seen})
        last = max(f[0] for f in seen)
        facts = {'address': address, 'count': len(seen), 'user_names': names, 'users': shown, 'services': services,
                 'last': iso_time(last)}
        notify(settings, state, 'login', address, subject_of(t, settings, 'login_subject', address=address),
               t['login_text'].format(n=len(seen), address=address, time=local_time(last), services=sep.join(services),
                                      users=t['login_names'].format(n=names, names=sep.join(shown))),
               facts, now=now, priority='high', tags=['lock'])


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
        try:
            stamp = datetime.datetime.fromisoformat(re.sub(r'([+-]\d\d)(\d\d)$', r'\1:\2', ev['timestamp'])).timestamp()
        except (KeyError, ValueError, TypeError):
            stamp = now
        if now - stamp > STALE_AFTER:
            continue                    # an old event (a backlog): not alerted
        signature = str(alert.get('signature') or alert.get('signature_id') or '?')
        source = str(ev.get('src_ip') or '?')
        g = groups.setdefault((str(alert.get('signature_id') or signature), source),
                              {'signature': signature, 'severity': severity, 'src': source, 'dst': Counter(),
                               'actions': set(), 'count': 0, 'first': None})
        g['count'] += 1
        g['dst'][str(ev.get('dest_ip') or '?')] += 1
        g['actions'].add('blocked' if alert.get('action') == 'blocked' else 'allowed')
        g['severity'] = min(g['severity'], severity)
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


def ipsec_up(conn):
    """An IPsec connection is up when one of its IKE sessions is ESTABLISHED with at least one child SA
    INSTALLED. `configctl ipsec list status` (list_status.py) puts each IKE SA strongSwan's list-sas
    gives under the connection's "sas", with its "state" and its "child-sas" by name, each with its own
    "state"; a session still CONNECTING (a peer that does not answer, strongSwan retrying) is not up."""
    for sa in conn.get('sas') or []:
        if not isinstance(sa, dict) or str(sa.get('state', '')).upper() != 'ESTABLISHED':
            continue
        children = sa.get('child-sas')
        children = children.values() if isinstance(children, dict) else children if isinstance(children, list) else []
        if any(isinstance(c, dict) and str(c.get('state', '')).upper() == 'INSTALLED' for c in children):
            return True
    return False


def vpn_reads(settings, entries, now):
    """({key: (name, 'up' or 'down')} of every connection this read could see, and the key prefixes of
    the sources that answered)"""
    reads, answered = {}, []
    ipsec = configctl('ipsec', 'list', 'status')
    if isinstance(ipsec, dict):
        answered.append('ipsec|')
        for cid, conn in ipsec.items():
            if isinstance(conn, dict):
                name = description(settings, cid) or str(conn.get('remote-addrs') or cid)
                reads[f'ipsec|{cid}'] = ('IPsec ' + name, 'up' if ipsec_up(conn) else 'down')
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
        reads.update(openvpn_reads(settings, entries, ovpn))
    return reads, answered


def openvpn_instances(settings):
    """{id: (role, description)} of the OpenVPN instances configured and enabled in config.xml, by the
    id `configctl openvpn connections` (ovpn_status.py) gives them: an instance of OPNsense's OpenVPN
    model (OPNsense/OpenVPN/Instances/Instance, socket instance-<uuid>.sock) by its uuid, a legacy
    server or client (openvpn/openvpn-server, openvpn/openvpn-client, socket server<vpnid>.sock or
    client<vpnid>.sock) by its vpnid"""
    found = {}
    for inst in settings.root.findall('./OPNsense/OpenVPN/Instances/Instance'):
        uuid = inst.get('uuid')
        if uuid and (inst.findtext('enabled') or '').strip() == '1':
            role = 'client' if (inst.findtext('role') or '').strip() == 'client' else 'server'
            found[uuid] = (role, (inst.findtext('description') or '').strip())
    for tag, role in (('openvpn-server', 'server'), ('openvpn-client', 'client')):
        for item in settings.root.findall(f'./openvpn/{tag}'):
            vpnid = (item.findtext('vpnid') or '').strip()
            if vpnid and item.find('disable') is None:
                found[vpnid] = (role, (item.findtext('description') or '').strip())
    return found


def openvpn_reads(settings, entries, ovpn):
    """{key: (name, 'up' or 'down')} of the OpenVPN instances: those configured and enabled in
    config.xml, and those ovpn_status.py lists. An instance that is configured and enabled but
    missing (it exited, and took its management socket with it) or failed (its socket refuses) is
    down; so are a failed server's clients. An instance neither configured nor listed has been
    removed: it gets no read, and collect_vpn() forgets it."""
    reads = {}
    clients = ovpn.get('client') if isinstance(ovpn.get('client'), dict) else {}
    servers = ovpn.get('server') if isinstance(ovpn.get('server'), dict) else {}
    configured = openvpn_instances(settings)
    for iid in sorted(set(clients) | set(servers) | set(configured)):
        role, descr = configured.get(iid, (None, ''))
        name = 'OpenVPN ' + (descr or description(settings, iid) or iid)
        inst = clients.get(iid) if isinstance(clients.get(iid), dict) else servers.get(iid)
        # missing: configured and enabled, but not running; failed: ovpn_status.py could not ask it (it
        # cannot tell a client from a server then and lists it under "server")
        failed = not isinstance(inst, dict) or inst.get('status') == 'failed'
        if role is None:
            role = 'client' if iid in clients else 'server' if not failed or f'ovpn|c|{iid}' not in entries else 'client'
        if role == 'client':
            reads[f'ovpn|c|{iid}'] = (name, 'up' if not failed and inst.get('status') == 'connected' else 'down')
            continue
        own = f'ovpn|s|{iid}|'
        if failed:
            reads[own] = (name, 'down')
            for key, entry in entries.items():
                if key.startswith(own) and key != own:
                    reads[key] = (entry.get('name') or key, 'down')
            continue
        if 'client_list' not in inst and 'timestamp' in inst:
            # a peer-to-peer instance: its own state
            reads[own] = (name, 'up' if inst.get('status') == 'connected' else 'down')
            continue
        reads[own] = (name, 'up')
        for client in inst.get('client_list') or []:
            if isinstance(client, dict):
                cn = client.get('common_name') or client.get('username') or client.get('real_address') or '?'
                reads[f'{own}{cn}'] = (f'{name}: {cn}', 'up')
        # a client that has left the server's list is down
        for key, entry in entries.items():
            if key.startswith(own) and key != own and key not in reads:
                reads[key] = (entry.get('name') or key, 'down')
    return reads


def collect_vpn(settings, state, now):
    first = state.first('vpn')
    entries = state.get('vpn')
    reads, answered = vpn_reads(settings, entries, now)
    for key in list(entries):
        if key in reads:
            continue
        if any(key.startswith(p) for p in answered):
            del entries[key]            # gone from what answered: removed from the configuration
    send = wanted(settings, 'vpn_alert') and not first
    t = nr.texts(settings.get('language'))
    for key, (name, read) in sorted(reads.items()):
        before = entry_copy(entries, key)
        said = track(entries, key, read, now)
        entries[key]['name'] = name
        if not said or not send or not kept_before(state, entries, key, before, 'vpn'):
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
RESETS_KEPT = 10                # resets kept for a retry at most


def send_reset(settings, state, entry, now, was_failing):
    """one kept reset to the channels, in the language set when it is tried: SENT, HELD (past the
    collector's cap or the pass deadline, not tried) or 'failed'"""
    t = nr.texts(settings.get('language'))
    reasons = [str(r) for r in entry.get('reasons') or []] or [t['unknown']]
    facts = {'boot': entry['boot'], 'reasons': reasons, 'value': entry.get('value'), 'read_at': entry.get('read_at')}
    results = notify(settings, state, 'watchdog', entry['boot'], subject_of(t, settings, 'wd_subject'),
                     t['wd_text'].format(time=local_time(time_of(entry.get('when'), now)),
                                         reasons=t.get('list_sep', ', ').join(reasons)),
                     facts, now=now, quiet=0, priority='high', tags=['warning'], record=retried(was_failing),
                     defer=True)
    return SENT if was_sent(results) else HELD if waits(results) else 'failed'


def try_reset(settings, state, entry, now, was_failing):
    """send_reset(); one that raises stays kept, as a failure"""
    try:
        return send_reset(settings, state, entry, now, was_failing)
    except Exception as exc:
        nr.log(f'watchdog reset of boot {entry.get("boot")} could not be sent: {exc}')
        return 'failed'


def new_reset(settings, state, st, record, now, alert):
    """a boot os-watchdog has a new record of: recorded, and when the watchdog caused its reset (and
    alert says to tell it), kept and tried - saved as kept first (can_keep()); where that save fails,
    the boot is put back as it was, and the reset waits for a run that can save it"""
    boot = str(record.get('boot'))
    old_boot = st.get('boot')
    st['boot'] = boot
    bits = [b for b in record.get('bits') or [] if isinstance(b, dict)]
    if 'watchdog' in record:
        # os-watchdog says it: true only - false is another cause, null that it cannot tell (a bit an
        # earlier boot left set, a register that answers nothing)
        by_watchdog = record.get('watchdog') is True
    else:
        # a record kept before os-watchdog wrote the field: bit 25 among its bits
        by_watchdog = any(str(b.get('bit')) == str(WATCHDOG_BIT) for b in bits)
    if not alert or not by_watchdog:
        return
    read_at = record.get('read_at')
    entry = {'boot': boot, 'when': time_of(read_at, now), 'reasons': [str(b.get('reason') or b.get('bit')) for b in bits],
             'value': record.get('value'), 'read_at': read_at, 'since': now, 'failed': False}
    st['pending'].append(entry)
    if may_hand_on(state) and channels_set(settings) and not can_keep(state, 'watchdog', first=True):
        without(st['pending'], entry)
        if old_boot is None:
            st.pop('boot', None)
        else:
            st['boot'] = old_boot
        return
    result = try_reset(settings, state, entry, now, False)
    if result == SENT:
        without(st['pending'], entry)
        save_or_log(state, 'watchdog')
    else:
        entry['failed'] = result != HELD


def retry_resets(settings, state, st, now, send, old):
    """the resets kept before this run, tried again while the cap leaves room; then those 24 hours
    old dropped, and the oldest past RESETS_KEPT - only where the state can be saved, as the
    anomalies' are (retry_anomalies())"""
    pending = st['pending']
    for p in old:
        if send and channels_set(settings) and may_hand_on(state) and can_keep(state, 'watchdog'):
            result = try_reset(settings, state, p, now, p.get('failed', True))
            if result == SENT:
                without(pending, p)
                save_or_log(state, 'watchdog')
                continue
            p['failed'] = p.get('failed', True) or result != HELD
    still = {id(p) for p in pending}
    expired = [p for p in old if id(p) in still and now - (p.get('since') or now) >= OUTBOX_MAX_AGE]
    if (expired or len(pending) - len(expired) > RESETS_KEPT) and not can_keep(state, 'watchdog'):
        return
    subject = subject_of(nr.texts(settings.get('language')), settings, 'wd_subject')
    for p in expired:
        without(pending, p)
        dropped(subject, f'watchdog reset of boot {p.get("boot")} dropped: not sent within 24 hours')
    over = len(pending) - RESETS_KEPT
    if over > 0:
        del pending[:over]
        detail = f'watchdog: {over} resets dropped unsent, the oldest: more than {RESETS_KEPT} were waiting'
        nr.log(detail)
        dropped(subject, detail)


def collect_watchdog(settings, state, now):
    """A reset the hardware watchdog caused, from os-watchdog's record of the boot: one alert, kept
    until a channel takes it - tried again each minute (silently after its first failure, as an
    anomaly is) and dropped after 24 hours - so that one tried in the first minutes after the boot,
    before the WAN is up, is not lost, nor one a run was killed sending. It is saved as kept, with its
    boot, before it is first tried: while the state cannot be saved (a full /var), none goes."""
    first = state.first('watchdog')
    st = state.get('watchdog')
    st['pending'] = [p for p in st.get('pending') or [] if isinstance(p, dict) and isinstance(p.get('boot'), str)]
    old = list(st['pending'])
    send = wanted(settings, 'watchdog_alert')
    record = nr.load_json(RESET_REASON, None)
    if isinstance(record, dict) and 'boot' in record and st.get('boot') != str(record.get('boot')):
        new_reset(settings, state, st, record, now, send and not first)
    retry_resets(settings, state, st, now, send, old)


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
# os-blocklists' outbound rule, which pf matches after outbound NAT (so behind NAT it logs the firewall's
# own address, left out below), and the floating rule its next release adds for every command-and-
# control feed, `block in log quick ... to <blocklists_<id>>`, which matches where the packet enters
# the firewall, before NAT, with the device's own address
BLOCKLIST_OUT = re.compile(r'^Block Lists: blocklists_(\S+) (?:out|from inside)$')
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
    lines = follow(st.setdefault('log', {}), day_file(FILTER_LOG, now), unfold=True)
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
        try:
            source = str(ipaddress.ip_address(rec.get('src', '')))
        except ValueError:
            continue
        if source in own or not nr.started_inside(source, nets):
            continue
        try:
            if str(ipaddress.ip_address(rec.get('dst', ''))) in own:
                continue                # the firewall itself, its address on a list: no server reached
        except ValueError:
            pass
        stamp = nr.line_time(line) or now
        if now - stamp > STALE_AFTER:
            continue                    # an old line (a backlog): neither alerted nor counted
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
    """an ISO 8601 time or Unix seconds, as Unix seconds; a number this large is milliseconds (1e11
    seconds is the year 5138), and a time that is not one - or none a date can hold - is default"""
    if isinstance(value, bool):
        return default
    try:
        # float() of an integer too large for a float (400 digits) raises OverflowError
        if isinstance(value, (int, float)):
            ts = float(value)
        else:
            try:
                ts = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
            except (TypeError, ValueError, OverflowError, OSError):
                ts = float(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(ts):
        return default
    if abs(ts) >= 1e11:
        ts /= 1000
    try:
        datetime.datetime.fromtimestamp(ts)
    except (OverflowError, OSError, ValueError):
        return default
    return ts


def channels_set(settings):
    return (settings.get('alert_mail') == '1' or bool(settings.get('alert_webhook_url')) or
            bool(settings.get('alert_ntfy_server') and settings.get('alert_ntfy_topic')))


def dropped(subject, detail):
    """the one history line of an alert dropped unsent"""
    try:
        nr.add_history({'schedule': subject, 'subject': subject, 'recipients': '', 'archive': '', 'status': 'failed',
                        'detail': detail})
    except Exception as exc:
        nr.log(f'alert "{subject}": the history could not be written: {exc}')


def retried(was_failing):
    """deliver()'s record for an alert tried again: its history is written once at the first failure,
    once on the send that succeeds, and (by its caller) once when it is dropped - not every minute"""
    return lambda results: was_sent(results) or not was_failing


OUTBOX_FILE_MAX = 1024 * 1024  # bytes read of one alert file at most


def read_outbox(path):
    """(the JSON, the file's stat) of one alert file, or (None, None) when it is not a regular file of
    its own: a symlink is not followed (lstat, and O_NOFOLLOW where the system has it), and what is
    opened must be what was looked at. The JSON is None when the file does not hold any."""
    try:
        info = os.lstat(path)
    except OSError:
        return None, None
    if not stat.S_ISREG(info.st_mode):
        return None, None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None, None
    with os.fdopen(fd, 'rb') as fh:
        opened = os.fstat(fh.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            return None, None
        data = fh.read(OUTBOX_FILE_MAX)
    try:
        # every string cleaned of lone surrogates once, here: none reaches a mail, the system log or the history
        return nr.no_surrogates(json.loads(data.decode('utf-8'))), opened
    except (ValueError, RecursionError):
        return None, opened


def remove_same(path, info):
    """remove path if it is still the file that was read (the same inode and size); whether it was"""
    try:
        now = os.lstat(path)
        if not stat.S_ISREG(now.st_mode) or (now.st_ino, now.st_dev, now.st_size) != (info.st_ino, info.st_dev, info.st_size):
            return False
        os.unlink(path)
        return True
    except OSError:
        return False


def outbox_files(state):
    """(the new files, the failing ones) of the outbox, by name; the failing ones are kept in the state"""
    st = state.get('xgs')
    failing = st.get('outbox_failing') if isinstance(st.get('outbox_failing'), dict) else {}
    if not os.path.isdir(XGS_OUTBOX):
        st.pop('outbox_failing', None)
        return [], []
    names = sorted(n for n in os.listdir(XGS_OUTBOX) if n.endswith('.json'))
    st['outbox_failing'] = failing = {n: t for n, t in failing.items() if n in names}
    return [n for n in names if n not in failing], [n for n in names if n in failing]


def collect_xgs_outbox(settings, state, now, send, names):
    """(a) one JSON file per alert - {"source", "kind", "at", "subject", "text", "facts"} - taken and
    removed once a channel has it; kept while every channel fails and tried again each minute,
    silently, and dropped after 24 hours. A file is removed only when it was sent or is 24 hours
    old: one held at the collector's cap waits for the next minute. A retry is tried only while the
    cap leaves room (collect_xgs() runs the new files and the retries apart)."""
    if not names:
        return
    failing = state.get('xgs').setdefault('outbox_failing', {})
    for name in names:
        path = os.path.join(XGS_OUTBOX, name)
        shown = nr.no_surrogates(name)      # a name that is not UTF-8 holds surrogates (Python's surrogateescape)
        item, info = read_outbox(path)
        if info is None:
            continue
        mtime = info.st_mtime
        usable = isinstance(item, dict) and bool(item.get('subject') or item.get('text'))
        retry = name in failing
        if usable and send and channels_set(settings) and (not retry or room(state)):
            # each file on its own, as each anomaly is: one that raises (its record is not what it
            # should be) is kept, as a failure, and stops neither the files after it nor the collector
            try:
                facts = item.get('facts') if isinstance(item.get('facts'), dict) else {}
                facts = dict(facts, source=str(item.get('source') or ''))
                results = notify(settings, state, str(item.get('kind') or 'xgs'), name,
                                 str(item.get('subject') or item.get('text'))[:300], str(item.get('text') or item.get('subject')),
                                 facts, at=time_of(item.get('at'), mtime), now=now, quiet=0, priority='high',
                                 tags=['warning'], record=retried(retry), defer=True)
            except Exception as exc:
                nr.log(f'{XGS_OUTBOX}/{shown} could not be sent: {exc}')
                results = None
            if was_sent(results):
                failing.pop(name, None)
                remove_same(path, info)
                continue
            if not waits(results):
                failing.setdefault(name, now)
        if now - mtime >= OUTBOX_MAX_AGE:
            failing.pop(name, None)
            if remove_same(path, info):
                dropped(str(item.get('subject') or shown) if isinstance(item, dict) else shown,
                        f'{XGS_OUTBOX}/{shown} dropped: not sent within 24 hours')


PENDING_MAX = 1000              # anomalies kept for a retry at most


def send_anomaly(settings, state, rec, now, was_failing):
    """one anomaly to the channels: SENT, HELD (past the collector's cap, not tried) or 'failed'"""
    t = nr.texts(settings.get('language'))
    at = time_of(rec.get('at'), now)
    kind, host = str(rec.get('kind') or 'anomaly'), str(rec.get('host') or settings.hostname())
    source = str(rec.get('source') or 'os-xgs-npu')
    # the anomaly's kind (sent, received, opened, scan, sweep...) is a fact, not a subject
    results = notify(settings, state, 'anomaly', f'{source}|{rec["id"]}', subject_of(t, settings, 'xgs_anomaly_subject', host=host),
                     t['xgs_anomaly_text'].format(source=source, time=local_time(at), message=str(rec.get('message') or '')),
                     {'id': rec['id'], 'kind': kind, 'host': host, 'source': source}, at=at, now=now, quiet=0,
                     priority='high', tags=['warning'], record=retried(was_failing), defer=True)
    return SENT if was_sent(results) else HELD if waits(results) else 'failed'


def without(items, item):
    """items without this one (the very object: two anomalies may be equal)"""
    items[:] = [x for x in items if x is not item]


def try_anomaly(settings, state, entry, now, was_failing):
    """send_anomaly() for one pending entry; an anomaly that raises (its record is not what it should
    be) stays pending, as a failure, and stops neither the others nor the collector"""
    try:
        return send_anomaly(settings, state, entry['rec'], now, was_failing)
    except Exception as exc:
        nr.log(f'anomaly {entry["rec"].get("id")} could not be sent: {exc}')
        return 'failed'


def collect_xgs_anomaly(settings, state, now, send, first):
    """(b) one JSON object a line - {"id", "at", "host", "kind", "message", "source"} - "id" counting up
    from 1: what is above the last id sent is sent; a file whose ids are all below it was started again.
    An anomaly not sent - no channel took it, or the collector's cap held it - is kept pending and tried
    again each minute (a failed one silently, as the outbox's files are; retry_anomalies()), and
    dropped after 24 hours. Returns the anomalies pending before this run, for retry_anomalies().

    The last id moves, and the anomaly goes into the pending list, one anomaly at a time; the state
    is saved so before it is sent, and again once it is, out of the list. So a record that cannot
    be sent loses none after it, and one a run was killed sending is tried again, after the new
    ones; while the state cannot be saved (a full /var), none is sent (can_keep())."""
    st = state.get('xgs')
    pending = [p for p in st.get('pending') or [] if isinstance(p, dict) and isinstance(p.get('rec'), dict)]
    for p in pending:
        p['rec'] = nr.no_surrogates(p['rec'])      # one kept by an older version may hold a lone surrogate
    st['pending'] = pending
    old = list(pending)
    try:
        with open(XGS_ANOMALY, encoding='utf-8', errors='replace') as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = None
    if lines is not None:
        records = []
        for line in lines:
            try:
                # cleaned of lone surrogates once, here, as an outbox file is (read_outbox())
                rec = nr.no_surrogates(json.loads(line))
            except (ValueError, RecursionError):
                continue
            if isinstance(rec, dict) and isinstance(rec.get('id'), int) and not isinstance(rec.get('id'), bool):
                records.append(rec)
        top = max((r['id'] for r in records), default=0)
        last = st.get('last_id')
        if first:
            st['last_id'] = top
        else:
            last = last if isinstance(last, int) else 0
            if top < last:
                last = 0                    # the file was started again
            st['last_id'] = last
            for rec in sorted(records, key=lambda r: r['id']):
                if rec['id'] <= st['last_id']:
                    continue
                if send and state.unsaved:
                    break                   # the state cannot be saved: the rest waits for a run that can
                st['last_id'] = rec['id']
                if not send:
                    continue
                entry = {'rec': rec, 'since': now, 'failed': False}
                pending.append(entry)
                if may_hand_on(state) and channels_set(settings) and \
                        not can_keep(state, f'{XGS_ANOMALY} id {rec["id"]}', first=True):
                    break                   # pending, unsent: it goes when the state can be saved
                result = try_anomaly(settings, state, entry, now, False)
                if result == SENT:
                    without(pending, entry)
                    save_or_log(state, f'{XGS_ANOMALY} id {rec["id"]}')
                else:
                    entry['failed'] = result != HELD
    return old


def retry_anomalies(settings, state, now, send, old):
    """The anomalies pending before this run, tried again while the cap leaves room; then those 24
    hours old dropped, and the oldest past PENDING_MAX - only where the state can be saved: a drop it
    cannot keep would be made, and said in the history and the system log, again each minute."""
    pending = state.get('xgs').setdefault('pending', [])
    for p in old:
        if send and channels_set(settings) and may_hand_on(state) and can_keep(state, XGS_ANOMALY):
            result = try_anomaly(settings, state, p, now, p.get('failed', True))
            if result == SENT:
                without(pending, p)
                save_or_log(state, f'{XGS_ANOMALY} id {p["rec"].get("id")}')
                continue
            p['failed'] = p.get('failed', True) or result != HELD
    still = {id(p) for p in pending}
    expired = [p for p in old if id(p) in still and now - (p.get('since') or now) >= OUTBOX_MAX_AGE]
    if (expired or len(pending) - len(expired) > PENDING_MAX) and not can_keep(state, XGS_ANOMALY):
        return
    for p in expired:
        without(pending, p)
    # one line in the history however many (it keeps 500): a single one by its id, as before
    ids = [str(p['rec'].get('id')) for p in expired]
    if len(ids) == 1:
        dropped(f'{XGS_ANOMALY} id {ids[0]}', f'{XGS_ANOMALY} id {ids[0]} dropped: not sent within 24 hours')
    elif ids:
        shown = ', '.join(ids[:HELD_SHOWN]) + (', …' if len(ids) > HELD_SHOWN else '')
        dropped(f'{XGS_ANOMALY}: {len(ids)} anomalies dropped',
                f'{XGS_ANOMALY}: {len(ids)} anomalies dropped, not sent within 24 hours: ids {shown}')
    over = len(pending) - PENDING_MAX
    if over > 0:
        # the oldest go: said once, with how many, in the system log and the history
        del pending[:over]
        detail = f'{XGS_ANOMALY}: {over} anomalies dropped unsent, the oldest: more than {PENDING_MAX} were waiting'
        nr.log(detail)
        dropped(f'{XGS_ANOMALY}: {over} anomalies dropped', detail)


def collect_xgs(settings, state, now):
    first = state.first('xgs')
    state.get('xgs')
    send = wanted(settings, 'xgs_alert')
    # what is new before any retry, so that retries that keep failing cannot take the cap every
    # minute: the new files, the new anomalies, then the files and the anomalies tried again
    new_files, failing_files = outbox_files(state)
    collect_xgs_outbox(settings, state, now, send, new_files)
    old = collect_xgs_anomaly(settings, state, now, send, first)
    collect_xgs_outbox(settings, state, now, send, failing_files)
    retry_anomalies(settings, state, now, send, old)


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


def run_collectors(settings, state, now, clock=time.monotonic):
    """One pass of the collectors, each on its own.

    - A pass more than STALE_AFTER after the last one (the plugin was off, the firewall was down):
      the log readers start again from the end of their logs, as on a first run, so a backlog is not
      sent; and each reads only lines of the last STALE_AFTER seconds anyway.
    - A collector hands on at most COLLECTOR_CAP alerts a run; the rest are one line in the history,
      and one more alert says how many.
    - Past PASS_DEADLINE seconds, the collectors not yet run wait for the next minute (their places
      do not move).
    """
    last = state.data.get('last_pass')
    if isinstance(last, (int, float)) and now - last > STALE_AFTER:
        for name in LOG_READERS:
            st = state.data.get(name)
            if isinstance(st, dict) and isinstance(st.get('log'), dict):
                st['log'].pop('path', None)
    started = clock()
    state.slow = set()
    state.past_deadline = lambda: clock() - started > PASS_DEADLINE
    t = nr.texts(settings.get('language'))
    for name, collect in COLLECTORS:
        if clock() - started > PASS_DEADLINE:
            nr.log(f'alert collectors took more than {PASS_DEADLINE} s: {name} and the ones after it wait for the next minute')
            break
        state.running, state.handed, state.held, state.held_subjects = name, 0, 0, []
        try:
            collect(settings, state, now)
        except Exception as exc:
            nr.log(f'alert collector {name} failed: {exc}')
        held, state.running = state.held, None
        if held:
            held_line(subject_of(t, settings, 'more_subject', n=held), held, state.held_subjects)
            try:
                notify(settings, state, name, f'more|{int(now)}', subject_of(t, settings, 'more_subject', n=held),
                       t['more_text'].format(n=held, max=COLLECTOR_CAP), {'collector': name, 'held': held}, now=now,
                       quiet=0, priority='high', tags=['warning'])
            except Exception as exc:
                nr.log(f'alert collector {name}: the summary alert failed: {exc}')
    state.past_deadline = None
    state.data['last_pass'] = now
    save_or_log(state, 'alert collectors')


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
