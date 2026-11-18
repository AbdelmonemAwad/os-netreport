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

Network report for OPNsense, mailed as HTML in any of the GUI languages (texts in i18n/<locale>.json).

  netreport.py scheduler        run from cron every minute: send due reports, run the alert collectors
                                (alerts.py), watch for new devices
  netreport.py send <uuid>      send one schedule now (prints JSON)
  netreport.py preview <uuid>   print the rendered report
  netreport.py testmail         send a short test message (prints JSON)
  netreport.py history          print the send history (JSON, newest first)
  netreport.py view <file>      print an archived report

Data sources: vnstat (volume), dpinger (gateways), Unbound query database (DNS and blocklists),
Suricata eve.json, CrowdSec, NetFlow aggregates (per device usage), ARP and host discovery
(devices), system counters and logs. Settings live in config.xml under OPNsense/NetReport.
"""

import calendar
import datetime
import fcntl
import glob
import gzip
import html
import ipaddress
import json
import os
import re
import smtplib
import ssl
import subprocess
import sys
import syslog
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

CONFIG = '/conf/config.xml'
STATE_DIR = '/var/db/netreport'
STATE_FILE = os.path.join(STATE_DIR, 'state.json')
DEVICES_FILE = os.path.join(STATE_DIR, 'devices.json')
HISTORY_FILE = os.path.join(STATE_DIR, 'history.json')
INFECTED_FILE = os.path.join(STATE_DIR, 'infected.json')     # written by alerts.py, its format there
ARCHIVE_DIR = os.path.join(STATE_DIR, 'archive')
LOCK_FILE = '/var/run/netreport.lock'
CATCH_UP = 12 * 3600            # send a missed report up to 12 hours late (firewall was off or rebooting)
DEVICE_SCAN_MINUTES = 5
HISTORY_MAX = 500

ALL_SECTIONS = ['summary', 'internet', 'connection', 'vpn', 'dns', 'web', 'security', 'apps', 'devices', 'mail', 'system']

UNBOUND_DB = '/var/unbound/data/unbound.duckdb'
# os-postfix logs through syslog-ng's local filter "postfix", which OPNsense writes like every local filter
# (the plan's phase 0, 2026-11-16)
POSTFIX_LOGS = '/var/log/postfix/postfix_*.log'
# a WireGuard peer is online for 300 s after its last handshake: OPNsense's own rule (VPN: WireGuard: Status)
WG_ONLINE = 300
# where os-ntopng's web interface answers on the firewall itself when the setting is empty
NTOPNG_URL = 'http://127.0.0.1:3000'
NTOPNG_BIN = '/usr/local/bin/ntopng'
# how long one report may spend reading Suricata's log for its Applications section
EVE_SCAN_SECONDS = 60
EVE_LOGS = '/var/log/suricata/eve.json*'

# ---------------------------------------------------------------- texts

I18N_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'i18n')
RTL = ('ar', 'fa', 'he', 'ur')
_catalogs = {}


def system_language():
    try:
        return ET.parse(CONFIG).getroot().findtext('./system/language') or 'en_US'
    except Exception:
        return 'en_US'


def texts(lang):
    """report texts for a locale (e.g. de_DE), English for anything a catalog lacks"""
    lang = {'ar': 'ar_SA', 'en': 'en_US'}.get(lang, lang)
    if not lang or lang == 'default':
        lang = system_language()
    if lang not in _catalogs:
        catalog = dict(load_json(os.path.join(I18N_DIR, 'en_US.json'), {}))
        if re.match(r'^[a-z]{2}_[A-Z]{2}$', lang):
            catalog.update({k: v for k, v in load_json(os.path.join(I18N_DIR, f'{lang}.json'), {}).items() if v})
        catalog['dir'] = 'rtl' if lang.split('_')[0] in RTL else 'ltr'
        catalog['lang'] = lang.replace('_', '-')
        _catalogs[lang] = catalog
    return _catalogs[lang]


# ---------------------------------------------------------------- helpers

def run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ''


def esc(s):
    return html.escape(str(s))


def human_bytes(n):
    """e.g. 38.4 GB, wrapped in unicode isolates so right-to-left text keeps the unit after the number"""
    n = float(n or 0)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(n) < 1000:
            text = f'{int(n)} B' if unit == 'B' else f'{n:.1f} {unit}'
            break
        n /= 1000
    else:
        text = f'{n:.1f} PB'
    return f'⁦{text}⁩'


def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path, data):
    """Write JSON whole: a temporary file of its own in the same folder, renamed over the file. Its
    own, so that the scheduler and a page action writing at the same time cannot fail each other."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            # ASCII: a lone surrogate (a \ud800 escape in a record read) stays an escape; in UTF-8
            # it could not be written, and the file would never be saved again
            json.dump(data, fh, indent=1, ensure_ascii=True)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def no_surrogates(value):
    """value with every string in it - the keys of a dict too, through dicts and lists - made one that
    UTF-8 can carry: a lone surrogate (a \\ud800 escape in JSON that was read) becomes "?". A mail's
    headers and body, the system log and the history page cannot take one."""
    if isinstance(value, str):
        return value.encode('utf-8', 'replace').decode('utf-8')
    if isinstance(value, dict):
        return {no_surrogates(k): no_surrogates(v) for k, v in value.items()}
    if isinstance(value, list):
        return [no_surrogates(v) for v in value]
    return value


def log(msg):
    syslog.openlog('netreport', facility=syslog.LOG_USER)
    syslog.syslog(syslog.LOG_NOTICE, msg)


def csv_list(value):
    return [v.strip() for v in (value or '').split(',') if v.strip()]


def line_time(line):
    """timestamp of an RFC 5424 syslog line, or None"""
    m = re.match(r'<\d+>1 (\S+)', line)
    if not m:
        return None
    try:
        return datetime.datetime.fromisoformat(m.group(1)).timestamp()
    except ValueError:
        return None


# ---------------------------------------------------------------- settings

class Settings:
    DEFAULTS = {
        'enabled': '1', 'title': 'Home network', 'recipients': '', 'language': 'default', 'mail_source': 'monit',
        'smtp_port': '465', 'smtp_security': 'ssl', 'smtp_auth': '1', 'wan_interface': 'wan', 'lan_interface': 'lan',
        'vpn_interfaces': '', 'new_device_alert': '1', 'temp_warn': '75', 'disk_warn': '85', 'loss_warn': '5',
        'backup_warn': '2', 'monthly_cap': '0', 'keep_days': '90',
        # alerts (alerts.py): all on by default; a channel is used once it is set
        'alerts': '1', 'alert_mail': '1', 'gateway_alert': '1', 'login_alert': '1', 'login_fail_count': '5',
        'ips_alert': '1', 'ips_severity': '1', 'vpn_alert': '1', 'watchdog_alert': '1', 'c2_alert': '1',
        'xgs_alert': '1',
    }

    def __init__(self):
        self.root = ET.parse(CONFIG).getroot()
        node = self.root.find('./OPNsense/NetReport')
        self.general = dict(self.DEFAULTS)
        self.schedules = {}
        if node is None:
            return
        general = node.find('general')
        for child in (list(general) if general is not None else []):
            if (child.text or '').strip() != '' or child.tag in ('recipients', 'vpn_interfaces'):
                self.general[child.tag] = (child.text or '').strip()
        for item in node.findall('./schedules/schedule'):
            sched = {c.tag: (c.text or '').strip() for c in item}
            sched['uuid'] = item.get('uuid')
            self.schedules[sched['uuid']] = sched

    def get(self, key):
        return self.general.get(key, '')

    def num(self, key):
        try:
            return int(self.general.get(key) or self.DEFAULTS.get(key) or 0)
        except ValueError:
            return 0

    def device(self, ifname):
        return self.root.findtext(f'./interfaces/{ifname}/if') or ''

    def descr(self, ifname):
        return self.root.findtext(f'./interfaces/{ifname}/descr') or ifname.upper()

    def lan(self):
        """(device, network, firewall address) of the local network"""
        name = self.get('lan_interface') or 'lan'
        ip = self.root.findtext(f'./interfaces/{name}/ipaddr') or ''
        bits = self.root.findtext(f'./interfaces/{name}/subnet') or '24'
        try:
            net = ipaddress.ip_network(f'{ip}/{bits}', strict=False)
        except ValueError:
            net = ipaddress.ip_network('192.168.1.0/24')
            ip = ''
        return self.device(name), net, ip

    def hostname(self):
        host = self.root.findtext('./system/hostname') or 'OPNsense'
        domain = self.root.findtext('./system/domain') or ''
        return f'{host}.{domain}' if domain else host


# ---------------------------------------------------------------- scheduling

def parse_time(value):
    try:
        hh, mm = value.split(':')
        return int(hh), int(mm)
    except Exception:
        return 8, 0


def last_occurrence(sched, moment):
    """most recent scheduled send time at or before moment"""
    hh, mm = parse_time(sched.get('send_time', '08:00'))
    base = moment.replace(hour=hh, minute=mm, second=0, microsecond=0)
    freq = sched.get('frequency', 'daily')
    if freq == 'weekly':
        days = {int(d) for d in csv_list(sched.get('weekdays')) if d.isdigit()} or {0}
        for back in range(0, 8):
            cand = base - datetime.timedelta(days=back)
            # config uses 0 = Sunday, python weekday() uses 0 = Monday
            if cand <= moment and (cand.weekday() + 1) % 7 in days:
                return cand
    elif freq == 'monthly':
        year, month = moment.year, moment.month
        for _ in range(3):
            last = calendar.monthrange(year, month)[1]
            md = sched.get('monthday') or '1'
            day = last if md == 'last' else min(int(md), last)
            cand = datetime.datetime(year, month, day, hh, mm)
            if cand <= moment:
                return cand
            month -= 1
            if month == 0:
                month, year = 12, year - 1
    return base if base <= moment else base - datetime.timedelta(days=1)


def report_window(sched, end):
    """(start, end) of the period one report covers"""
    period = sched.get('period', 'auto')
    day = datetime.timedelta(days=1)
    if period == 'day':
        return end - day, end
    if period == 'week':
        return end - 7 * day, end
    if period == 'month':
        return end - 30 * day, end
    if period == 'prev_month':
        first = end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return (first - day).replace(day=1), first
    if period == 'mtd':
        return end.replace(day=1, hour=0, minute=0, second=0, microsecond=0), end
    # since the previous scheduled report
    occ = last_occurrence(sched, end)
    prev = last_occurrence(sched, occ - datetime.timedelta(minutes=1))
    return end - (occ - prev), end


def period_label(sched, start, end, t):
    if sched.get('period') == 'prev_month':
        return f"{t['months'][start.month - 1]} {start.year}"
    if sched.get('period') == 'mtd':
        return t['mtd']
    hours = round((end - start).total_seconds() / 3600)
    if hours == 24:
        return t['last_24h']
    if hours == 168:
        return t['last_7d']
    if hours == 720:
        return t['last_30d']
    if hours % 24 == 0:
        return t['last_nd'].format(n=hours // 24)
    return t['last_nh'].format(n=hours)


# ---------------------------------------------------------------- data collection

def hostnames(settings):
    """ip -> name from dnsmasq static hosts, DHCP reservations and leases"""
    names = {'127.0.0.1': 'OPNsense', '::1': 'OPNsense'}
    lan_ip = settings.lan()[2]
    if lan_ip:
        names[lan_ip] = 'OPNsense'
    for h in settings.root.iter('hosts'):
        ip, host = h.findtext('ip'), h.findtext('host')
        if ip and host:
            for one in ip.split(','):
                names[one.strip()] = host
    for path in ('/var/db/dnsmasq.leases',):
        if os.path.exists(path):
            for line in open(path, errors='ignore'):
                parts = line.split()
                if len(parts) >= 4 and parts[3] != '*' and parts[2].count('.') == 3:
                    names.setdefault(parts[2], parts[3])
    return names


def label(ip, names):
    return f'{names[ip]} ({ip})' if ip in names else ip


def vnstat_volume(dev, start, end):
    out = {'rx': 0, 'tx': 0, 'ok': False}
    if not dev:
        return out
    s, e = start.timestamp(), end.timestamp()
    hourly = (e - s) <= 3 * 86400 and time.time() - s <= 3.5 * 86400
    table, key = ('h', 'hour') if hourly else ('d', 'day')
    try:
        data = json.loads(run(f'vnstat -i {dev} --json {table}'))
        for row in data['interfaces'][0]['traffic'].get(key, []):
            ts = row.get('timestamp', 0)
            if s <= ts < e:
                out['rx'] += row['rx']
                out['tx'] += row['tx']
        out['ok'] = True
    except Exception:
        pass
    return out


def vnstat_month(dev):
    try:
        data = json.loads(run(f'vnstat -i {dev} --json m 1'))
        row = data['interfaces'][0]['traffic']['month'][-1]
        return row['rx'], row['tx']
    except Exception:
        return 0, 0


def gateway_status():
    rows = []
    try:
        data = json.loads(run('pluginctl -r return_gateways_status'))
        for name, g in data.get('dpinger', data).items():
            if isinstance(g, dict):
                rows.append({'name': name, 'status': g.get('status', '?'),
                             'delay': g.get('delay', '~'), 'loss': g.get('loss', '~')})
    except Exception:
        pass
    return rows


def system_logs(start):
    """system log files that may hold lines newer than start"""
    since = datetime.datetime.fromtimestamp(start).date() - datetime.timedelta(days=1)
    for path in sorted(glob.glob('/var/log/system/system_*.log')):
        m = re.search(r'_(\d{8})\.log$', path)
        if m and datetime.datetime.strptime(m.group(1), '%Y%m%d').date() < since:
            continue
        yield path


def gateway_events(start, end):
    s, e = start.timestamp(), end.timestamp()
    events = Counter()
    for path in system_logs(s):
        for line in open(path, errors='ignore'):
            if 'dpinger' not in line or 'alarm' not in line.lower():
                continue
            ts = line_time(line)
            if ts is None or not s <= ts < e:
                continue
            gw = re.search(r'GATEWAY ALARM: (\S+)', line)
            events[gw.group(1) if gw else '?'] += 1
    return events


def dns_stats(start, end, top_n):
    res = {'total': 0, 'blocked': 0, 'top_blocked': [], 'top_clients': [], 'ok': False}
    s, e = int(start.timestamp()), int(end.timestamp())
    code = f'''
import duckdb, json
c = duckdb.connect('/var/unbound/data/unbound.duckdb', read_only=True)
q = lambda s: c.execute(s).fetchall()
w = "time >= {s} and time < {e}"
out = {{'ok': True}}
out['total'] = q("select count(*) from query where " + w)[0][0]
out['blocked'] = q("select count(*) from query where " + w + " and action = 1")[0][0]
out['top_blocked'] = q("select domain, count(*) n from query where " + w + " and action = 1 group by domain order by n desc limit {int(top_n)}")
out['top_clients'] = q("select client, count(*) n from query where " + w + " group by client order by n desc limit {int(top_n)}")
print(json.dumps(out))
'''
    try:
        raw = subprocess.run(['/usr/local/bin/python3', '-c', code], capture_output=True, text=True,
                             timeout=120, cwd='/usr/local/opnsense/scripts/unbound').stdout
        res.update(json.loads(raw))
    except Exception:
        pass
    return res


def local_networks():
    """Every network this firewall is directly attached to.

    Read from the machine rather than from a setting, because the answer changes when an
    interface does, and a stale answer here would put a device's own traffic in the column
    headed "somebody is attacking you".
    """
    nets = []
    for line in run('/sbin/ifconfig -a').splitlines():
        found = re.search(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)', line)
        if found:
            try:
                bits = bin(int(found.group(2), 16)).count('1')
                nets.append(ipaddress.ip_network('%s/%d' % (found.group(1), bits), strict=False))
            except Exception:
                pass
            continue
        # IPv6 too, so that a device using it counts as one of ours; never the link-local
        # networks (every interface has fe80::/10) or the loopback
        found = re.search(r'inet6 ([0-9A-Fa-f:.]+)(?:%\S+)? prefixlen (\d+)', line)
        if not found:
            continue
        try:
            net = ipaddress.ip_network('%s/%s' % (found.group(1), found.group(2)), strict=False)
        except Exception:
            continue
        if net.network_address.is_link_local or net.network_address.is_loopback:
            continue
        nets.append(net)
    return nets


def started_inside(address, nets):
    """Whether the address that opened a flow is one of ours.

    On a firewall watching its WAN, a connection a LAN device opened arrives with the
    firewall's own outside address as the flow source, because NAT has already happened.
    On a firewall watching a LAN interface it arrives with the device's own address. Both
    are covered by asking whether the address sits in a network this machine is attached
    to - which is why the test is by network and not by a list of addresses.
    """
    if not address:
        return False
    try:
        value = ipaddress.ip_address(address)
    except Exception:
        return False
    return any(value in net for net in nets)


def suricata_alerts(start, end, top_n):
    s, e = start.timestamp(), end.timestamp()
    sigs, srcs = Counter(), Counter()
    out_sigs, out_hosts = Counter(), Counter()
    total = severe = inbound = inbound_severe = out_total = out_severe = 0
    nets = local_networks()
    for path in sorted(glob.glob('/var/log/suricata/eve.json*')):
        if os.path.getmtime(path) < s:
            continue
        opener = gzip.open if path.endswith('.gz') else open
        try:
            with opener(path, 'rt', errors='ignore') as fh:
                for line in fh:
                    if '"event_type":"alert"' not in line:
                        continue
                    try:
                        ev = json.loads(line)
                        stamp = re.sub(r'([+-]\d\d)(\d\d)$', r'\1:\2', ev['timestamp'])
                        ts = datetime.datetime.fromisoformat(stamp).timestamp()
                    except Exception:
                        continue
                    if not s <= ts < e:
                        continue
                    total += 1
                    grave = ev['alert'].get('severity', 3) == 1
                    if grave:
                        severe += 1

                    # flow.src_ip is the address that OPENED the conversation, which is
                    # not the source of the packet the rule matched. A reply arriving
                    # from outside, on a connection this network made, reads as inbound
                    # by src_ip and as ours by this. Where a record carries no flow
                    # object the question cannot be answered, and falling back to src_ip
                    # is the only honest thing left.
                    opener = (ev.get('flow') or {}).get('src_ip') or ev.get('src_ip')
                    if started_inside(opener, nets):
                        out_total += 1
                        out_sigs[ev['alert'].get('signature', '?')] += 1
                        out_hosts[opener or '?'] += 1
                        if grave:
                            out_severe += 1
                        continue

                    inbound += 1
                    if grave:
                        inbound_severe += 1
                    sigs[ev['alert'].get('signature', '?')] += 1
                    srcs[ev.get('src_ip', '?')] += 1
        except Exception:
            pass
    return {'total': total, 'severe': severe,
            'inbound': inbound, 'inbound_severe': inbound_severe,
            'out_total': out_total, 'out_severe': out_severe,
            'sigs': sigs.most_common(top_n), 'srcs': srcs.most_common(top_n),
            'out_sigs': out_sigs.most_common(top_n),
            'out_hosts': out_hosts.most_common(top_n)}


def crowdsec(start):
    out = {'alerts': 0, 'bans': 0, 'ok': os.path.exists('/usr/local/bin/cscli')}
    if not out['ok']:
        return out
    hours = max(1, int((time.time() - start.timestamp()) // 3600) + 1)
    try:
        out['alerts'] = len(json.loads(run(f'cscli alerts list --since {hours}h -o json') or '[]') or [])
    except Exception:
        pass
    try:
        decisions = json.loads(run('cscli decisions list -a -o json', timeout=120) or '[]') or []
        out['bans'] = sum(len(a.get('decisions') or []) for a in decisions)
    except Exception:
        pass
    return out


def scan_devices(settings):
    """devices on the local network right now: mac -> ip, plus mac -> vendor"""
    lan_dev, lan_net, fw_ip = settings.lan()
    active = {}
    for m in re.finditer(r'\(([\d.]+)\) at ([0-9a-f:]{17})', run(f'arp -an -i {lan_dev}' if lan_dev else 'arp -an')):
        ip, mac = m.group(1), m.group(2)
        try:
            if ip != fw_ip and ipaddress.ip_address(ip) in lan_net:
                active[mac] = ip
        except ValueError:
            pass
    vendors = {}
    try:
        for row in json.loads(run('configctl hostwatch dump_full', timeout=30) or '{}').get('rows', []):
            if len(row) > 3 and row[3]:
                vendors[row[1]] = row[3]
    except Exception:
        pass
    return active, vendors


def update_devices(settings):
    """merge the devices seen now into the device database; returns (database, new macs, active)"""
    db = load_json(DEVICES_FILE, None)
    # the first scan only records what is there, it does not report every device as new
    baseline = db is None
    if db is None:
        db = {}
    active, vendors = scan_devices(settings)
    names = hostnames(settings)
    now = time.time()
    new = []
    for mac, ip in active.items():
        entry = db.get(mac)
        if entry is None:
            entry = db[mac] = {'first_seen': now}
            if not baseline:
                new.append(mac)
        entry['ip'] = ip
        entry['last_seen'] = now
        entry['name'] = names.get(ip) or entry.get('name', '')
        if vendors.get(mac):
            entry['vendor'] = vendors[mac]
    save_json(DEVICES_FILE, db)
    return db, new, active


def top_talkers(settings, start, end, top_n):
    """per device download/upload from NetFlow on the LAN interface.

    The aggregator keys egress flows ("out", firewall -> device) by the device address,
    so on the LAN side "out" is what the device downloaded and "in" is what it sent.
    """
    lan_dev, lan_net, fw_ip = settings.lan()
    down, up = defaultdict(int), defaultdict(int)
    raw = run(f'/usr/local/bin/python3 /usr/local/opnsense/scripts/netflow/get_top_usage.py '
              f'--provider FlowSourceAddrTotals --start_time {int(start.timestamp())} '
              f'--end_time {int(end.timestamp())} --key_fields src_addr,direction --value_field octets '
              f'--filter if={lan_dev} --max_hits 500', timeout=120)
    try:
        rows = json.loads(raw)
    except Exception:
        rows = []
    for row in rows:
        ip = row.get('src_addr') or ''
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr not in lan_net or ip in (fw_ip, str(lan_net.broadcast_address)):
            continue
        (down if row.get('direction') == 'out' else up)[ip] += int(row.get('total', 0))
    ranked = sorted(set(down) | set(up), key=lambda ip: -(down[ip] + up[ip]))[:top_n]
    return [(ip, down[ip], up[ip]) for ip in ranked]


# ---------------------------------------------------------------- VPN, mail, applications, web activity

def num(value):
    """a count from a service's JSON (some give numbers as strings), 0 for anything else"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def vpn_sessions(settings, now, answers=None):
    """Who is connected now, from the actions OPNsense's own status pages call: a list of
    (service, connection, user, address, since or None, traffic in bytes), the traffic as each service
    counts it - IPsec its associations, OpenVPN its encrypted link, WireGuard its transfer.

    IPsec: one row per established IKE session (a road warrior is one each), its user the EAP or XAuth
    identity or else the remote identity, its address the virtual one it was given or else its own.
    OpenVPN: each client of a server instance. WireGuard: each peer whose last handshake is at most
    WG_ONLINE seconds old, by the name its configuration gives its key; WireGuard keeps no start time."""
    import alerts
    rows = []
    if answers is None:
        answers = alerts.vpn_answers()
    ipsec = answers.get('ipsec')
    for cid, conn in (ipsec.items() if isinstance(ipsec, dict) else []):
        if not isinstance(conn, dict):
            continue
        name = alerts.description(settings, cid) or str(conn.get('remote-addrs') or cid)
        for sa in conn.get('sas') or []:
            if not isinstance(sa, dict) or str(sa.get('state', '')).upper() != 'ESTABLISHED':
                continue
            children = sa.get('child-sas')
            children = children.values() if isinstance(children, dict) else children if isinstance(children, list) else []
            traffic = sum(num(c.get('bytes-in')) + num(c.get('bytes-out')) for c in children if isinstance(c, dict))
            vips = sa.get('remote-vips') if isinstance(sa.get('remote-vips'), list) else []
            user = sa.get('remote-eap-id') or sa.get('remote-xauth-id') or sa.get('remote-id') or '?'
            age = sa.get('established')
            since = now - num(age) if age is not None and str(age).isdigit() else None
            rows.append(('IPsec', name, str(user), str(vips[0] if vips else sa.get('remote-host') or ''), since, traffic))
    ovpn = answers.get('ovpn')
    if isinstance(ovpn, dict):
        configured = alerts.openvpn_instances(settings)
        servers = ovpn.get('server') if isinstance(ovpn.get('server'), dict) else {}
        for iid, inst in sorted(servers.items()):
            if not isinstance(inst, dict):
                continue
            name = configured.get(iid, (None, ''))[1] or alerts.description(settings, iid) or iid
            for client in inst.get('client_list') or []:
                if not isinstance(client, dict):
                    continue
                user = client.get('username')
                if user in (None, '', 'UNDEF'):
                    user = client.get('common_name') or '?'
                start = num(client.get('connected_since__time_t_'))
                rows.append(('OpenVPN', name, str(user), str(client.get('virtual_address') or client.get('real_address') or ''),
                             start or None, num(client.get('bytes_received')) + num(client.get('bytes_sent'))))
    wg = answers.get('wg')
    if isinstance(wg, dict) and wg.get('status') == 'ok':
        peers = {}
        for item in settings.root.iter('client'):
            if item.findtext('pubkey'):
                peers[item.findtext('pubkey').strip()] = (item.findtext('name') or '').strip()
        for rec in wg.get('records') or []:
            if not isinstance(rec, dict) or rec.get('type') != 'peer':
                continue
            handshake = num(rec.get('latest-handshake'))
            if not handshake or now - handshake > WG_ONLINE:
                continue
            key = str(rec.get('public-key') or '')
            rows.append(('WireGuard', str(rec.get('if') or ''), peers.get(key) or key[:8] + '…',
                         str(rec.get('endpoint') or ''), None, num(rec.get('transfer-rx')) + num(rec.get('transfer-tx'))))
    return rows


def vpn_outages(log, key, s, e, now):
    """(outages that began in [s, e), seconds down within [s, e)) of one connection, from the tunnel
    watch's log (alerts.py's collect_vpn: a 'down' once a new state has held on two reads, a 'back' the
    same way); a down still running counts up to now"""
    events = sorted((x for x in log if x.get('key') == key and isinstance(x.get('at'), (int, float))),
                    key=lambda x: x['at'])
    down_at = None
    for x in events:
        if x['at'] < s:
            down_at = x['at'] if x.get('event') == 'down' else None
    current = max(down_at, s) if down_at is not None else None
    count = total = 0
    for x in events:
        if not s <= x['at'] < e:
            continue
        if x.get('event') == 'down':
            count += 1
            if current is None:
                current = x['at']
        elif x.get('event') == 'back' and current is not None:
            total += x['at'] - current
            current = None
        elif x.get('event') == 'back' and isinstance(x.get('down'), (int, float)):
            # its down is not in the log (before this version, or dropped by the log's cap): the back says
            # how long it lasted
            began = x['at'] - x['down']
            count += 1 if began >= s else 0
            total += x['at'] - max(s, began)
    if current is not None:
        total += max(0, min(e, now) - current)
    return count, total


def vpn_report(settings, start, end):
    """the tunnels as the alert layer's tunnel watch reads them (alerts.vpn_reads), their outages in the
    period from its log, and the sessions now; None when there is no VPN at all"""
    import alerts
    now = time.time()
    s, e = start.timestamp(), end.timestamp()
    data = load_json(alerts.STATE_FILE, {})
    data = data if isinstance(data, dict) else {}
    entries = data.get('vpn') if isinstance(data.get('vpn'), dict) else {}
    log = [x for x in data.get('vpn_log') or [] if isinstance(x, dict)]
    # the three status actions asked once, for the tunnels and the sessions both
    answers = alerts.vpn_answers()
    reads, _ = alerts.vpn_reads(settings, dict(entries), now, answers)
    tunnels = []
    for key, (name, state) in sorted(reads.items(), key=lambda kv: kv[1][0].lower()):
        # a road warrior's users are its sessions: an OpenVPN server's clients, an IPsec connection open to
        # any address, a WireGuard peer sent no keepalive (alerts.road_warrior); not tunnels of their own
        if alerts.road_warrior(settings, key):
            continue
        entry = entries.get(key) if isinstance(entries.get(key), dict) else {}
        count, down = vpn_outages(log, key, s, e, now)
        if not count and not down and state != 'up' and entry.get('state') == 'down' and entry.get('reported'):
            # down since before the log knows of it (the watch says a down only after an up): its time down
            down = max(0, min(e, now) - max(entry.get('since') or s, s))
        tunnels.append({'name': name, 'up': state == 'up', 'since': entry.get('since') if entry.get('state') == state else None,
                        'outages': count, 'down': down})
    sessions = vpn_sessions(settings, now, answers)
    if not tunnels and not sessions:
        return None
    since = data.get('vpn_log_since')
    return {'tunnels': tunnels, 'sessions': sessions,
            'log_since': since if isinstance(since, (int, float)) and since > s else None}


def mail_stats(start, end, top_n):
    """what the mail server's log (os-postfix) says of the period: messages delivered, deferred and
    bounced (one per recipient, as postfix logs them; a deferred one once, however many times postfix
    tried it again in the period), and connections refused, with the addresses refused most; ok False
    where this firewall keeps no such log"""
    s, e = start.timestamp(), end.timestamp()
    out = {'ok': False, 'sent': 0, 'deferred': 0, 'bounced': 0, 'rejected': 0, 'rejects': []}
    since = datetime.datetime.fromtimestamp(s).date() - datetime.timedelta(days=1)
    rejects, deferred = Counter(), set()
    for path in sorted(glob.glob(POSTFIX_LOGS)):
        out['ok'] = True
        m = re.search(r'_(\d{8})\.log$', path)
        if m and datetime.datetime.strptime(m.group(1), '%Y%m%d').date() < since:
            continue
        try:
            with open(path, errors='ignore') as fh:
                for line in fh:
                    status = re.search(r' status=(sent|deferred|bounced)\b', line)
                    refused = 'NOQUEUE: reject:' in line
                    if not status and not refused:
                        continue
                    ts = line_time(line)
                    if ts is None or not s <= ts < e:
                        continue
                    if status and status.group(1) == 'deferred':
                        message = re.search(r'\] ([0-9A-Za-z]{4,}): to=<([^>]*)>', line)
                        deferred.add(message.groups() if message else line)
                        continue
                    if status:
                        out[status.group(1)] += 1
                        continue
                    out['rejected'] += 1
                    client = re.search(r' from [^\s\[]*\[([0-9A-Fa-f.:]+)\]', line)
                    rejects[client.group(1) if client else '?'] += 1
        except OSError:
            pass
    out['rejects'] = rejects.most_common(top_n)
    out['deferred'] = len(deferred)
    return out


def suricata_apps(start, end, top_n):
    """from Suricata's eve.json in the period: the application protocols it recognised (records with an
    app_proto other than "failed") and the sites named in its TLS (SNI) and HTTP (Host) records; ok False
    where it wrote no TLS or HTTP record and no protocol at all - Intrusion Detection off, or its TLS and
    HTTP logging off. Read for EVE_SCAN_SECONDS at most (the scheduler holds its lock while a report is
    built): partial True when the log was left unread past it."""
    s, e = start.timestamp(), end.timestamp()
    protos, sites = Counter(), Counter()
    deadline, partial = time.monotonic() + EVE_SCAN_SECONDS, False
    for path in sorted(glob.glob(EVE_LOGS)):
        if partial or os.path.getmtime(path) < s:
            continue
        opener = gzip.open if path.endswith('.gz') else open
        try:
            with opener(path, 'rt', errors='ignore') as fh:
                for number, line in enumerate(fh):
                    if number % 10000 == 0 and time.monotonic() > deadline:
                        partial = True
                        break
                    if '"app_proto"' not in line and '"event_type":"tls"' not in line and '"event_type":"http"' not in line:
                        continue
                    try:
                        ev = json.loads(line)
                        stamp = re.sub(r'([+-]\d\d)(\d\d)$', r'\1:\2', ev['timestamp'])
                        ts = datetime.datetime.fromisoformat(stamp).timestamp()
                    except Exception:
                        continue
                    if not s <= ts < e:
                        continue
                    proto = ev.get('app_proto')
                    if proto and proto != 'failed':
                        protos[str(proto)] += 1
                    name = (ev.get('tls') or {}).get('sni') if ev.get('event_type') == 'tls' else \
                        (ev.get('http') or {}).get('hostname') if ev.get('event_type') == 'http' else None
                    if name:
                        sites[str(name).lower().rstrip('.')] += 1
        except Exception:
            pass
    return {'ok': bool(protos or sites), 'protos': protos.most_common(top_n), 'sites': sites.most_common(top_n),
            'partial': partial}


def ntopng_apps(settings, top_n):
    """applications by traffic from os-ntopng's REST API (v2, get/interface/l7/stats.lua) with the API
    token set on the General tab: (rows, None), or ([], why) - None as why when no token is set, or
    when no address is set and os-ntopng is not installed (removed, its token left behind). The figures
    are ntopng's totals since it last started (sinceStartup), of its first interface (ifid 0).
    ntopng's answer is {"rc": 0, "rsp": ...}; its rows are read whether it gives a list of objects
    (label or name, and bytes or value) or an object of name -> bytes."""
    token = settings.get('ntopng_token')
    if not token or (not settings.get('ntopng_url') and not os.path.exists(NTOPNG_BIN)):
        return [], None
    import urllib.parse
    import urllib.request
    base = (settings.get('ntopng_url') or NTOPNG_URL).rstrip('/')
    url = base + '/lua/rest/v2/get/interface/l7/stats.lua?' + urllib.parse.urlencode({'ifid': 0, 'ndpistats_mode': 'sinceStartup'})
    try:
        req = urllib.request.Request(url, headers={'Authorization': 'Token ' + token.strip()})
        context = ssl.create_default_context() if url.startswith('https:') else None
        with urllib.request.urlopen(req, timeout=15, context=context) as answer:
            body = json.loads(answer.read(4 * 1024 * 1024).decode('utf-8', 'replace'))
    except Exception as exc:
        return [], str(getattr(exc, 'reason', None) or exc)[:120]
    if not isinstance(body, dict) or body.get('rc') not in (0, None):
        return [], 'rc %s' % (body.get('rc') if isinstance(body, dict) else '?')
    rsp = body.get('rsp')
    rows = []
    if isinstance(rsp, dict):
        rsp = rsp.get('ndpi') if isinstance(rsp.get('ndpi'), (dict, list)) else rsp
    if isinstance(rsp, list):
        for item in rsp:
            if isinstance(item, dict):
                name = item.get('label') or item.get('name') or item.get('application')
                value = item.get('bytes') if item.get('bytes') is not None else item.get('value')
                if name and isinstance(value, (int, float)):
                    rows.append((str(name), int(value)))
    elif isinstance(rsp, dict):
        for name, value in rsp.items():
            if isinstance(value, dict):
                value = value.get('bytes') if isinstance(value.get('bytes'), (int, float)) else \
                    num((value.get('bytes') or {}).get('sent')) + num((value.get('bytes') or {}).get('rcvd')) \
                    if isinstance(value.get('bytes'), dict) else None
            if isinstance(value, (int, float)):
                rows.append((str(name), int(value)))
    rows.sort(key=lambda r: -r[1])
    return rows[:top_n], (None if rows else 'no applications in its answer')


def hour_ranges(hours):
    """local hours of the day with activity as ranges, e.g. 07–09, 19–23"""
    hours = sorted(set(hours))
    out, i = [], 0
    while i < len(hours):
        j = i
        while j + 1 < len(hours) and hours[j + 1] == hours[j] + 1:
            j += 1
        out.append(f'{hours[i]:02d}' if i == j else f'{hours[i]:02d}–{hours[j]:02d}')
        i = j + 1
    return ', '.join(out)


def web_devices(rows, quarters, top_n):
    """Unbound's (client, domain, action, count) and (client, quarter of an hour) of a period, per device:
    the top_n devices by queries, each with its queries, its 5 domains asked for most (not blocked), its
    blocked queries and the 3 domains blocked most, and the local hours it was active in - from quarters
    of an hour, so that a time zone half an hour off UTC gives the right hour"""
    total, blocked, asked, refused = Counter(), Counter(), defaultdict(Counter), defaultdict(Counter)
    for client, domain, action, n in rows:
        total[client] += n
        if action == 1:
            blocked[client] += n
            refused[client][domain] += n
        else:
            asked[client][domain] += n
    hours = defaultdict(set)
    for client, quarter in quarters:
        hours[client].add(datetime.datetime.fromtimestamp(int(quarter) * 900).hour)
    return [{'client': c, 'queries': n, 'blocked': blocked[c], 'domains': asked[c].most_common(5),
             'blocked_domains': refused[c].most_common(3), 'hours': hour_ranges(hours[c])}
            for c, n in sorted(total.items(), key=lambda kv: (-kv[1], str(kv[0])))[:top_n]]


def web_activity(start, end, top_n):
    """web activity per device from Unbound's query database (Reporting: Unbound DNS, statistics on), in
    two queries over the period (web_devices()); ok False without the database, slow True when it did not
    answer within 120 s"""
    res = {'ok': False, 'slow': False, 'devices': []}
    if not os.path.exists(UNBOUND_DB):
        return res
    s, e = int(start.timestamp()), int(end.timestamp())
    code = f'''
import duckdb, json
c = duckdb.connect({UNBOUND_DB!r}, read_only=True)
w = "time >= {s} and time < {e}"
rows = c.execute("select client, domain, action, count(*) from query where " + w + " group by client, domain, action").fetchall()
quarters = c.execute("select client, time // 900 from query where " + w + " group by client, time // 900").fetchall()
print(json.dumps({{'rows': rows, 'quarters': quarters}}))
'''
    try:
        raw = subprocess.run(['/usr/local/bin/python3', '-c', code], capture_output=True, text=True,
                             timeout=120, cwd='/usr/local/opnsense/scripts/unbound').stdout
        answer = json.loads(raw)
    except subprocess.TimeoutExpired:
        res['slow'] = True
        return res
    except Exception:
        return res
    res.update(ok=True, devices=web_devices(answer.get('rows') or [], answer.get('quarters') or [], top_n))
    return res


def last_backup():
    """time of the last remote configuration backup found in the system log"""
    newest = None
    for path in sorted(glob.glob('/var/log/system/system_*.log'), reverse=True):
        for line in open(path, errors='ignore'):
            if 'backup configuration as' in line:
                ts = line_time(line)
                if ts and (newest is None or ts > newest):
                    newest = ts
        if newest:
            break
    return newest


def ago(seconds, t):
    seconds = max(0, int(seconds))
    if seconds >= 86400:
        return t['ago_days'].format(n=seconds // 86400)
    if seconds >= 3600:
        return t['ago_hours'].format(n=seconds // 3600)
    return t['ago_min'].format(n=max(1, seconds // 60))


def system_info(settings, t):
    info = {}
    info['version'] = run('opnsense-version').strip()
    try:
        boot = int(re.search(r'sec = (\d+)', run('sysctl -n kern.boottime')).group(1))
        up = int(time.time()) - boot
        d, h = up // 86400, (up % 86400) // 3600
        info['uptime'] = t['days_hours'].format(d=d, h=h) if d else t['hours_only'].format(h=h)
    except Exception:
        info['uptime'] = '?'
    info['load'] = ' / '.join(run('sysctl -n vm.loadavg').strip().strip('{} ').split()[:3])
    temps = [float(x) for x in re.findall(r'temperature: ([\d.]+)C', run('sysctl -a | grep -i temperature'))]
    info['temp'] = max(temps, default=0)
    try:
        page = int(run('sysctl -n hw.pagesize'))
        total = int(run('sysctl -n hw.physmem'))
        free = sum(int(run(f'sysctl -n vm.stats.vm.{k}') or 0)
                   for k in ('v_free_count', 'v_inactive_count', 'v_cache_count')) * page
        used = total - free
        info['mem'] = t['used_of'].format(used=human_bytes(used), total=human_bytes(total),
                                          pct=round(100 * used / total))
    except Exception:
        info['mem'] = '?'
    df = run('df -k /').splitlines()
    try:
        parts = df[-1].split()
        size, used = int(parts[1]) * 1024, int(parts[2]) * 1024
        info['disk_pct'] = int(parts[4].rstrip('%'))
        info['disk'] = t['used_of'].format(used=human_bytes(used), total=human_bytes(size), pct=info['disk_pct'])
    except Exception:
        info['disk_pct'], info['disk'] = 0, '?'
    smart, info['smart_ok'] = [], True
    if os.path.exists('/usr/local/sbin/smartctl'):
        for d in run('sysctl -n kern.disks').split():
            r = run(f'smartctl -H /dev/{d}')
            if 'PASSED' in r or ' OK' in r:
                smart.append(f"{d}: {t['healthy']}")
            elif r:
                smart.append(f"{d}: {t['warning']}")
                info['smart_ok'] = False
    info['smart'] = t.get('list_sep', ', ').join(smart)
    info['backup_ts'] = last_backup()
    info['backup'] = ago(time.time() - info['backup_ts'], t) if info['backup_ts'] else t['none_found']
    tunnels = []
    for ifname in csv_list(settings.get('vpn_interfaces')):
        dev = settings.device(ifname)
        state = t['tunnel_idle']
        if dev.startswith('wg'):
            stamps = [int(x) for x in run(f'wg show {dev} latest-handshakes').split()[1::2] if x.isdigit()]
            recent = max(stamps, default=0)
            if recent and time.time() - recent < 600:
                state = t['tunnel_up'].format(ago=ago(time.time() - recent, t))
        elif dev:
            state = t['healthy'] if 'UP' in run(f'ifconfig {dev}').split('\n')[0] else t['warning']
        tunnels.append((settings.descr(ifname), state))
    info['tunnels'] = tunnels
    return info


# ---------------------------------------------------------------- rendering

CSS = '''
body{font-family:'Segoe UI',Tahoma,Arial,'Noto Sans','PingFang SC','Microsoft YaHei','Malgun Gothic','Meiryo',sans-serif;background:#f3f4f6;margin:0;padding:16px;color:#111827}
.wrap{max-width:780px;margin:auto;background:#fff;border-radius:10px;overflow:hidden;border:1px solid #e5e7eb}
.head{background:#1f2937;color:#fff;padding:18px 22px}
.head h1{margin:0;font-size:20px}.head p{margin:4px 0 0;color:#cbd5e1;font-size:13px}
.sec{padding:14px 22px;border-top:1px solid #eef0f3}
.sec h2{font-size:16px;margin:0 0 10px;color:#1f2937}.sec h3{font-size:14px;margin:14px 0 6px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 8px;border-bottom:1px solid #f1f2f4;text-align:start;vertical-align:top}
th{background:#f9fafb;color:#4b5563;font-weight:600}
.kpis{display:flex;flex-wrap:wrap;gap:8px}
.kpi{flex:1 1 140px;background:#f9fafb;border:1px solid #eef0f3;border-radius:8px;padding:10px}
.kpi b{display:block;font-size:18px;color:#111827}.kpi span{font-size:12px;color:#6b7280}
.kpi i{display:block;font-style:normal;font-size:11px;margin-top:3px}
.up{color:#b45309}.down{color:#047857}
.ok{color:#047857}.warn{color:#b45309}.bad{color:#b91c1c}.muted{color:#6b7280;font-size:12px}
.issues{margin:0;padding:0 18px}.issues li{margin:4px 0}
.ltr{direction:ltr;unicode-bidi:embed}
'''


def table(t, headers, rows):
    if not rows:
        return f'<p class="muted">{esc(t["no_data"])}</p>'
    head = ''.join(f'<th>{esc(x)}</th>' for x in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{c}</td>' for c in r) + '</tr>' for r in rows)
    return f'<table><tr>{head}</tr>{body}</table>'


def trend(t, cur, prev):
    """small "▲ 12% vs previous period" line, empty when there is nothing to compare"""
    if prev is None or not prev:
        return ''
    pct = 100.0 * (cur - prev) / prev
    if abs(pct) < 1:
        return f'<i class="muted">= {esc(t["vs_prev"])}</i>'
    cls, arrow = ('up', '▲') if pct > 0 else ('down', '▼')
    return f'<i class="{cls}">{arrow} {abs(pct):.0f}% {esc(t["vs_prev"])}</i>'


def kpis(items):
    """items: (label, value, extra html)"""
    return '<div class="kpis">' + ''.join(
        f'<div class="kpi"><b>{v}</b><span>{esc(k)}</span>{x}</div>' for k, v, x in items) + '</div>'


def infected_table(t, names):
    """the devices that tried to reach a command-and-control list (infected.json), or nothing"""
    infected = load_json(INFECTED_FILE, {})
    rows = sorted(((a, e) for a, e in (infected.items() if isinstance(infected, dict) else []) if isinstance(e, dict)),
                  key=lambda x: -(x[1].get('last') or 0))
    if not rows:
        return ''

    def when(ts):
        return f'<span class="ltr">{datetime.datetime.fromtimestamp(ts):%Y-%m-%d %H:%M}</span>' if ts else ''

    def who(address, entry):
        name = names.get(address) or entry.get('name')
        return f'{name} ({address})' if name else address

    return (f'<h3 class="bad">{esc(t["infected"])}</h3><p class="muted">{esc(t["infected_intro"])}</p>' +
            table(t, [t['device'], 'MAC', t['blocklist'], t['times'], t['first_seen'], t['last_seen']], [
                [esc(who(a, e)),
                 f'<span class="ltr">{esc(e.get("mac") or "")}</span>', esc(e.get('list') or ''),
                 f'{int(e.get("count") or 0):,}', when(e.get('first')), when(e.get('last'))] for a, e in rows]))


def build_report(settings, sched, start, end):
    """returns subject, html, plain text and the list of issues (level, text)"""
    t = texts(sched.get('language'))
    sections = [s for s in ALL_SECTIONS if s in csv_list(sched.get('sections'))] or ALL_SECTIONS
    top_n = int(sched.get('top_n') or 10)
    compare = sched.get('compare', '1') == '1'
    prev_start = start - (end - start)
    names = hostnames(settings)
    issues = []
    parts = {}

    # internet
    wan_dev = settings.device(settings.get('wan_interface'))
    wan = vnstat_volume(wan_dev, start, end)
    wan_prev = vnstat_volume(wan_dev, prev_start, start) if compare else None
    month_rx, month_tx = vnstat_month(wan_dev)
    cap = settings.num('monthly_cap') * 10 ** 9
    cap_pct = round(100 * (month_rx + month_tx) / cap) if cap else 0
    if cap and cap_pct >= 100:
        issues.append(('bad', t['i_cap100'].format(p=cap_pct)))
    elif cap and cap_pct >= 80:
        issues.append(('warn', t['i_cap80'].format(p=cap_pct)))
    items = [
        (t['download'], human_bytes(wan['rx']), trend(t, wan['rx'], wan_prev and wan_prev['rx'])),
        (t['upload'], human_bytes(wan['tx']), trend(t, wan['tx'], wan_prev and wan_prev['tx'])),
        (t['month_total'], human_bytes(month_rx + month_tx),
         f'<i class="muted">{esc(t["cap_used"].format(p=cap_pct, cap=human_bytes(cap)))}</i>' if cap else ''),
    ]
    for ifname in csv_list(settings.get('vpn_interfaces')):
        vol = vnstat_volume(settings.device(ifname), start, end)
        if vol['ok']:
            items.append((t['via'].format(name=settings.descr(ifname)), human_bytes(vol['rx'] + vol['tx']), ''))
    # without vnstat (os-vnstat) there are no volume counters at all
    parts['internet'] = kpis(items) if wan['ok'] else f'<p class="muted">{esc(t["no_data"])}</p>'

    # connection
    gws = gateway_status()
    events = gateway_events(start, end)
    loss_warn = settings.num('loss_warn')
    rows = []
    for g in gws:
        if g['delay'] == '~':        # not monitored (e.g. link-local IPv6)
            continue
        up = g['status'] in ('none', 'online')
        try:
            loss = float(str(g['loss']).split()[0])
        except (ValueError, IndexError):
            loss = 0
        if not up:
            issues.append(('bad', t['i_gw_down'].format(name=g['name'], status=g['status'])))
        elif loss >= loss_warn:
            issues.append(('warn', t['i_gw_loss'].format(name=g['name'], loss=g['loss'])))
        state = f'<span class="ok">{esc(t["online"])}</span>' if up else f'<span class="bad">{esc(g["status"])} ⚠️</span>'
        rows.append([esc(g['name']), state, f'<span class="ltr">{esc(g["delay"])}</span>',
                     f'<span class="ltr">{esc(g["loss"])}</span>', f'{events.get(g["name"], 0):,}'])
    outages = sum(events.values())
    if outages:
        issues.append(('warn', t['i_outages'].format(n=outages)))
    parts['connection'] = table(t, [t['gateway'], t['state_now'], t['delay'], t['loss'], t['outages']], rows)

    def at(ts):
        return f'<span class="ltr">{datetime.datetime.fromtimestamp(ts):%Y-%m-%d %H:%M}</span>' if ts else '—'

    # vpn
    if 'vpn' in sections:
        import alerts
        vpn = vpn_report(settings, start, end)
        if vpn is None:
            parts['vpn'] = f'<p class="muted">{esc(t["vpn_none"])}</p>'
        else:
            down_now = [x for x in vpn['tunnels'] if not x['up']]
            if down_now:
                issues.append(('warn', t['i_vpn_down'].format(n=len(down_now))))
            body = kpis([
                (t['tunnels_up'], f'{len(vpn["tunnels"]) - len(down_now)} / {len(vpn["tunnels"])}', ''),
                (t['vpn_outages'], f'{sum(x["outages"] for x in vpn["tunnels"]):,}', ''),
                (t['users_now'], f'{len(vpn["sessions"]):,}', ''),
            ])
            body += table(t, [t['vpn_conn'], t['state_now'], t['since'], t['vpn_outages'], t['down_for']], [
                [esc(x['name']),
                 f'<span class="ok">{esc(t["online"])}</span>' if x['up'] else f'<span class="bad">{esc(t["vpn_down_state"])}</span>',
                 at(x['since']), f'{x["outages"]:,}', esc(alerts.duration(x['down'], t)) if x['down'] else '—']
                for x in vpn['tunnels']])
            if vpn['sessions']:
                body += f'<h3>{esc(t["active_now"])}</h3>' + table(
                    t, [t['service'], t['vpn_conn'], t['user'], t['address'], t['since'], t['traffic']], [
                        [esc(svc), esc(conn), esc(user), f'<span class="ltr">{esc(addr)}</span>', at(since), human_bytes(traffic)]
                        for svc, conn, user, addr, since, traffic in sorted(vpn['sessions'], key=lambda r: -r[5])[:50]])
                body += f'<p class="muted">{esc(t["vpn_traffic_note"])}</p>'
            if vpn['log_since']:
                body += f'<p class="muted">{esc(t["vpn_log_from"].format(time=datetime.datetime.fromtimestamp(vpn["log_since"]).strftime("%Y-%m-%d %H:%M")))}</p>'
            parts['vpn'] = body

    # dns
    if 'dns' in sections:
        dns = dns_stats(start, end, top_n)
        dns_prev = dns_stats(prev_start, start, 1) if compare else None
        rate = (100.0 * dns['blocked'] / dns['total']) if dns['total'] else 0
        body = kpis([
            (t['queries'], f'{dns["total"]:,}', trend(t, dns['total'], dns_prev and dns_prev['total'])),
            (t['blocked'], f'{dns["blocked"]:,}', trend(t, dns['blocked'], dns_prev and dns_prev['blocked'])),
            (t['block_rate'], f'{rate:.1f}%', ''),
        ])
        body += f'<h3>{esc(t["top_blocked"])}</h3>' + table(t, [t['domain'], t['times']], [
            [f'<span class="ltr">{esc(d.rstrip("."))}</span>', f'{n:,}'] for d, n in dns['top_blocked']])
        body += f'<h3>{esc(t["top_clients"])}</h3>' + table(t, [t['device'], t['times']], [
            [esc(label(c, names)), f'{n:,}'] for c, n in dns['top_clients']])
        parts['dns'] = body

    # web activity per device
    if 'web' in sections:
        web = web_activity(start, end, top_n)
        if not web['ok']:
            parts['web'] = f'<p class="muted">{esc(t["web_slow"] if web["slow"] else t["web_off"])}</p>'
        else:
            def domains(pairs, counted=True):
                return '<br>'.join(f'<span class="ltr">{esc(str(d).rstrip("."))}</span>' + (f' ({n:,})' if counted else '')
                                   for d, n in pairs) or '—'
            parts['web'] = table(t, [t['device'], t['queries'], t['top_domains'], t['blocked'], t['active_hours']], [
                [esc(label(d['client'], names)), f'{d["queries"]:,}', domains(d['domains']),
                 f'{d["blocked"]:,}' + ('<br>' + domains(d['blocked_domains'], False) if d['blocked_domains'] else ''),
                 f'<span class="ltr">{esc(d["hours"])}</span>'] for d in web['devices']])

    # security
    ids = suricata_alerts(start, end, top_n)
    ids_prev = suricata_alerts(prev_start, start, 1) if compare and 'security' in sections else None
    cs = crowdsec(start)
    # Only what came from outside belongs under "needs your attention". An alert on a
    # connection this network opened is still reported, further down and in its own
    # words, because it can mean something - but it is not somebody at the door.
    if ids['inbound_severe']:
        issues.append(('bad', t['i_severe_in'].format(n=ids['inbound_severe'])))
    if ids['out_severe']:
        issues.append(('info', t['i_outbound'].format(n=ids['out_severe'])))
    if cs['alerts']:
        issues.append(('info', t['i_crowdsec'].format(n=cs['alerts'])))
    items = [
        (t['ids_alerts'], f'{ids["total"]:,}', trend(t, ids['total'], ids_prev and ids_prev['total'])),
        (t['severe'], f'{ids["severe"]:,}', ''),
    ]
    if cs['ok']:
        items += [(t['cs_alerts'], f'{cs["alerts"]:,}', ''), (t['cs_bans'], f'{cs["bans"]:,}', '')]
    body = kpis(items)
    body += f'<h3>{esc(t["top_sigs"])}</h3>' + table(t, [t['alert'], t['times']], [
        [f'<span class="ltr">{esc(s)}</span>', f'{n:,}'] for s, n in ids['sigs']])
    body += f'<h3>{esc(t["top_srcs"])}</h3>' + table(t, [t['address'], t['times']], [
        [f'<span class="ltr">{esc(ip)}</span>', f'{n:,}'] for ip, n in ids['srcs']])
    if ids['out_total']:
        body += f'<h3>{esc(t["out_heading"])}</h3>'
        body += f'<p class="muted">{esc(t["out_intro"])}</p>'
        body += table(t, [t['alert'], t['times']], [
            [f'<span class="ltr">{esc(s)}</span>', f'{n:,}'] for s, n in ids['out_sigs']])
        body += table(t, [t['address'], t['times']], [
            [f'<span class="ltr">{esc(ip)}</span>', f'{n:,}'] for ip, n in ids['out_hosts']])
    body += infected_table(t, names)
    ids_general = settings.root.find('./OPNsense/IDS/general')
    if ids_general is not None and ids_general.findtext('enabled') == '1' and ids_general.findtext('ips') != '1':
        body += f'<p class="muted">{esc(t["ids_note"])}</p>'
    parts['security'] = body

    # applications: ntopng's by traffic where its token is set, and Suricata's records
    if 'apps' in sections:
        body = ''
        ntop, why = ntopng_apps(settings, top_n)
        if ntop:
            body += f'<h3>{esc(t["ntopng_apps"])}</h3>' + table(t, [t['app'], t['traffic']], [
                [esc(name), human_bytes(n)] for name, n in ntop])
        elif why:
            body += f'<p class="muted">{esc(t["ntopng_failed"].format(why=why))}</p>'
        apps = suricata_apps(start, end, top_n)
        if apps['ok']:
            body += f'<h3>{esc(t["app_protos"])}</h3>' + table(t, [t['app'], t['records']], [
                [f'<span class="ltr">{esc(p)}</span>', f'{n:,}'] for p, n in apps['protos']])
            body += f'<h3>{esc(t["top_sites"])}</h3>' + table(t, [t['site'], t['times']], [
                [f'<span class="ltr">{esc(site)}</span>', f'{n:,}'] for site, n in apps['sites']])
            if apps['partial']:
                body += f'<p class="muted">{esc(t["apps_partial"].format(n=EVE_SCAN_SECONDS))}</p>'
        else:
            body += f'<p class="muted">{esc(t["apps_no_ids"])}</p>'
        parts['apps'] = body

    # devices
    db, _, active = update_devices(settings)
    s_ts, e_ts = start.timestamp(), end.timestamp()
    new = sorted(((m, d) for m, d in db.items() if s_ts <= d.get('first_seen', 0) < e_ts),
                 key=lambda x: x[1]['first_seen'])
    if new:
        issues.append(('warn', t['i_new_dev'].format(n=len(new))))
    body = kpis([(t['active_now'], len(active), ''), (t['known'], len(db), ''), (t['new_in_period'], len(new), '')])
    if new:
        body += f'<h3 class="warn">{esc(t["new_list"])}</h3>' + table(t, [t['device'], 'MAC', t['vendor'], t['first_seen']], [
            [esc(label(d.get('ip', ''), names) if d.get('ip') else '?'), f'<span class="ltr">{esc(m)}</span>',
             esc(d.get('vendor', '')), f'<span class="ltr">{datetime.datetime.fromtimestamp(d["first_seen"]):%Y-%m-%d %H:%M}</span>']
            for m, d in new])
    if 'devices' in sections:
        talkers = top_talkers(settings, start, end, top_n)
        body += f'<h3>{esc(t["top_talkers"])}</h3>' + table(t, [t['device'], t['download'], t['upload'], t['total']], [
            [esc(label(ip, names)), human_bytes(d), human_bytes(u), human_bytes(d + u)] for ip, d, u in talkers])
    parts['devices'] = body

    # mail, from the mail server's log (os-postfix)
    if 'mail' in sections:
        mail = mail_stats(start, end, top_n)
        if not mail['ok']:
            parts['mail'] = f'<p class="muted">{esc(t["mail_none"])}</p>'
        else:
            body = kpis([(t['mail_sent'], f'{mail["sent"]:,}', ''), (t['mail_deferred'], f'{mail["deferred"]:,}', ''),
                         (t['mail_bounced'], f'{mail["bounced"]:,}', ''), (t['mail_rejected'], f'{mail["rejected"]:,}', '')])
            if mail['rejects']:
                body += f'<h3>{esc(t["top_rejected"])}</h3>' + table(t, [t['address'], t['times']], [
                    [f'<span class="ltr">{esc(a)}</span>', f'{n:,}'] for a, n in mail['rejects']])
            parts['mail'] = body

    # system
    info = system_info(settings, t)
    if info['temp'] and info['temp'] >= settings.num('temp_warn'):
        issues.append(('bad', t['i_temp'].format(t=f'{info["temp"]:.0f}')))
    if info['disk_pct'] >= settings.num('disk_warn'):
        issues.append(('bad', t['i_disk'].format(p=info['disk_pct'])))
    if not info['smart_ok']:
        issues.append(('bad', t['i_smart']))
    backup_warn = settings.num('backup_warn')
    if backup_warn:
        if not info['backup_ts']:
            issues.append(('warn', t['i_backup_none']))
        elif time.time() - info['backup_ts'] > backup_warn * 86400:
            issues.append(('warn', t['i_backup_old'].format(n=int((time.time() - info['backup_ts']) // 86400))))
    rows = [
        [esc(t['version']), f'<span class="ltr">{esc(info["version"])}</span>'],
        [esc(t['uptime']), esc(info['uptime'])],
        [esc(t['load']), f'<span class="ltr">{esc(info["load"])}</span>'],
        [esc(t['temp']), f'{info["temp"]:.0f}°C' if info['temp'] else '—'],
        [esc(t['memory']), esc(info['mem'])],
        [esc(t['disk']), esc(info['disk'])],
    ]
    if info['smart']:
        rows.append([esc(t['smart']), esc(info['smart'])])
    rows.append([esc(t['backup']), esc(info['backup'])])
    for name, state in info['tunnels']:
        rows.append([esc(t['tunnel'].format(name=name)), esc(state)])
    parts['system'] = table(t, [t['item'], t['value']], rows)

    # highlights
    order = {'bad': 0, 'warn': 1, 'info': 2}
    issues.sort(key=lambda i: order[i[0]])
    if issues:
        icon = {'bad': '🔴', 'warn': '🟠', 'info': '🔵'}
        parts['summary'] = '<ul class="issues">' + ''.join(
            f'<li class="{"bad" if lvl == "bad" else ("warn" if lvl == "warn" else "")}">{icon[lvl]} {esc(txt)}</li>'
            for lvl, txt in issues) + '</ul>'
    else:
        parts['summary'] = f'<p class="ok">{esc(t["all_good"])}</p>'

    title = settings.get('title') or 'OPNsense'
    now = datetime.datetime.now()
    span = period_label(sched, start, end, t)
    subject = t['subject'].format(title=title, date=f'{now:%Y-%m-%d}')
    body = ''.join(f'<div class="sec"><h2>{esc(t[s])}</h2>{parts[s]}</div>' for s in sections if s in parts)
    page = (f'<!DOCTYPE html><html dir="{t["dir"]}" lang="{t["lang"]}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><style>{CSS}</style></head><body>'
            f'<div class="wrap"><div class="head"><h1>📊 {esc(t["report"])} — {esc(title)}</h1>'
            f'<p>{esc(span)} · <span class="ltr">{start:%Y-%m-%d %H:%M} → {end:%Y-%m-%d %H:%M}</span> · '
            f'{esc(t["generated"].format(time=now.strftime("%Y-%m-%d %H:%M")))}</p></div>{body}'
            f'<div class="sec muted">{esc(t["footer"].format(host=settings.hostname(), schedule=sched.get("description", "")))}</div>'
            f'</div></body></html>')
    text = '\n'.join([subject, span, ''] + [f'- {txt}' for _, txt in issues] + ['', t['text_fallback']])
    return subject, page, text, issues


# ---------------------------------------------------------------- mail

def mail_settings(settings):
    if settings.get('mail_source') == 'custom':
        # without authentication the saved username and password are left unused
        auth = settings.get('smtp_auth') == '1'
        user = settings.get('smtp_user') if auth else ''
        return {'host': settings.get('smtp_host'), 'port': settings.num('smtp_port') or 465,
                'security': settings.get('smtp_security') or 'ssl', 'user': user,
                'password': settings.get('smtp_password') if auth else '',
                'sender': settings.get('from_address') or user}
    monit = settings.root.find('./OPNsense/monit/general')
    if monit is None or not monit.findtext('mailserver'):
        raise RuntimeError('No mail server: configure Services: Monit or a custom SMTP server.')
    port = int(monit.findtext('port') or 25)
    use_ssl = monit.findtext('ssl') == '1'
    security = 'ssl' if port == 465 else ('starttls' if use_ssl or port == 587 else 'none')
    user = monit.findtext('username') or ''
    return {'host': monit.findtext('mailserver').split(',')[0].strip(), 'port': port, 'security': security,
            'user': user, 'password': monit.findtext('password') or '',
            'sender': user if '@' in user else f'opnsense@{settings.hostname()}'}


def recipients_for(settings, sched, ms):
    rcpt = csv_list(sched.get('recipients')) if sched else []
    rcpt = rcpt or csv_list(settings.get('recipients'))
    # the mail account's own address: its username, or the sender address of a custom server
    # that takes mail without signing in, which leaves no username
    own = ms['user'] or (ms['sender'] if settings.get('mail_source') == 'custom' else '')
    if not rcpt and '@' in own:
        rcpt = [own]
    if not rcpt:
        raise RuntimeError('No recipients configured.')
    return rcpt


QUIT_TIMEOUT = 5                # seconds in all for QUIT, once the mail server took the message


def send_mail(ms, rcpt, subject, page, text, attach_name=None, before_send=None, after_send=None):
    """before_send() runs as the message is about to go, after_send() once the server took it (the alert
    layer moves and stops its time limit there). The QUIT then has QUIT_TIMEOUT in all - not smtplib's
    quit(), which reads a reply's continuation lines for as long as a server sends them - and whatever
    it gets, the mail was sent."""
    msg = MIMEMultipart('mixed')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = formataddr((str(Header('OPNsense', 'utf-8')), ms['sender']))
    msg['To'] = ', '.join(rcpt)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=ms['sender'].split('@')[-1])
    alt = MIMEMultipart('alternative')
    alt.attach(MIMEText(text, 'plain', 'utf-8'))
    alt.attach(MIMEText(page, 'html', 'utf-8'))
    msg.attach(alt)
    if attach_name:
        part = MIMEApplication(page.encode('utf-8'), Name=attach_name)
        part['Content-Disposition'] = f'attachment; filename="{attach_name}"'
        msg.attach(part)
    context = ssl.create_default_context()
    if ms['security'] == 'ssl':
        server = smtplib.SMTP_SSL(ms['host'], ms['port'], timeout=60, context=context)
    else:
        server = smtplib.SMTP(ms['host'], ms['port'], timeout=60)
        if ms['security'] == 'starttls':
            server.starttls(context=context)
    try:
        if ms['user'] and ms['password']:
            server.login(ms['user'], ms['password'])
        if before_send:
            before_send()
        server.sendmail(ms['sender'], rcpt, msg.as_string())
        if after_send:
            after_send()
    except BaseException:
        server.close()
        raise
    # the server has the message: a QUIT that fails or is slow does not make it a failure (it would be
    # mailed again with its retry). It has QUIT_TIMEOUT in all, for its send and the first piece of
    # the answer, which is all that is read
    try:
        if server.sock is not None:
            end = time.monotonic() + QUIT_TIMEOUT
            server.sock.settimeout(QUIT_TIMEOUT)
            server.sock.sendall(b'QUIT\r\n')
            server.sock.settimeout(max(end - time.monotonic(), 0.001))
            server.sock.recv(512)
    except Exception:
        pass
    finally:
        server.close()


# ---------------------------------------------------------------- history and archive

def add_history(entry):
    entries = load_json(HISTORY_FILE, [])
    entry['time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    entries.insert(0, entry)
    save_json(HISTORY_FILE, entries[:HISTORY_MAX])


def archive(settings, uuid, page):
    keep = settings.num('keep_days')
    if keep <= 0:
        return ''
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    name = f'{datetime.datetime.now():%Y%m%d-%H%M%S}-{(uuid or "x")[:8]}.html'
    with open(os.path.join(ARCHIVE_DIR, name), 'w', encoding='utf-8') as fh:
        fh.write(page)
    cutoff = time.time() - keep * 86400
    for path in glob.glob(os.path.join(ARCHIVE_DIR, '*.html')):
        if os.path.getmtime(path) < cutoff:
            os.unlink(path)
    return name


# ---------------------------------------------------------------- commands

def deliver(settings, sched, forced=False):
    now = datetime.datetime.now().replace(second=0, microsecond=0)
    start, end = report_window(sched, now)
    entry = {'schedule': sched.get('description', ''), 'subject': '', 'recipients': '', 'archive': ''}
    try:
        subject, page, text, issues = build_report(settings, sched, start, end)
        entry['subject'] = subject
        if not forced and sched.get('only_issues') == '1' and not any(lvl != 'info' for lvl, _ in issues):
            entry.update(status='skipped', detail='')
            add_history(entry)
            return {'status': 'skipped', 'detail': ''}
        ms = mail_settings(settings)
        rcpt = recipients_for(settings, sched, ms)
        entry['recipients'] = ', '.join(rcpt)
        attach = f'network-report-{now:%Y-%m-%d}.html' if sched.get('attach') == '1' else None
        send_mail(ms, rcpt, subject, page, text, attach)
        entry['archive'] = archive(settings, sched.get('uuid'), page)
        entry.update(status='sent', detail='')
        add_history(entry)
        log(f'sent "{subject}" to {entry["recipients"]}')
        return {'status': 'sent', 'detail': entry['recipients']}
    except Exception as exc:
        entry.update(status='failed', detail=str(exc))
        add_history(entry)
        log(f'report "{entry["schedule"]}" failed: {exc}')
        return {'status': 'failed', 'detail': str(exc)}


def new_device_alert(settings, db, macs):
    """the devices that joined the network for the first time, through the alert layer (alerts.py)"""
    import alerts
    t = texts(settings.get('language'))
    names = hostnames(settings)
    rows = [[esc(label(db[m].get('ip', ''), names)), f'<span class="ltr">{esc(m)}</span>', esc(db[m].get('vendor', ''))]
            for m in macs]
    title = settings.get('title') or 'OPNsense'
    subject = t['alert_subject'].format(title=title)
    page = (f'<!DOCTYPE html><html dir="{t["dir"]}" lang="{t["lang"]}"><head><meta charset="utf-8"><style>{CSS}</style></head><body>'
            f'<div class="wrap"><div class="head"><h1>🔔 {esc(subject)}</h1></div><div class="sec">'
            f'<p>{esc(t["alert_intro"])}</p>{table(t, [t["device"], "MAC", t["vendor"]], rows)}'
            f'<p class="muted">{esc(t["alert_hint"])}</p></div></div></body></html>')
    text = '\n'.join([subject, ''] + [f'- {db[m].get("ip", "")} {m} {db[m].get("vendor", "")}' for m in macs])
    facts = {'devices': [{'mac': m, 'ip': db[m].get('ip', ''), 'name': names.get(db[m].get('ip', ''), ''),
                          'vendor': db[m].get('vendor', '')} for m in macs]}
    # each set of new devices is its own alert: no quiet time holds it back
    alerts.notify(settings, None, 'new_device', ','.join(macs), subject, text, facts=facts, page=page, quiet=0,
                  tags=['new'])


def scheduler():
    lock = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return
    settings = Settings()
    if settings.get('enabled') != '1':
        return
    # the minute this run is for, taken before the collectors: a long run must not move the device
    # scan's :x0/:x5 past it
    now = datetime.datetime.now()

    # The alert collectors first, so that a report being built does not hold an alert back; each in
    # its own try, so that one failing stops neither the others nor the reports (alerts.run_collectors).
    try:
        import alerts
        alerts.run_collectors(settings, alerts.State(), time.time())
    except Exception as exc:
        log(f'alerts failed: {exc}')

    state = load_json(STATE_FILE, {})
    last_sent = state.setdefault('last_sent', {})
    for uuid, sched in settings.schedules.items():
        if sched.get('enabled') != '1':
            continue
        occ = last_occurrence(sched, now)
        if uuid not in last_sent:
            # new schedule: start counting from now, don't fire for a time that already passed
            last_sent[uuid] = now.timestamp()
            continue
        if occ.timestamp() > last_sent[uuid] and (now - occ).total_seconds() <= CATCH_UP:
            last_sent[uuid] = now.timestamp()
            save_json(STATE_FILE, state)
            deliver(settings, sched)
    for uuid in list(last_sent):
        if uuid not in settings.schedules:
            del last_sent[uuid]
    save_json(STATE_FILE, state)

    if now.minute % DEVICE_SCAN_MINUTES == 0:
        db, new, _ = update_devices(settings)
        if new and settings.get('alerts') == '1' and settings.get('new_device_alert') == '1':
            new_device_alert(settings, db, new)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    arg = sys.argv[2] if len(sys.argv) > 2 else ''
    os.makedirs(STATE_DIR, exist_ok=True)
    # alerts.py imports this module by its name: the one running is the one it gets
    sys.modules.setdefault('netreport', sys.modules[__name__])
    if cmd == 'scheduler':
        scheduler()
    elif cmd in ('send', 'preview'):
        settings = Settings()
        sched = settings.schedules.get(arg)
        if sched is None:
            print(json.dumps({'status': 'failed', 'detail': 'unknown schedule'}) if cmd == 'send' else '')
            return
        if cmd == 'send':
            print(json.dumps(deliver(settings, sched, forced=True), ensure_ascii=False))
        else:
            now = datetime.datetime.now().replace(second=0, microsecond=0)
            start, end = report_window(sched, now)
            print(build_report(settings, sched, start, end)[1])
    elif cmd == 'testmail':
        settings = Settings()
        t = texts(settings.get('language'))
        try:
            ms = mail_settings(settings)
            rcpt = recipients_for(settings, None, ms)
            body = t['test_body'].format(to=', '.join(rcpt))
            page = (f'<html dir="{t["dir"]}" lang="{t["lang"]}"><body style="font-family:Tahoma,Arial,sans-serif">'
                    f'<p>✅ {esc(body)}</p></body></html>')
            send_mail(ms, rcpt, t['test_subject'], page, body)
            print(json.dumps({'status': 'sent', 'detail': ', '.join(rcpt)}, ensure_ascii=False))
        except Exception as exc:
            print(json.dumps({'status': 'failed', 'detail': str(exc)}, ensure_ascii=False))
    elif cmd == 'history':
        # an older line may hold a lone surrogate: printed as UTF-8 it raises, and as an escape PHP's
        # json_decode() refuses the whole list - the page would show no history at all
        print(json.dumps(no_surrogates(load_json(HISTORY_FILE, [])), ensure_ascii=True))
    elif cmd == 'view':
        if re.match(r'^[0-9A-Za-z_-]+\.html$', arg) and os.path.exists(os.path.join(ARCHIVE_DIR, arg)):
            print(open(os.path.join(ARCHIVE_DIR, arg), encoding='utf-8').read())
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
