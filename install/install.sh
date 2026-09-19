#!/bin/sh
# Install the Network Report plugin from a copy of this repository on the firewall:
#   sh install/install.sh
# Safe to run again after an update: settings in config.xml are kept.

set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)

# plugin files: src/ maps to /usr/local
cp -R "${HERE}/src/" /usr/local/
chmod 755 /usr/local/opnsense/scripts/netreport/netreport.py
chmod 755 /usr/local/opnsense/scripts/netreport/merge_ui_translations.py
chmod 755 /usr/local/etc/rc.syshook.d/start/60-netreport
chmod 644 /usr/local/etc/cron.d/netreport

# syntax check before anything is reloaded
for f in $(find "${HERE}/src" -name '*.php'); do
    php -l "$f" > /dev/null
done
python3 -m py_compile /usr/local/opnsense/scripts/netreport/netreport.py

# reload configd actions, menu and ACL caches
service configd restart > /dev/null
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json

# GUI strings for every installed language, then reload php so the new catalogs are used
echo "translated strings added: $(/usr/local/opnsense/scripts/netreport/merge_ui_translations.py)"
configctl webgui restart > /dev/null 2>&1 || true

echo "Network Report installed: Reporting > Network Report"
