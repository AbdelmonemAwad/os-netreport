#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
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
chmod 755 /usr/local/opnsense/scripts/netreport/self-update.py
# No daily self-update since 2026-10-20: a release is installed from XGS: Updates
# (its Plugins tab, in os-xgs-npu) or by hand with self-update.py. An older
# install's cron entry goes.
rm -f /usr/local/etc/cron.d/netreport-update

# syntax check before anything is reloaded
for f in $(find "${HERE}/src" -name '*.php'); do
    php -l "$f" > /dev/null
done
python3 -m py_compile /usr/local/opnsense/scripts/netreport/netreport.py

# Where the page goes in the menu: XGS when os-xgs-npu is installed, Reporting when it is not.
# OPNsense's menu file takes no condition, so place-menu.sh writes it from menu/ and says which.
chmod 755 /usr/local/opnsense/scripts/netreport/place-menu.sh
MENUPLACE=$(/usr/local/opnsense/scripts/netreport/place-menu.sh)

# reload configd actions, menu and ACL caches (in /var/lib/php/tmp on 26.7, /tmp before it)
service configd restart > /dev/null
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json

# GUI strings for every installed language but Arabic, then reload php so the new catalogs
# are used. The Arabic is in opnsense-arabic's catalogue since 2026-10-22; the copy an earlier
# install left goes, so that nothing merges it again. The merge prints two numbers: the strings
# it added, and the strings of its own it corrected.
rm -f /usr/local/opnsense/scripts/netreport/i18n/ui/ar_SA.json
MERGED=$(/usr/local/opnsense/scripts/netreport/merge_ui_translations.py) || MERGED='0 0'
echo "translated strings added: ${MERGED%% *}, corrected: ${MERGED##* }"
configctl webgui restart > /dev/null 2>&1 || true

# What this install is, for the self-update: the commit, from a git checkout, or from the
# .source-commit stamp that an xgs-image-builder image or the self-update leaves in the tree.
# Without either it is recorded as unknown, and the self-update takes the latest release once.
REV=; RDATE=; RSRC=unknown
if [ -e "${HERE}/.git" ] && REV=$(git -C "${HERE}" rev-parse HEAD 2>/dev/null); then
    RDATE=$(git -C "${HERE}" log -1 --format=%cI 2>/dev/null); RSRC=git
elif [ -s "${HERE}/.source-commit" ]; then
    read -r REV RDATE _ < "${HERE}/.source-commit"; RSRC=stamp
else
    REV=
fi
case ${REV} in *[!0-9a-f]*) REV=; RDATE=; RSRC=unknown ;; esac
install -d -m 0755 /usr/local/share/os-netreport
printf '{"commit": "%s", "date": "%s", "source": "%s", "installed_at": %s}\n' \
    "${REV}" "${RDATE}" "${RSRC}" "$(date +%s)" > /usr/local/share/os-netreport/installed.json

if [ "${MENUPLACE}" = xgs ]; then
    echo "Network Report installed: XGS > Network Report"
else
    echo "Network Report installed: Reporting > Network Report"
fi
