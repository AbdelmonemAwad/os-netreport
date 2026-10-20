#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the Network Report plugin files. Settings stay in config.xml and the
# history in /var/db/netreport, so a later reinstall picks up where it left off.

# the cron entry of the daily self-update an install before 2026-10-20 had, so that it cannot
# reinstall half way through this
rm -f /usr/local/etc/cron.d/netreport-update
rm -rf /usr/local/share/os-netreport
rm -f /usr/local/etc/cron.d/netreport
rm -f /usr/local/etc/rc.syshook.d/start/60-netreport
rm -f /usr/local/share/pkg/triggers/os-netreport.ucl
rm -f /usr/local/opnsense/service/conf/actions.d/actions_netreport.conf
rm -rf /usr/local/opnsense/scripts/netreport
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/NetReport
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/NetReport
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/NetReport
service configd restart > /dev/null
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
echo "Network Report removed"
