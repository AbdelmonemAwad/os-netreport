#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-netreport are in place, on install and on upgrade
# alike. tools/make-package.sh inlines it into the package manifest.
#
# The first block and the last-but-one are, line for line, what every OPNsense plugin
# runs: os-smart and os-vnstat carry the same and nothing else.
#
# Three things install/install.sh does are deliberately NOT here:
#
#   the chmod lines - pkg has already set every mode and owner from the plist, and it
#   recorded what it set. Setting them again from a script lets the disk and pkg's record
#   of the disk drift apart, and pkg check -s then reports this package as altered on a
#   machine where nothing is wrong.
#
#   the php -l and py_compile checks - they belong to the source tree, before a package
#   exists, and .github/workflows/checks.yml already runs them on every change. By the
#   time this script runs the files are installed; a check that fails here cannot undo
#   anything.
#
#   rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json - two problems with
#   that line, and the package fixes both. Those caches are not in /tmp on 26.7; they are
#   in the framework's own tempDir, which is /var/lib/php/tmp, so the line has been
#   removing nothing for a while. And the right way to do it is not an rm at all:
#   rc.configure_plugins POST_INSTALL below calls system_cache_flush(), which invalidates
#   the ACL cache and the menu cache wherever they are, and clears the model caches and
#   the compiled Volt templates as well.

# configd reads actions_netreport.conf once, at start.
if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

# One line the hand installation does not have, and should. The device database, the
# schedule state, the history and the archive live here. netreport.py creates the
# directory itself with os.makedirs(), which means whatever the umask says - 0755 in
# practice, world-readable - and devices.json is a list of every MAC, hostname and vendor
# on the network. Making it here, first, at 0750, settles it before anything writes:
# makedirs(exist_ok=True) does not change the mode of a directory that already exists, so
# the only way to get this right is to get there first. Matches os-linkhealth's
# /var/db/linkhealth, and install -d repairs the mode on an upgrade.
install -d -o root -g wheel -m 0750 /var/db/netreport

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/NetReport
fi

# Put the plugin in config.xml's system/firmware/plugins list, which is where OPNsense
# keeps the plugins it considers managed; without it System > Firmware > Plugins shows
# this as an installed package that nothing configured. register.php reads the version
# marker the package ships at /usr/local/opnsense/version/netreport and refuses anything
# whose name does not start with os-. It is idempotent.
if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-netreport > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# The GUI strings are merged into the gettext catalogues of every installed language.
# This is the same thing /usr/local/etc/rc.syshook.d/start/60-netreport does at every
# boot - the catalogues belong to the opnsense-lang package, which replaces them on its
# own schedule, independent of the core version - so doing it now takes no new liberty
# with the machine; it only brings the first run forward from the next reboot to now.
# The webgui is restarted only when there was something to add, because a restart takes
# away every logged-in session's php worker.
if [ -x /usr/local/opnsense/scripts/netreport/merge_ui_translations.py ]; then
	ADDED=$(/usr/local/opnsense/scripts/netreport/merge_ui_translations.py 2> /dev/null) || ADDED=
	echo "translated strings added: ${ADDED:-0}"
	if [ -n "${ADDED}" ] && [ "${ADDED}" != "0" ]; then
		# absolute, because a pkg script does not necessarily inherit a PATH with
		# /usr/local/sbin in it - which is why os-vnstat's own post-install calls
		# /usr/local/sbin/configctl by its full path too
		[ -f /usr/local/sbin/configctl ] &&
		    /usr/local/sbin/configctl webgui restart > /dev/null 2>&1 || true
	fi
fi

echo "Network Report installed: the page is at Reporting > Network Report"
