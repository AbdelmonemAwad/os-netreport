#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-netreport have been removed. pkg does not run this
# during an upgrade - it runs the new post-install instead - so everything here may assume
# the plugin is going for good.
#
# pkg has already removed every file the package owns, including the cron line in
# /usr/local/etc/cron.d/netreport and the boot hook, and every directory under them that
# it created and that is now empty. What is left is what pkg cannot know about: the entry
# this plugin made in config.xml, and the GUI's caches.

# Take the plugin back out of config.xml's system/firmware/plugins. Left in, it would be a
# plugin OPNsense believes it is managing and cannot find, and the next plugin sync would
# try to install it from a repository that has never heard of it.
if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php remove os-netreport > /dev/null 2>&1 || true
fi

# actions_netreport.conf is gone; configd is still holding it.
if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

# system_cache_flush(): without it the menu keeps a dead entry and the user manager keeps
# an ACL tag pointing at a page that is not there, for up to an hour each.
if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_DEINSTALL
fi

# Three things are kept on purpose, and all three are named here rather than left for
# somebody to find later:
#
#   the settings in config.xml, including the schedule and the recipients.
#
#   /var/db/netreport - the device database, the history and the archived reports. Without
#   it a reinstall has never seen any of these devices before and the first report calls
#   the whole network new.  Remove it with:  rm -rf /var/db/netreport
#
#   the strings merged into the GUI gettext catalogues. They are msgids that nothing on
#   the machine asks for any more, so they are never looked up, and the next update of
#   opnsense-lang, which owns those files, replaces them outright. There is no supported
#   way to take one string back out of a compiled .mo, which is why this does not try.
#   Until then pkg check -s opnsense-lang will name each altered catalogue; that is the
#   hand installation's doing as much as the package's, and it is not a fault.
echo "Network Report removed; the settings in config.xml are kept"
