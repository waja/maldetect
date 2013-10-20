#
# Regular cron jobs for the maldetect package
#
0 4	* * *	root	[ -x /usr/bin/maldetect_maintenance ] && /usr/bin/maldetect_maintenance
