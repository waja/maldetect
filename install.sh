#!/usr/bin/env bash
#
##
# Linux Malware Detect v1.6.4
#             (C) 2002-2019, R-fx Networks <proj@r-fx.org>
#             (C) 2019, Ryan MacDonald <ryan@r-fx.org>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
ver=1.6.4
ver_major=1.6
inspath=/usr/local/maldetect
logf=$inspath/logs/event_log
conftemp="$inspath/internals/importconf"
find=`which find 2> /dev/null`


clamav_linksigs() {
        cpath="$1"
        if [ -d "$cpath" ]; then
                rm -f $cpath/rfxn.* ; cp -f $inspath/sigs/rfxn.ndb $inspath/sigs/rfxn.hdb $cpath/ 2> /dev/null
                rm -f $cpath/lmd.user.* ; cp -f $inspath/sigs/lmd.user.ndb $inspath/sigs/lmd.user.hdb $cpath/ 2> /dev/null
        fi
}

if [ ! -d "$inspath" ] && [ -d "files" ]; then
	mkdir -p $inspath
	chmod 755 $inspath
	cp -pR files/* $inspath
	chmod 755 $inspath/maldet
	mkdir -p $inspath/clean $inspath/pub $inspath/quarantine $inspath/sess $inspath/sigs $inspath/tmp 2> /dev/null
	chmod 750 $inspath/quarantine $inspath/sess $inspath/tmp $inspath/internals/tlog 2> /dev/null
	ln -fs $inspath/maldet /usr/local/sbin/maldet
	ln -fs $inspath/maldet /usr/local/sbin/lmd
	cp -f CHANGELOG COPYING.GPL README $inspath/
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2> /dev/null
else
	if [ "$(ps -A --user root -o "command" 2> /dev/null | grep maldetect | grep inotifywait)" ]; then
		$inspath/maldet -k >> /dev/null 2>&1
		monmode=1
	fi
	$find ${inspath}.* -maxdepth 0 -type d -mtime +30 2> /dev/null | xargs rm -rf
	chattr -ia $inspath/internals/internals.conf
	mv $inspath $inspath.bk$$
	ln -fs $inspath.bk$$ $inspath.last
	mkdir -p $inspath
	chmod 755 $inspath
	cp -pR files/* $inspath
	chmod 755 $inspath/maldet
	ln -fs $inspath/maldet /usr/local/sbin/maldet
	ln -fs $inspath/maldet /usr/local/sbin/lmd
	mkdir -p /usr/local/share/man/man1/
	gzip -9 $inspath/maldet.1
	ln -fs $inspath/maldet.1.gz /usr/local/share/man/man1/maldet.1.gz
	cp -f $inspath.bk$$/ignore_* $inspath/  >> /dev/null 2>&1
	if [ "$ver_major" == "1.5" ] || [ "$ver_major" == "1.6" ]; then
		cp -f $inspath.bk$$/sess/* $inspath/sess/ >> /dev/null 2>&1
		cp -f $inspath.bk$$/tmp/* $inspath/tmp/ >> /dev/null 2>&1
		cp -f $inspath.bk$$/quarantine/* $inspath/quarantine/ >> /dev/null 2>&1
                cp -f $inspath.bk$$/cron/* $inspath/cron/
	fi
	cp -f $inspath.bk$$/sigs/custom.* $inspath/sigs/ >> /dev/null 2>&1
	cp -f $inspath.bk$$/monitor_paths $inspath/ >> /dev/null 2>&1
	cp -pf $inspath.bk$$/clean/custom.* $inspath/clean/ >> /dev/null 2>&1
	cp -f CHANGELOG COPYING.GPL README $inspath/
	mkdir -p $inspath/clean $inspath/pub $inspath/quarantine $inspath/sess $inspath/sigs $inspath/tmp 2> /dev/null
	chmod 750 $inspath/quarantine $inspath/sess $inspath/tmp $inspath/internals/tlog 2> /dev/null
	clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2> /dev/null
fi

if [ -d "/etc/cron.daily" ]; then
	cp -f cron.daily /etc/cron.daily/maldet
	chmod 755 /etc/cron.daily/maldet
fi

if [ -d "/etc/cron.d" ]; then
	cp -f cron.d.pub /etc/cron.d/maldet_pub
	chmod 644 /etc/cron.d/maldet_pub
fi

if [ "$(uname -s)" != "FreeBSD" ]; then
        if test "$(cat /proc/1/comm 2> /dev/null)" == "systemd"
        then
                mkdir -p /etc/systemd/system/
                mkdir -p /usr/lib/systemd/system/
                cp -af ./files/service/maldet.service /usr/lib/systemd/system/
                systemctl daemon-reload
                systemctl enable maldet.service
	else
                cp -af ./files/service/maldet.sh /etc/init.d/maldet
                chmod 755 /etc/init.d/maldet
		chkconfig --level 2345 maldet on
	fi
	if [ -f /etc/redhat-release ]; then
		if [ ! -f "/etc/sysconfig/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet
		fi
	elif [ -f /etc/debian_version ] || [ -f /etc/lsb-release ]; then
		if [ ! -f "/etc/default/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/default/maldet
		fi
		update-rc.d -f maldet remove
		update-rc.d maldet defaults 70 30
	elif [ -f /etc/gentoo-release ]; then
		rc-update add maldet default
	elif [ -f /etc/slackware-version ]; then
		ln -sf /etc/init.d/maldet /etc/rc.d/rc3.d/S70maldet
		ln -sf /etc/init.d/maldet /etc/rc.d/rc4.d/S70maldet
		ln -sf /etc/init.d/maldet /etc/rc.d/rc5.d/S70maldet
	else
		if [ ! -f "/etc/sysconfig/maldet" ]; then
			cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet 2> /dev/null
		fi
		/sbin/chkconfig maldet on
	fi
fi

mkdir -p $inspath/logs && touch $logf
ln -fs $logf $inspath/event_log
$inspath/maldet --alert-daily 2> /dev/null

echo "Linux Malware Detect v$ver"
echo "            (C) 2002-2019, R-fx Networks <proj@r-fx.org>"
echo "            (C) 2019, Ryan MacDonald <ryan@r-fx.org>"
echo "This program may be freely redistributed under the terms of the GNU GPL"
echo ""
echo "installation completed to $inspath"
echo "config file: $inspath/conf.maldet"
echo "exec file: $inspath/maldet"
echo "exec link: /usr/local/sbin/maldet"
echo "exec link: /usr/local/sbin/lmd"
echo "cron.daily: /etc/cron.daily/maldet"
if [ -f "$conftemp" ] && [ -f "${inspath}.last/conf.maldet" ]; then
	. files/conf.maldet
	. ${inspath}.last/conf.maldet
	if [ "$quarantine_hits" == "0" ] && [ "$quar_hits" == "1" ]; then
		quarantine_hits=1
	fi
	if [ "$quarantine_clean" == "0" ] && [ "$quar_clean" == "1" ]; then
		quarantine_clean="1"
	fi
	if [ -f "files/internals/compat.conf" ]; then
		source files/internals/compat.conf
	fi
	source $conftemp
	echo "imported config options from $inspath.last/conf.maldet"
fi
$inspath/maldet --update 1
if [ "$monmode" == "1" ]; then
	echo "detected active monitoring mode, restarted inotify watch with '-m users'"
	$inspath/maldet -m users >> /dev/null 2>&1 &
fi
echo ""
