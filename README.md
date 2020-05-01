# Apache log parser

Simple Apache/HTTPD command-line log parser for short analysis, targeted to web server administration tasks.

Unix-alike systems only.

## Motivation

Keep it simple. Very simple.

Although advanced and nice-looking log analytic tools such as [Elastic Stack](https://www.elastic.co/products/) exists (I have used it), I wanted something far more simple and with far less overhead for weekly tasks and for configuring an Apache web server. Therefore, I wrote this simple Python script to parse Apache web server logs.

**Advantages** of this tool are little overhead, piping output to other Unix tools and doing some quick log checks. The main idea is to give desired output for short analysis so that you can properly configure your web server protection mechanisms and network environment based on the actual server data.

This tool is not for intrusion detection/prevention or does not alert administration about hostile penetration attempts. However, it may reveal simple underlying misconfigurations such as invalid URL references on your site.

## Requirements

Following Arch Linux packages. If you use another distribution, refer to corresponding packages:

```
python
python-apachelogs
```

[python-apachelogs](https://github.com/jwodder/apachelogs/) is not available either on Arch Linux repositories or AUR repositories. Therefore, I provide a PKGBUILD file to install it. [python-apachelogs - PKGBUILD](python-apachelogs/PKGBUILD)

`python-apachelogs` has a sub-dependency of [python-pydicti](python-apachelogs/python-pydicti/PKGBUILD) package.

Recommended packages for IP address geo-location:

```
geoip
geoip-database
```

## Installation

Arch Linux:

run `updpkgsums && makepkg -Cfi` in [apache-logparser](apache-logparser/) directory. Installs `httpd-logparser` executable file in `/usr/bin/` folder.

## Examples

**Q: How many valid requests from Finland and Sweden occured between 15th - 24th April 2020?**

```
httpd-logparser --outfields time http_status country -d /var/log/httpd/ -c ^20* -f access_log* -cf Finland Sweden -dl "15-04-2020" -du "24-04-2020" --sortby time --stats


Processing file: access_log
Processing file: access_log.1
Processing file: access_log.2
Processing file: access_log.3
Processing file: access_log.4
Processing log entry: 883

2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
2020-04-17 08:47:05     200     Finland
...
...
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:07     200     Finland
2020-04-23 18:04:08     200     Finland

Processed files:       access_log, access_log.1, access_log.2, access.log_3, access_log.4
Processed log entries: 883
Matched log entries:   211
```


**Q: How many redirects have occured since 01st April 2020?**

```
httpd-logparser --outfields time http_status country -d /var/log/httpd/ -c ^30* -f access_log* -dl "01-04-2020" --sortby time --stats

Processing file: access_log
Processing file: access_log.1
Processing file: access_log.2
Processing file: access_log.3
Processing file: access_log.4
Processing log entry: 8993

2020-04-01 02:13:12     302     United States
2020-04-01 02:13:12     302     United States
2020-04-01 02:13:13     301     United States
2020-04-01 02:13:13     302     United States
2020-04-01 02:13:14     302     United States
2020-04-01 02:13:14     302     United States
2020-04-01 02:13:14     302     United States
2020-04-01 02:13:15     302     United States
2020-04-01 02:13:15     302     United States
2020-04-01 03:25:06     302     United States
2020-04-01 04:03:39     302     Russian Federation
2020-04-01 04:03:44     302     Russian Federation
...
...
2020-05-01 18:53:05     302     Italy
2020-05-01 18:53:21     301     Italy
2020-05-01 18:53:22     301     Italy
2020-05-01 18:53:24     302     Italy
2020-05-01 18:53:25     302     Italy
2020-05-01 18:53:26     302     Italy
2020-05-01 18:53:26     302     Italy
2020-05-01 18:54:20     302     Italy
2020-05-01 19:18:15     301     Russian Federation
2020-05-01 19:18:15     301     Russian Federation
2020-05-01 19:18:15     301     Russian Federation
2020-05-01 19:18:17     301     Russian Federation
2020-05-01 19:21:19     302     France

Processed files:       access_log, access_log.1, access_log.2, access_log.3, access_log.4
Processed log entries: 8994
Matched log entries:   3207
```

**Q: How many `4XX` codes have connected clients from China and United States produced in all time?**

```
httpd-logparser --outfields time country http_status http_request -d /var/log/httpd/ -c ^4 -f access_log* -cf "United States" China --sortby time --stats

Processing file: access_log
Processing file: access_log.1
Processing file: access_log.2
Processing file: access_log.3
Processing file: access_log.4
Processing log entry: 10221

2020-03-29 18:49:34     United States           408     None
2020-03-29 18:49:34     United States           408     None
2020-03-29 19:28:02     China                   408     None
2020-04-08 06:14:48     China                   400     GET /phpMyAdmin/scripts/setup.php HTTP/1.1
2020-04-08 06:14:53     China                   400     GET /horde/imp/test.php HTTP/1.1
2020-04-08 06:14:54     China                   400     GET /login?from=0.000000 HTTP/1.1
...
...
2020-04-24 10:40:16     United States           403     GET /MAPI/API HTTP/1.1
2020-04-24 11:33:16     United States           403     GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1
2020-04-24 13:00:12     United States           403     GET /cgi-bin/luci HTTP/1.1
2020-04-24 13:00:13     United States           403     GET /dana-na/auth/url_default/welcome.cgi HTTP/1.1
2020-04-24 13:00:15     United States           403     GET /remote/login?lang=en HTTP/1.1
2020-04-24 13:00:17     United States           403     GET /index.asp HTTP/1.1
2020-04-24 13:00:18     United States           403     GET /htmlV/welcomeMain.htm HTTP/1.1
2020-04-24 20:08:20     United States           403     GET /dana-na/auth/url_default/welcome.cgi HTTP/1.1
2020-04-24 20:08:22     United States           403     GET /remote/login?lang=en HTTP/1.1
2020-04-25 03:57:39     United States           403     GET /home.asp HTTP/1.1
2020-04-25 03:57:39     United States           403     GET /login.cgi?uri= HTTP/1.1
2020-04-25 03:57:39     United States           403     GET /vpn/index.html HTTP/1.1
2020-04-25 03:57:39     United States           403     GET /cgi-bin/luci HTTP/1.1
2020-04-25 03:57:40     United States           403     GET /dana-na/auth/url_default/welcome.cgi HTTP/1.1
2020-04-25 03:57:40     United States           403     GET /remote/login?lang=en HTTP/1.1
2020-04-25 03:57:40     United States           403     GET /index.asp HTTP/1.1
2020-04-25 03:57:40     United States           403     GET /htmlV/welcomeMain.htm HTTP/1.1
2020-04-25 11:56:32     United States           403     GET /owa/auth/logon.aspx?url=https%3a%2f%2f1%2fecp%2f HTTP/1.1
2020-04-25 21:29:50     United States           403     GET /images/favicon-32x32.png HTTP/1.1
2020-04-25 21:30:08     United States           408     None

Processed files:       access_log, access_log.1, access_log.2, access_log.3, access_log.4
Processed log entries: 10222
Matched log entries:   90
```

**Q: Which user agents are used by all clients in all time?**

```
httpd-logparser --outfields user_agent -d /var/log/httpd/ -f access_log* --noprogress | sort -u

facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)
fasthttp
Go-http-client/1.1
HTTP Banner Detection (https://security.ipip.net)
kubectl/v1.12.0 (linux/amd64) kubernetes/0ed3388
libwww-perl/5.833
libwww-perl/6.06
libwww-perl/6.43
Microsoft Office Word 2014
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50728)
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.30729; .NET CLR 3.5.30729; Tablet PC 2.0)
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.2)
...
...
Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Mozilla/5.0 (X11; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0
Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0
Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0
Mozilla/5.0 zgrab/0.x
Mozilla/5.0 zgrab/0.x (compatible; Researchscan/t12sns; +http://researchscan.comsys.rwth-aachen.de)
Mozilla/5.0 zgrab/0.x (compatible; Researchscan/t13rl; +http://researchscan.comsys.rwth-aachen.de)
NetSystemsResearch studies the availability of various services across the internet. Our website is netsystemsresearch.com
None
python-requests/1.2.3 CPython/2.7.16 Linux/4.14.165-102.185.amzn1.x86_64
python-requests/2.10.0
python-requests/2.19.1
python-requests/2.22.0
python-requests/2.23.0
python-requests/2.6.0 CPython/2.7.5 Linux/3.10.0-1062.12.1.el7.x86_64
python-requests/2.6.0 CPython/2.7.5 Linux/3.10.0-1062.18.1.el7.x86_64
Python-urllib/3.7
Ruby
Wget/1.19.4 (linux-gnu)
WinHTTP/1.1
```

**Q: Time difference between a single client requests? Exclude Finland! Include only the most recent access_log file.**

```
httpd-logparser --outfields http_status time time_diff country -d /var/log/httpd/ -cf "\!Finland" -f access_log$

200     2020-05-01 18:53:07     +2.0            Italy
200     2020-05-01 18:53:19     +12.0           Italy
200     2020-05-01 18:53:20     +1.0            Italy
200     2020-05-01 18:53:20     0.0             Italy
200     2020-05-01 18:53:21     +1.0            Italy
200     2020-05-01 18:53:20     -1.0            Italy
200     2020-05-01 18:53:21     +1.0            Italy
200     2020-05-01 18:53:21     0.0             Italy
301     2020-05-01 18:53:21     0.0             Italy
301     2020-05-01 18:53:22     +1.0            Italy
200     2020-05-01 18:53:22     0.0             Italy
200     2020-05-01 18:53:22     0.0             Italy
200     2020-05-01 18:53:23     +1.0            Italy
200     2020-05-01 18:53:23     0.0             Italy
302     2020-05-01 18:53:24     +1.0            Italy
200     2020-05-01 18:53:24     0.0             Italy
200     2020-05-01 18:53:25     +1.0            Italy
302     2020-05-01 18:53:25     0.0             Italy
302     2020-05-01 18:53:26     +1.0            Italy
302     2020-05-01 18:53:26     0.0             Italy
200     2020-05-01 18:53:26     0.0             Italy
200     2020-05-01 18:53:27     +1.0            Italy
200     2020-05-01 18:53:32     +5.0            Italy
302     2020-05-01 18:54:20     +48.0           Italy
408     2020-05-01 18:54:40     +20.0           Italy
...
...
200     2020-05-01 22:14:36     NEW_CONN        Russian Federation
200     2020-05-01 22:30:40     +964.0          Russian Federation
500     2020-05-01 22:35:01     NEW_CONN        Singapore
500     2020-05-01 22:35:06     +5.0            Singapore
500     2020-05-01 22:35:09     +3.0            Singapore
500     2020-05-01 22:35:14     +5.0            Singapore
200     2020-05-01 22:37:47     NEW_CONN        Russian Federation
...
...
```

## Usage

```
usage: httpd-logparser [-h] -d [LOG_DIR] -f LOG_FILE [LOG_FILE ...] [-s [LOG_SYNTAX]] [-c STATUS_CODE [STATUS_CODE ...]] [-cf COUNTRY [COUNTRY ...]] [-ot [OUT_TIMEFORMAT]]
                       [-of OUT_FIELD [OUT_FIELD ...]] [-ng] [-dl [DAY_LOWER]] [-du [DAY_UPPER]] [-sb [SORTBY_FIELD]] [-sbr [SORTBY_FIELD_REVERSE]] [-st] [-np]

optional arguments:
  -h, --help            show this help message and exit
  -d [LOG_DIR], --dir [LOG_DIR]
                        Apache log file directory.
  -f LOG_FILE [LOG_FILE ...], --files LOG_FILE [LOG_FILE ...]
                        Apache log files. Regular expressions supported.
  -s [LOG_SYNTAX], --logsyntax [LOG_SYNTAX]
                        Apache log files syntax, defined as "LogFormat" directive in Apache configuration.
  -c STATUS_CODE [STATUS_CODE ...], --statuscodes STATUS_CODE [STATUS_CODE ...]
                        Print only these status codes. Regular expressions supported.
  -cf COUNTRY [COUNTRY ...], --countryfilter COUNTRY [COUNTRY ...]
                        Include only these countries. Negative match (exclude): "\!Country"
  -ot [OUT_TIMEFORMAT], --outtimeformat [OUT_TIMEFORMAT]
                        Output time format. Default: "%d-%m-%Y %H:%M:%S"
  -of OUT_FIELD [OUT_FIELD ...], --outfields OUT_FIELD [OUT_FIELD ...]
                        Output fields. Default: log_file_name, http_status, remote_host, country, time, time_diff, user_agent, http_request
  -ng, --nogeo          Skip country check with external "geoiplookup" tool.
  -dl [DAY_LOWER], --daylower [DAY_LOWER]
                        Do not check log entries older than this day. Day syntax: 31-12-2020
  -du [DAY_UPPER], --dayupper [DAY_UPPER]
                        Do not check log entries newer than this day. Day syntax: 31-12-2020
  -sb [SORTBY_FIELD], --sortby [SORTBY_FIELD]
                        Sort by an output field.
  -sbr [SORTBY_FIELD_REVERSE], --sortbyreverse [SORTBY_FIELD_REVERSE]
                        Sort by an output field, reverse order.
  -st, --stats          Show short statistics at the end.
  -np, --noprogress     Do not show progress information.
```

## License

GPLv3.
