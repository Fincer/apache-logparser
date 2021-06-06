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

**Q: Can you list me unique connections (IP addresses) associated with country and city location data, using the last Apache log file?**

```
httpd-logparser --outfields time remote_host country city -d /var/log/httpd/ -f access_log$ -np --stats | sort -k 3 -u | sort -k 4

Processed files:       access_log
Matched log entries:   724
Processed log entries: 724
2021-06-06 10:00:57     135.23.195.XXX   Canada                  Quebec
2021-06-06 04:58:58     8.210.233.XXX    China                   Guangzhou
2021-06-06 05:01:37     23.228.109.XXX   China                   Shanghai
2021-06-06 04:49:57     8.210.71.XXX     China                   Unknown: 34.772499, 113.726601
2021-06-06 09:47:32     92.151.100.XXX   France                  Boulogne-Billancourt
2021-06-06 02:05:38     195.154.122.XXX  France                  Ivry-sur-Seine
2021-06-06 03:24:22     92.116.45.XXX    Germany                 Bielefeld
2021-06-06 06:06:58     207.154.218.XXX  Germany                 Frankfurt am Main
2021-06-06 10:45:40     172.105.77.XXX   Germany                 Frankfurt am Main
2021-06-06 00:25:20     92.116.52.XXX    Germany                 Hamm
2021-06-06 05:02:54     159.69.10.XXX    Germany                 Mannheim
2021-06-06 06:24:55     89.246.127.XXX   Germany                 Schloss Holte-Stukenbrock
2021-06-06 10:08:21     138.201.56.XXX   Germany                 Unknown: 51.299301, 9.490900
2021-06-06 03:42:02     47.31.198.XXX    India                   Delhi
2021-06-06 00:15:16     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 02:10:21     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 02:32:48     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 03:26:22     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 06:52:23     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 07:00:48     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 11:10:59     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 00:23:05     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 02:46:33     92.118.160.XXX   Lithuania               Unknown: 56.000000, 24.000000
2021-06-06 05:11:20     45.131.212.XXX   Netherlands             Amsterdam
2021-06-06 05:12:40     185.180.143.XXX  Portugal                Unknown: 38.705700, -9.135900
2021-06-06 07:55:47     89.137.179.XXX   Romania                 Timisoara
2021-06-06 06:10:46     91.243.100.XXX   Russian Federation      Novocherkassk
2021-06-06 11:30:51     213.177.208.XXX  Spain                   Palencia
2021-06-06 01:41:48     184.22.158.XXX   Thailand                Thalang
2021-06-06 08:14:41     176.88.78.XXX    Turkey                  Ankara
2021-06-06 08:32:04     212.82.66.XXX    United Kingdom          Burnham
2021-06-06 03:53:41     45.146.164.XXX   United Kingdom          London
2021-06-06 04:33:42     185.158.250.XXX  United Kingdom          Manchester
2021-06-06 10:16:19     82.10.88.XXX     United Kingdom          Shrewsbury
2021-06-06 10:14:28     40.77.189.XXX    United States           Chicago
2021-06-06 08:16:07     69.170.221.XXX   United States           Colorado Springs
2021-06-06 10:57:25     192.241.206.XXX  United States           San Francisco
2021-06-06 01:09:16     128.14.209.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 06:44:49     47.243.113.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 06:45:48     47.243.116.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 08:00:40     162.244.34.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 10:30:53     47.242.214.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 04:22:27     162.244.33.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 04:34:47     47.243.48.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 06:37:16     47.243.109.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 06:42:37     162.244.33.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 06:44:49     47.243.109.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 07:04:20     47.243.113.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 07:44:23     47.243.110.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 08:29:33     47.242.12.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 10:38:15     128.14.133.XXX   United States           Unknown: 37.750999, -97.821999
2021-06-06 03:18:25     23.95.132.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 04:13:55     128.1.248.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 08:21:11     64.62.197.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 11:17:33     47.243.95.XXX    United States           Unknown: 37.750999, -97.821999
2021-06-06 08:03:24     167.56.236.XXX   Uruguay                 Castillos
```

NOTE: The last numerical part of all ip addresses are anonymized with `XXX` string.

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
usage: httpd-logparser [-h] -d [LOG_DIR] -f LOG_FILE [LOG_FILE ...] [-s [LOG_SYNTAX]] [-c STATUS_CODE [STATUS_CODE ...]] [-cf COUNTRY [COUNTRY ...]] [-ot [OUT_TIMEFORMAT]] [-of OUT_FIELD [OUT_FIELD ...]] [-ng] [-gd [GEODB]] [-dl [DAY_LOWER]] [-du [DAY_UPPER]]
                       [-sb [SORTBY_FIELD]] [-sbr [SORTBY_FIELD_REVERSE]] [-st] [-np]

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
                        Output fields. Default: log_file_name, http_status, remote_host, country, city, time, time_diff, user_agent, http_request
  -ng, --nogeo          Skip country check with external "geoiplookup" tool.
  -gd [GEODB], --geodir [GEODB]
                        Database file directory for "geoiplookup" tool. Default: /usr/share/GeoIP/
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
