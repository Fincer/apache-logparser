# Apache log parser

Simple Apache/HTTPD command-line log parser for short analysis, targeted to web server administration tasks.

Unix-alike systems only.

## Motivation

Keep it simple. Very simple.

Although advanced and nice-looking log analytic tools such as [Elastic Stack](https://www.elastic.co/products/) exists, I wanted something far more simple and with far less overhead for weekly tasks and for configuring an Apache web server. Therefore, I wrote this simple Python script to parse Apache web server logs.

**Advantages** of this tool are little overhead, piping output to other Unix tools and doing some quick log checks. The main idea is to give desired output for short analysis so that you can properly configure your web server protection mechanisms and network environment based on the actual server data.

This tool is not for intrusion detection/prevention or does not alert administration about hostile penetration attempts. However, it may reveal simple underlying misconfigurations such as invalid URL references on your website.

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

run `updpkgsums && makepkg -Cfi` in [apache-logparser](apache-logparser/) directory. The command installs `httpd-logparser` executable file in `/usr/bin/` folder.

## Supported output formats

- `table` and `csv`

## Examples

**Q: List unique connections (IP addresses) associated with country and city location data, using the last Apache log file?**

```
httpd-logparser --files-list /var/log/httpd/access_log --included-fields time,remote_host,country,city | sort -k 2 -u | sort -k 3

103.102.153.XXX Indonesia               Unknown: -6.175000, 106.828598  2022-06-12 10:33:58 
103.102.153.XXX Indonesia               Unknown: -6.175000, 106.828598  2022-06-12 10:33:59 
103.102.153.XXX Indonesia               Unknown: -6.175000, 106.828598  2022-06-12 10:34:00 
103.102.153.XXX Indonesia               Unknown: -6.175000, 106.828598  2022-06-12 10:34:01 
103.144.178.XXX Indonesia               Unknown: -6.175000, 106.828598  2022-06-16 06:34:19 
62.214.113.XXX  Germany                 Unterhaching    2022-06-10 14:39:16 
62.214.113.XXX  Germany                 Unterhaching    2022-06-10 16:34:15 
62.214.113.XXX  Germany                 Unterhaching    2022-06-10 16:40:03 
62.214.113.XXX  Germany                 Unterhaching    2022-06-10 16:40:04 
62.214.113.XXX  Germany                 Unterhaching    2022-06-10 16:40:05 
84.234.169.XXX  Norway                  Valderoy        2022-06-06 00:20:18 
194.137.241.XXX Finland                 Vantaa          2022-06-07 12:20:42 
194.137.241.XXX Finland                 Vantaa          2022-06-07 12:20:43 
194.137.241.XXX Finland                 Vantaa          2022-06-07 12:20:44
...
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-07 21:25:38 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-07 21:25:39 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-07 21:25:40 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-07 21:25:41 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-07 21:25:42 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-08 23:35:25 
176.108.111.XXX Ukraine                 Vyzhnytsya      2022-06-11 19:52:42 
82.207.245.XXX  Germany                 Wachtberg       2022-06-03 02:26:58 
82.207.245.XXX  Germany                 Wachtberg       2022-06-03 02:27:08 
82.207.245.XXX  Germany                 Wachtberg       2022-06-03 02:27:09 
82.207.245.XXX  Germany                 Wachtberg       2022-06-03 02:27:10 
79.191.159.XXX  Poland                  Warsaw          2022-06-11 18:05:13 
49.7.20.XXX     China                   Wenzhou         2022-06-09 15:26:26 
49.7.21.XXX     China                   Wenzhou         2022-06-09 23:25:57 
49.7.20.XXX     China                   Wenzhou         2022-06-19 01:41:41 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:45:21 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:10 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:11 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:12 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:13 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:14 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:41 
81.82.244.XXX   Belgium                 Wetteren        2022-06-13 13:49:46 
95.223.231.XXX  Germany                 Wiesbaden       2022-06-04 21:42:20 
95.223.231.XXX  Germany                 Wiesbaden       2022-06-04 21:42:21 
95.223.231.XXX  Germany                 Wiesbaden       2022-06-04 21:42:23 
95.223.231.XXX  Germany                 Wiesbaden       2022-06-04 21:42:28 
37.201.116.XXX  Germany                 Wiesbaden       2022-06-10 19:55:50 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:21 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:22 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:23 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:25 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:26 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:57 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:51:58 
113.57.152.XXX  China                   Wuhan           2022-06-14 15:52:01 
89.164.183.XXX  Croatia                 Zagreb          2022-06-04 11:44:22 
89.164.183.XXX  Croatia                 Zagreb          2022-06-04 11:44:23 
89.164.183.XXX  Croatia                 Zagreb          2022-06-04 11:44:24 
89.164.183.XXX  Croatia                 Zagreb          2022-06-04 11:44:25 
89.164.183.XXX  Croatia                 Zagreb          2022-06-04 11:44:26 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:49 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:51 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:52 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:53 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:55 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:56 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:45:59 
86.32.46.XXX    Croatia                 Zagreb          2022-06-04 16:46:00 
85.10.56.XXX    Croatia                 Zagreb          2022-06-09 19:39:55 
85.10.56.XXX    Croatia                 Zagreb          2022-06-17 19:57:56 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:41 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:42 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:43 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:44 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:45 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:46 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:47 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:48 
122.56.232.XXX  New Zealand             Auckland        2022-06-02 08:46:49 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:22 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:23 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:24 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:25 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:26 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:27 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:28 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:29 
121.98.28.XXX   New Zealand             Dunedin         2022-06-08 14:32:30 
185.113.213.XXX Netherlands             Zennewijnen     2022-06-15 11:54:36 
185.113.213.XXX Netherlands             Zennewijnen     2022-06-15 11:54:37 
185.113.213.XXX Netherlands             Zennewijnen     2022-06-15 11:54:39
```

NOTE: The last numerical part of all ip addresses are anonymized with `XXX` string.

**Q: How many valid requests from Finland and Sweden occured between 15th - 24th April 2022?**

```
httpd-logparser --files-regex /var/log/httpd/access_log --included-fields time,http_status,country --sort-by time --status-codes ^20* --day-lower "15-04-2022" --day-upper "24-04-2022" --countries Finland,Sweden --show-stats --show-progress

File count: 5
Lines in total: 86876
Processing file: /var/log/httpd/access_log (lines: 23116)
Processing file: /var/log/httpd/access_log.1 (lines: 21566)
Processing file: /var/log/httpd/access_log.2 (lines: 13490)
Processing file: /var/log/httpd/access_log.3 (lines: 13822)
Processing file: /var/log/httpd/access_log.4 (lines: 14882)
Processing log entry: 81924 (94.30%)

...
200     Sweden                  2022-04-17 21:51:09 
200     Sweden                  2022-04-17 21:51:10 
200     Sweden                  2022-04-17 21:51:10 
200     Sweden                  2022-04-17 23:41:35 
200     Sweden                  2022-04-17 23:41:36 
200     Sweden                  2022-04-17 23:41:36 
200     Sweden                  2022-04-17 23:41:39 
200     Sweden                  2022-04-18 11:23:18 
200     Sweden                  2022-04-19 07:16:25 
200     Sweden                  2022-04-19 07:16:34 
200     Finland                 2022-04-19 11:47:51 
200     Finland                 2022-04-19 11:47:52 
200     Finland                 2022-04-19 11:47:52 
200     Finland                 2022-04-19 11:47:52
...
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 09:51:16 
200     Finland                 2022-04-22 12:38:49 
200     Finland                 2022-04-22 16:53:11
...

Processed files:       /var/log/httpd/access_log, /var/log/httpd/access_log.1, /var/log/httpd/access_log.2, /var/log/httpd/access_log.3, /var/log/httpd/access_log.4
Processed log entries: 86876
Matched log entries:   533
```

Answer: 533

**Q: How many redirects have occured since the 1st April 2022 according to two selected log files?**

```
httpd-logparser --outfields time http_status country -d /var/log/httpd/ -c ^30* -f access_log* -dl "01-04-2020" --sortby time --stats

httpd-logparser --files-regex /var/log/httpd/access_log.\[2-3\] --included-fields time,http_status,country --sort-by time --status-codes ^30* --day-lower "01-04-2022" --show-stats

...
304     Canada                  2022-05-23 01:52:45 
302     Canada                  2022-05-23 01:53:33 
302     Europe                  2022-05-23 01:56:03 
302     Poland                  2022-05-23 02:00:31 
302     Russian Federation      2022-05-23 02:52:50 
302     United States           2022-05-23 04:34:30 
302     France                  2022-05-23 04:51:31 
302     Germany                 2022-05-23 05:02:16 
302     Russian Federation      2022-05-23 05:04:13 
302     Russian Federation      2022-05-23 05:04:14 
302     Russian Federation      2022-05-23 05:04:14 
302     United States           2022-05-23 05:11:10 
302     United States           2022-05-23 05:11:11 
302     Russian Federation      2022-05-23 05:23:09 
302     China                   2022-05-23 05:54:41
...
302     Germany                 2022-05-31 19:53:18 
302     Germany                 2022-05-31 19:53:18 
302     Germany                 2022-05-31 19:53:18 
302     Germany                 2022-05-31 19:53:19 
302     Germany                 2022-05-31 19:53:19 
304     Finland                 2022-05-31 20:06:55 
304     Finland                 2022-05-31 20:16:02 
304     Finland                 2022-05-31 20:16:03 
304     Finland                 2022-05-31 20:16:06 
302     Russian Federation      2022-05-31 20:40:33 
302     United Kingdom          2022-05-31 21:09:32 
302     China                   2022-05-31 21:13:38 
302     Russian Federation      2022-05-31 21:20:09 
302     Romania                 2022-05-31 22:01:31 
304     United States           2022-05-31 22:11:30 
302     Russian Federation      2022-05-31 22:59:23 
302     United States           2022-05-31 23:16:52 
304     Ukraine                 2022-05-31 23:22:50 
302     Russian Federation      2022-05-31 23:30:51 
302     Netherlands             2022-05-31 23:37:10 
302     Netherlands             2022-05-31 23:37:11 
302     Netherlands             2022-05-31 23:37:12

Processed files:       /var/log/httpd/access_log.2, /var/log/httpd/access_log.3
Processed log entries: 77730
Matched log entries:   6788

Invalid lines:
        File: /var/log/httpd/access_log.2, line: 24668

```

Answer: 6788

You should also check any invalid log lines detected by the tool.

**Q: How many `4XX` codes have connected clients from China and United States produced?**

```
httpd-logparser --files-regex /var/log/httpd/access_log --included-fields time,country,http_status,http_request --countries "United States",China --sort-by time --status-codes ^4 --show-progress --show-stats

File count: 2
Lines in total: 23614
Processing file: /var/log/httpd/access_log (lines: 12021)
Processing file: /var/log/httpd/access_log.1 (lines: 11593)
Processing log entry: 18423 (78.01%)
...

408     United States           2022-06-01 03:45:18     None
408     United States           2022-06-01 03:45:18     None
408     United States           2022-06-01 09:11:15     None
408     United States           2022-06-01 11:36:05     None
408     United States           2022-06-01 11:36:05     None
421     United States           2022-06-01 13:08:29     GET / HTTP/1.1
408     United States           2022-06-01 19:44:42     None
408     United States           2022-06-01 19:44:42     None
408     China                   2022-06-02 06:30:51     None
408     China                   2022-06-02 06:30:51     None
408     China                   2022-06-02 06:30:51     None
408     United States           2022-06-02 11:45:57     None
408     United States           2022-06-02 11:46:05     None
408     United States           2022-06-02 11:46:18     None
408     United States           2022-06-02 20:53:49     None
408     United States           2022-06-02 20:53:49     None
408     United States           2022-06-03 00:01:39     None
408     United States           2022-06-03 00:02:04     None
408     United States           2022-06-03 00:02:37     None
408     United States           2022-06-03 00:21:26     None
408     China                   2022-06-03 11:39:22     None
408     United States           2022-06-03 15:41:34     None
408     United States           2022-06-04 01:28:08     None
408     United States           2022-06-04 07:29:53     None
408     United States           2022-06-04 07:29:56     None
408     United States           2022-06-04 07:29:56     None
408     United States           2022-06-04 11:25:10     None
408     United States           2022-06-04 11:25:10     None
408     China                   2022-06-04 11:37:11     None
408     United States           2022-06-04 17:36:35     None
408     China                   2022-06-05 15:56:35     None
408     China                   2022-06-05 15:56:45     None
408     United States           2022-06-06 01:32:25     None
408     United States           2022-06-06 01:32:25     None
408     United States           2022-06-06 01:32:29     None
...

Processed files:       /var/log/httpd/access_log, /var/log/httpd/access_log.1
Processed log entries: 23614
Matched log entries:   112
```

Answer: 112

**Q: Which user agents clients have used recently?**

```
httpd-logparser --files-list /var/log/httpd/access_log --included-fields user_agent | sort -u

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

**Q: Which is time difference between single client requests? Exclude Finland. Include all access_log files.**

```
httpd-logparser --included-fields http_status,time,time_diff,country --countries "\!Finland" --files-regex /var/log/httpd/old/access_log

200     Taiwan                  2022-06-19 12:21:47     NEW_CONN
200     Taiwan                  2022-06-19 12:21:48     +1      
200     Taiwan                  2022-06-19 12:21:49     +1      
200     Taiwan                  2022-06-19 12:21:49     0       
200     Taiwan                  2022-06-19 12:21:49     0       
200     Taiwan                  2022-06-19 12:21:49     0       
200     Taiwan                  2022-06-19 12:21:50     +1      
200     Taiwan                  2022-06-19 12:21:49     -1      
200     Taiwan                  2022-06-19 12:21:49     0       
200     Taiwan                  2022-06-19 12:21:50     +1      
200     Taiwan                  2022-06-19 12:21:50     0       
200     Taiwan                  2022-06-19 12:21:50     0       
200     Taiwan                  2022-06-19 12:21:51     +1      
200     Taiwan                  2022-06-19 12:21:56     +5      
200     Taiwan                  2022-06-19 12:22:04     +8      
200     Taiwan                  2022-06-19 12:22:05     +1      
200     Taiwan                  2022-06-19 12:22:06     +1      
200     Taiwan                  2022-06-19 12:22:06     0       
200     Taiwan                  2022-06-19 12:22:06     0       
302     Taiwan                  2022-06-19 12:22:07     +1      
200     Taiwan                  2022-06-19 12:22:07     0       
200     Taiwan                  2022-06-19 12:22:07     0       
200     Taiwan                  2022-06-19 12:22:07     0       
200     Taiwan                  2022-06-19 12:22:07     0       
200     Taiwan                  2022-06-19 12:22:07     0       
200     Taiwan                  2022-06-19 12:22:14     +7      
200     Taiwan                  2022-06-19 12:22:14     0       
200     Japan                   2022-06-19 12:34:49     NEW_CONN
200     Japan                   2022-06-19 12:34:54     +5      
200     United States           2022-06-19 12:55:44     NEW_CONN
200     United States           2022-06-19 12:55:44     0       
200     United States           2022-06-19 12:55:50     +6      
200     United States           2022-06-19 12:55:55     +5      
302     France                  2022-06-19 13:01:30     NEW_CONN
200     United States           2022-06-19 13:10:07     NEW_CONN
200     United States           2022-06-19 13:10:12     +5      
302     China                   2022-06-19 13:15:59     NEW_CONN
302     China                   2022-06-19 13:16:10     +11     
302     China                   2022-06-19 13:16:11     +1      
200     Germany                 2022-06-19 13:27:42     NEW_CONN
200     Hong Kong               2022-06-19 13:40:02     NEW_CONN
200     Hong Kong               2022-06-19 13:40:02     0       
200     Hong Kong               2022-06-19 13:40:02     0       
...
200     India                   2022-06-19 13:45:03     NEW_CONN
200     India                   2022-06-19 13:45:04     +1      
200     India                   2022-06-19 13:45:04     0       
200     India                   2022-06-19 13:45:04     0       
200     India                   2022-06-19 13:45:04     0       
200     India                   2022-06-19 13:45:05     +1      
200     India                   2022-06-19 13:45:05     0       
200     India                   2022-06-19 13:45:05     0
...
```

## Usage

```
usage: httpd-logparser [-h] [-fr [FILES_REGEX]] [-f [FILES_LIST]] [-c CODES [CODES ...]] [-cf [COUNTRIES]] [-tf [TIME_FORMAT]] [-if [INCL_FIELDS]]
                     [-ef [EXCL_FIELDS]] [-gl] [-ge [GEOTOOL_EXEC]] [-gd [GEO_DATABASE_LOCATION]] [-dl [DATE_LOWER]] [-du [DATE_UPPER]]
                     [-sb [SORTBY_FIELD]] [-ro] [-st] [-p] [--httpd-conf-file] [--httpd-log-nickname] [-lf LOG_FORMAT] [-ph]
                     [--output-format {table,csv}]

Apache HTTPD server log parser

optional arguments:
  -h, --help            show this help message and exit
  -fr [FILES_REGEX], --files-regex [FILES_REGEX]
                        Apache log files matching input regular expression. (default: None)
  -f [FILES_LIST], --files-list [FILES_LIST]
                        Apache log files. Regular expressions supported. (default: None)
  -c CODES [CODES ...], --status-codes CODES [CODES ...]
                        Print only these numerical status codes. Regular expressions supported. (default: None)
  -cf [COUNTRIES], --countries [COUNTRIES]
                        Include only these countries. Negative match (exclude): "\!Country" (default: None)
  -tf [TIME_FORMAT], --time-format [TIME_FORMAT]
                        Output time format. (default: %d-%m-%Y %H:%M:%S)
  -if [INCL_FIELDS], --included-fields [INCL_FIELDS]
                        Included fields. All fields: all, log_file_name, http_status, remote_host, country, city, time, time_diff, user_agent,
                        http_request (default: http_status, remote_host, time, time_diff, user_agent, http_request)
  -ef [EXCL_FIELDS], --excluded-fields [EXCL_FIELDS]
                        Excluded fields. (default: None)
  -gl, --geo-location   Check origin countries with external "geoiplookup" tool. NOTE: Automatically includes "country" and "city" fields. (default:
                        False)
  -ge [GEOTOOL_EXEC], --geotool-exec [GEOTOOL_EXEC]
                        "geoiplookup" tool executable found in PATH. (default: geoiplookup)
  -gd [GEO_DATABASE_LOCATION], --geo-database-dir [GEO_DATABASE_LOCATION]
                        Database file directory for "geoiplookup" tool. (default: /usr/share/GeoIP/)
  -dl [DATE_LOWER], --day-lower [DATE_LOWER]
                        Do not check log entries older than this day. Day syntax: 31-12-2020 (default: None)
  -du [DATE_UPPER], --day-upper [DATE_UPPER]
                        Do not check log entries newer than this day. Day syntax: 31-12-2020 (default: None)
  -sb [SORTBY_FIELD], --sort-by [SORTBY_FIELD]
                        Sort by an output field. (default: None)
  -ro, --reverse-order  Sort in reverse order. (default: False)
  -st, --show-stats     Show short statistics at the end. (default: False)
  -p, --show-progress   Show progress information. (default: False)
  --httpd-conf-file     Apache HTTPD configuration file with LogFormat directive. (default: /etc/httpd/conf/httpd.conf)
  --httpd-log-nickname  LogFormat directive nickname (default: combinedio)
  -lf LOG_FORMAT, --log-format LOG_FORMAT
                        Log format, manually defined. (default: None)
  -ph, --print-headers  Print column headers. (default: False)
  --output-format {table,csv}
                        Output format for results. (default: table)
```

## License

GPLv3.
