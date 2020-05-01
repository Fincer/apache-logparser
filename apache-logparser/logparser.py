#!/bin/env python

#    Simple Apache log parser
#    Copyright (C) 2020  Pekka Helenius
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

################################################################

# TODO prev_host: instead of comparing to previous entry, check if such IP has been seen in XXX seconds
# store IP values for temporary list for XXX seconds, and check list values

import argparse
import os
import re
import subprocess
from datetime import datetime
from apachelogs import LogParser

out_fields_list = ['log_file_name', 'http_status', 'remote_host', 'country', 'time', 'time_diff', 'user_agent', 'http_request']
out_timeformat  = "%d-%m-%Y %H:%M:%S"
dayformat       = "%d-%m-%Y"
ot              = '"' + re.sub(r'%', '%%', out_timeformat) + '"'
geotool         = "geoiplookup"
geodb           = "/usr/share/GeoIP/GeoIP.dat"

# Log format as defined in Apache/HTTPD configuration file (LogFormat directive)
in_log_syntax   = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" \"%{cache-status}e\""

argparser = argparse.ArgumentParser()

argparser.add_argument('-d',  '--dir',            help = 'Apache log file directory.', nargs = '?', dest = 'log_dir', required = True)
argparser.add_argument('-f',  '--files',          help = 'Apache log files. Regular expressions supported.', nargs = '+', dest = 'log_file', required = True)
argparser.add_argument('-s',  '--logsyntax',      help = 'Apache log files syntax, defined as "LogFormat" directive in Apache configuration.', nargs = '?', dest = 'log_syntax')
argparser.add_argument('-c',  '--statuscodes',    help = 'Print only these status codes. Regular expressions supported.', nargs = '+', dest = 'status_code')
argparser.add_argument('-cf', '--countryfilter',  help = 'Include only these countries. Negative match (exclude): "\!Country"', nargs = '+', dest = 'country')
argparser.add_argument('-ot', '--outtimeformat',  help = 'Output time format.\nDefault: ' + ot, nargs = '?', dest = 'out_timeformat')
argparser.add_argument('-of', '--outfields',      help = 'Output fields.\nDefault: ' + ', '.join(out_fields_list), nargs = '+', dest = 'out_field')
argparser.add_argument('-ng', '--nogeo',          help = 'Skip country check with external "geoiplookup" tool.', action='store_true', dest = 'no_geo')
argparser.add_argument('-dl', '--daylower',       help = 'Do not check log entries older than this day.\nDay syntax: 31-12-2020', nargs = '?', dest = 'day_lower')
argparser.add_argument('-du', '--dayupper',       help = 'Do not check log entries newer than this day.\nDay syntax: 31-12-2020', nargs = '?', dest = 'day_upper')
argparser.add_argument('-sb', '--sortby',         help = 'Sort by an output field.', nargs = '?', dest = 'sortby_field')
argparser.add_argument('-sbr', '--sortbyreverse', help = 'Sort by an output field, reverse order.', nargs = '?', dest = 'sortby_field_reverse')
argparser.add_argument('-st', '--stats',          help = 'Show short statistics at the end.', action='store_true', dest = 'show_count')
argparser.add_argument('-np', '--noprogress',     help = 'Do not show progress information.', action='store_true', dest = 'no_progress')
args = argparser.parse_args()

if args.status_code is None:
    status_filter = False
    skip_line_1   = False
else:
    status_filter = True
    skip_line_1   = True
    status_codes  = args.status_code

    http_valid_codes    = [
        '100',
        '101',
        '102',
        '103',
        '200',
        '201',
        '202',
        '203',
        '204',
        '205',
        '206',
        '207',
        '208',
        '226',
        '300',
        '301',
        '302',
        '303',
        '304',
        '305',
        '306',
        '307',
        '308',
        '400',
        '401',
        '402',
        '403',
        '404',
        '405',
        '406',
        '407',
        '408',
        '409',
        '410',
        '411',
        '412',
        '413',
        '414',
        '415',
        '416',
        '417',
        '418',
        '421',
        '422',
        '423',
        '424',
        '425',
        '426',
        '428',
        '429',
        '431',
        '451',
        '500',
        '501',
        '502',
        '503',
        '504',
        '505',
        '506',
        '507',
        '508',
        '510',
        '511',
        '218'
    ]

    code_statuses = []
    for status_input in status_codes:
        init_status     = False
        status_append   = status_input
        status_appended = False

        for status_valid in http_valid_codes:

            if re.search(status_input, status_valid):
                status_append = status_valid
                init_status     = True
                status_appended = True
                code_statuses.append((status_append, init_status))
            else:
                 init_status  = False
        if not status_appended:
            code_statuses.append((status_append, init_status))

    error_msg = ""
    for vl in code_statuses:
        status, init_status = vl

        if not init_status:
            error_msg += "Invalid status code '" + status + "' supplied\n"

    if error_msg != "":
        raise Exception("\n" + error_msg)

if args.country is None:
    country_filter = False
    skip_line_2    = False
else:
    country_filter = True
    countries_filter_list = args.country
    skip_line_2    = True

if args.out_timeformat is not None:
    out_timeformat = args.out_timeformat

if args.out_field is not None:
    out_fields_list = args.out_field

if args.day_lower is not None:
    day_lower = datetime.strptime(args.day_lower, dayformat)
else:
    day_lower = None
if args.day_upper is not None:
    day_upper = datetime.strptime(args.day_upper, dayformat)
else:
    day_upper = None

if args.log_syntax is None:
    log_syntax = in_log_syntax
else:
    log_syntax = args.log_syntax

log_dir     = args.log_dir
files       = args.log_file
no_progress = args.no_progress
files_tmp   = []
parser      = LogParser(log_syntax)

for file_regex in files:
    for file in os.listdir(log_dir):
        fullpath = log_dir + file
        if os.path.isfile(fullpath):
            if re.search(file_regex, file):
                files_tmp.append(file)

    files_tmp.sort()
    files = files_tmp

def fileCheck(file, flag, env=None):
    if env is None:
        filepath = file
    else:
        for path in os.environ[env].split(os.pathsep):
            filepath = os.path.join(path, file)
            if os.path.isfile(filepath):
                break

    if os.access(filepath, eval(flag)):
        return True

    return False

# TODO Really exclude, when no additional args are passed to either of both
if args.sortby_field is not None and args.sortby_field_reverse is not None:
    raise Exception("Use either normal or reverse sorting.")

sortby_field = None
if args.sortby_field is not None:
    sortby_field  = args.sortby_field
    reverse_order = False
elif args.sortby_field_reverse is not None:
    sortby_field  = args.sortby_field_reverse
    reverse_order = True

i            = 0
country_seen = False
prev_host    = ""
host_country = ""
log_entries  = []

for file in files:
    if not no_progress:
        print("Processing file: " + file)

    with open(log_dir + file, 'r') as f:

        for line in f:

            if not no_progress:
                print("Processing log entry: " + str(i), end = "\r")

            if i != 0 and not (skip_line_1 or skip_line_2):
                prev_host      = entry_remote_host
                prev_host_time = entry_time

            entry              = parser.parse(line)
            entry_time         = entry.request_time.replace(tzinfo=None)

            # TODO Handle situations where date_upper & date_lower are equal
            if day_upper is not None and day_lower is not None:
                if day_lower > day_upper:
                    raise Exception("Earlier day can't be later than later day")

            if day_upper is not None:
                if day_upper > datetime.now():
                    raise Exception("Day can't be in the future")

            if day_lower is not None:
                if day_lower > datetime.now():
                    raise Exception("Day can't be in the future")

            if day_lower is not None:
                if entry_time <= day_lower: continue

            if day_upper is not None:
                if entry_time >= day_upper: continue

            entry_remote_host  = entry.remote_host
            entry_http_status  = entry.final_status
            entry_user_agent   = entry.headers_in["User-Agent"]

            # In case where request has newline or other similar chars. Tell Python interpreter to escape them
            entry_http_request = str(entry.request_line).encode('unicode_escape').decode()

            if status_filter:
                for status in code_statuses:
                    num, num_ok = status
                    status = int(num)
                    if status != entry_http_status:
                        skip_line_1 = True
                    else:
                        skip_line_1 = False
                        break

            if not args.no_geo and fileCheck(geotool, "os.X_OK", "PATH") and fileCheck(geodb, "os.R_OK"):
                if prev_host == entry.remote_host:
                    country_seen = True
                else:
                    country_seen = False

                if not country_seen:
                    host_country = subprocess.check_output([geotool, entry_remote_host]).rstrip().decode()
                    host_country = re.sub(r"^.*, (.*)", r'\1', host_country)

                    if re.search("Address not found", host_country):
                        host_country = "Unknown"

                if country_filter:
                    for country in countries_filter_list:
                        if country[1] == "!":
                            country = country[2:]
                            if country.lower() == host_country.lower():
                                skip_line_2 = True
                                break
                            else:
                                skip_line_2 = False

                        elif country.lower() != host_country.lower():
                            skip_line_2 = True
                        else:
                            skip_line_2 = False
                            break

            else:
                skip_line_2 = False

            if skip_line_1 or skip_line_2:
                i += 1
                continue

            time_diff = str("NEW_CONN")
            if prev_host == entry_remote_host:
                time_diff = ( entry_time - prev_host_time ).total_seconds()
                if time_diff > 0:
                    time_diff = "+" + str(time_diff)
            if i == 0:
                time_diff = float(0.0)

            # TODO: Optimize stri generation logic, avoid generating multiple times since it's really not necessary
            out_fields = [
                ('log_file_name', file,               '{:s}'  ),
                ('http_status',   entry_http_status,  '{:3s}' ),
                ('remote_host',   entry_remote_host,  '{:15s}'),
                ('country',       host_country,       '{:20s}'),
                ('time',          entry_time,         '{:8s}' ),
                ('time_diff',     time_diff,          '{:8s}' ),
                ('user_agent',    entry_user_agent,   '{:s}'  ),
                ('http_request',  entry_http_request, '{:s}'  )
            ]

            stri = ""
            printargs = []
            t = 0
            while t <= len(out_fields_list) - 1:

                for out_field in out_fields:
                    entry, data, striformat = out_field

                    if args.no_geo and entry == "country":
                        continue

                    if out_fields_list[t] == entry:
                        stri += "\t" + striformat
                        printargs.append(data)
                        break
                t += 1

            log_entries.append(printargs)

            i += 1

if sortby_field is not None:
    sort_field_found = False
    d = 0
    for field in out_fields_list:
        if field == sortby_field:
            sort_field_index = d
            sort_field_found = True
            break
        d += 1

    if sort_field_found:
        log_entries.sort(key = lambda log_entries: log_entries[sort_field_index], reverse=reverse_order)

if not no_progress:
    print("\n")

for entry in log_entries:
    c = 0
    entry_tmp = []
    while c <= len(entry) - 1:
        entry_tmp.append(str(entry[c]))
        c += 1
    print(stri.format(*entry_tmp).lstrip())

if args.show_count:
    print(("\n" +
        "Processed files:       {:s}\n" +
        "Processed log entries: {:d}\n" +
        "Matched log entries:   {:d}\n").format(
                ', '.join(files),
                i,
                len(log_entries)
            )
        )
