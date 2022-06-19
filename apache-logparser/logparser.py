#!/bin/env python

#    Simple Apache HTTPD log file parser
#    Copyright (C) 2022  Pekka Helenius <pekka [dot] helenius [at] fjordtek [dot] com>
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
# TODO: store IP values for temporary list for XXX seconds, and check list values

import argparse
import os
import re
import subprocess

from datetime import datetime
from apachelogs import LogParser, InvalidEntryError

class program(object):

  """
  Init
  """
  def __init__(self):
    self.get_args()
    # Exclude private IP address classes from geo lookup process
    # 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    self.private_class_ip_networks = ['^127\.', '^172\.[1[6-9]|2[0-9]|3[0-1]]\.', '^192\.168\.']

  """
  Define & get output fields
  """
  def get_out_fields(self):
    out_fields = {
      'log_file_name': {'data': None, 'format': '{:s}',   'included': False, 'human_name': 'Log file name'},
      'http_status':   {'data': None, 'format': '{:3s}',  'included': True,  'human_name': 'Status'},
      'remote_host':   {'data': None, 'format': '{:15s}', 'included': True,  'human_name': 'Remote IP'},
      'country':       {'data': None, 'format': '{:20s}', 'included': False, 'human_name': 'Country'},
      'city':          {'data': None, 'format': '{:15s}', 'included': False, 'human_name': 'City'},
      'time':          {'data': None, 'format': '{:20s}', 'included': True,  'human_name': 'Date/Time'},
      'time_diff':     {'data': None, 'format': '{:8s}',  'included': True,  'human_name': 'Time diff'},
      'user_agent':    {'data': None, 'format': '{:s}',   'included': True,  'human_name': 'User agent'},
      'http_request':  {'data': None, 'format': '{:s}',   'included': True,  'human_name': 'Request'}
    }
    return out_fields

  """
  Argument parser
  """
  def get_args(self):

    all_fields      = self.get_out_fields()
    incl_fields     = [i for i in all_fields.keys() if all_fields[i]['included']]
    out_time_format = "%d-%m-%Y %H:%M:%S"

    argparser = argparse.ArgumentParser(
      description     = 'Apache HTTPD server log parser',
      formatter_class = argparse.ArgumentDefaultsHelpFormatter
    )

    argparser.add_argument(
      '-fr', '--files-regex',
      help     = 'Apache log files matching input regular expression.',
      nargs    = '?',
      dest     = 'files_regex',
      required = False
    )
    argparser.add_argument(
      '-f', '--files-list',
      help     = 'Apache log files.\nRegular expressions supported.',
      nargs    = '?',
      type     = lambda x: [i for i in x.split(',')],
      dest     = 'files_list',
      required = False
    )
    argparser.add_argument(
      '-c',  '--status-codes',
      help     = 'Print only these numerical status codes.\nRegular expressions supported.',
      nargs    = '+',
      dest     = 'codes'
    )
    argparser.add_argument(
      '-cf', '--countries',
      help     = 'Include only these countries.\nNegative match (exclude): "\!Country"',
      nargs    = '?',
      type     = lambda x: [i for i in x.split(',')],
      dest     = 'countries'
    )
    argparser.add_argument(
      '-tf', '--time-format',
      help     = 'Output time format.',
      nargs    = '?',
      dest     = 'time_format',
      default  = out_time_format
    )
    argparser.add_argument(
      '-if', '--included-fields',
      help     = 'Included fields.\nAll fields: all, ' + ', '.join(all_fields),
      nargs    = '?',
      dest     = 'incl_fields',
      type     = lambda x: [i for i in x.split(',')],
      default  = ', '.join(incl_fields)
    )
    argparser.add_argument(
      '-ef', '--excluded-fields',
      help     = 'Excluded fields.',
      nargs    = '?',
      dest     = 'excl_fields',
      type     = lambda x: [i for i in x.split(',')],
      default  = None
    )
    argparser.add_argument(
      '-gl', '--geo-location',
      help     = 'Check origin countries with external "geoiplookup" tool.\nNOTE: Automatically includes "country" and "city" fields.',
      action   = 'store_true',
      dest     = 'use_geolocation'
    )
    argparser.add_argument(
      '-ge', '--geotool-exec',
      help     = '"geoiplookup" tool executable found in PATH.',
      nargs    = '?',
      dest     = 'geotool_exec',
      default  = "geoiplookup"
    )
    argparser.add_argument(
      '-gd', '--geo-database-dir',
      help     = 'Database file directory for "geoiplookup" tool.',
      nargs    = '?',
      dest     = 'geo_database_location',
      default  = '/usr/share/GeoIP/'
    )
    argparser.add_argument(
      '-dl', '--day-lower',
      help     = 'Do not check log entries older than this day.\nDay syntax: 31-12-2020',
      nargs    = '?',
      dest     = 'date_lower'
    )
    argparser.add_argument(
      '-du', '--day-upper',
      help     = 'Do not check log entries newer than this day.\nDay syntax: 31-12-2020',
      nargs    = '?',
      dest     = 'date_upper'
    )
    argparser.add_argument(
      '-sb', '--sort-by',
      help     = 'Sort by an output field.',
      nargs    = '?',
      dest     = 'sortby_field'
    )
    argparser.add_argument(
      '-ro', '--reverse-order',
      help     = 'Sort in reverse order.',
      dest     = 'sortby_reverse',
      action   = 'store_true'
    )
    argparser.add_argument(
      '-st', '--show-stats',
      help     = 'Show short statistics at the end.',
      action   = 'store_true',
      dest     = 'show_stats'
    )
    argparser.add_argument(
      '-p', '--show-progress',
      help     = 'Show progress information.',
      dest     = 'show_progress',
      action   = 'store_true'
    )
    argparser.add_argument(
      '--httpd-conf-file',
      help     = 'Apache HTTPD configuration file with LogFormat directive.',
      action   = 'store_true',
      dest     = 'httpd_conf_file',
      default  = '/etc/httpd/conf/httpd.conf'
    )
    argparser.add_argument(
      '--httpd-log-nickname',
      help     = 'LogFormat directive nickname',
      action   = 'store_true',
      dest     = 'httpd_log_nickname',
      default  = 'combinedio'
    )
    argparser.add_argument(
      '-lf', '--log-format',
      help     = 'Log format, manually defined.',
      dest     = 'log_format',
      required = False
    )
    argparser.add_argument(
      '-ph', '--print-headers',
      help     = 'Print column headers.',
      dest     = 'column_headers',
      required = False,
      action   = 'store_true'
    )
    argparser.add_argument(
      '--output-format',
      help     = 'Output format for results.',
      dest     = 'output_format',
      required = False,
      default  = 'table',
      choices  = ['table', 'csv']
    )
    args = argparser.parse_args()
    return args

  """
  Populate recognized HTTP status codes
  """
  def populate_status_codes(self):

    http_valid_codes = [
      '100-103',
      '200-208',
      '218'
      '226',
      '300-308',
      '400-431',
      '451',
      '500-511'
    ]
    codes = []
    for code in http_valid_codes:
      if len(code.split('-')) == 2:
        code_start = int(code.split('-')[0])
        code_end   = int(code.split('-')[1])
        for i in range(code_start,code_end):
          codes.append(str(i))
      else:
        codes.append(code)

    return codes

  """
  Get valid HTTP status codes from user input
  """
  def get_input_status_codes(self, valid_codes, user_codes):

    codes = []

    for user_code in user_codes:
      user_code     = str(user_code)
      validated     = False
      code_appended = False

      for valid_code in valid_codes:

        if re.search(user_code, valid_code):
          validated     = True
          code_appended = True
          codes.append((valid_code, validated))
        else:
          validated = False
      if not code_appended:
        codes.append((user_code, validated))

    return codes

  """
  Get log file list
  """
  def get_files(self, files_regex=None, files_list=None):

    files = []

    if files_regex is None and files_list is None:
      raise Exception("Either single file or regex file selection method is required.")

    if files_regex and files_list:
      raise Exception("Single file and regex file selection methods are mutually exclusive.")

    if files_regex:
      log_dir = '/'.join(files_regex.split('/')[:-1])
      file_part = files_regex.split('/')[-1]
      for lfile in os.listdir(log_dir):
        if os.path.isfile(log_dir + '/' + lfile):
          if re.match(file_part, lfile):
            files.append(log_dir + '/' + lfile)

    if files_list:
      for lfile in files_list:
        if os.path.isfile(lfile):
          files.append(lfile)

    if len(files) == 0:
      raise Exception("No matching files found.")

    files.sort()
    return files

  """
  Common file checker
  """
  def check_file(self, sfile, flag, env = None):

    file_path = sfile

    if env is not None:
      for path in os.environ[env].split(os.pathsep):
        file_path = os.path.join(path, sfile)
        if os.path.isfile(file_path):
          break

    if os.access(file_path, eval(flag)):
        return True
    return False

  """
  Get Apache HTTPD LogFormat directive syntax
  """
  def get_httpd_logformat_directive(self, cfile, tag=None):

    try:
      log_format = None
      with open(cfile, 'r') as f:
        for line in f:
          if re.search('^[ ]+LogFormat ".*' + tag, line):
            r = re.search('^[ ]+LogFormat "(.*)(!?("))', line)
            log_format = r.groups()[0].replace('\\', '')
            break
        f.close()
        return log_format

    except:
      raise Exception("Couldn't open Apache HTTPD configuration file.")

  """
  Geotool processing
  """
  def geotool_get_data(self, geotool_exec, database_file, remote_host):

    host_country = None
    host_city    = None

    if re.match('|'.join(self.private_class_ip_networks), remote_host):
      host_country = "Local"
      host_city    = "Local"
      return {
        'host_country': host_country,
        'host_city':    host_city
      }

    if self.check_file(geotool_exec, "os.X_OK", "PATH") and self.check_file(database_file, "os.R_OK"):

      host_country_main = subprocess.check_output([geotool_exec,'-d', database_file, remote_host]).rstrip().decode()
      host_country_main = host_country_main.split('\n')

      try:
        host_country = host_country_main[0].split(', ')[1]
      except:
        if re.search("Address not found", host_country_main[0]):
          host_country = "Unknown"

      if len(host_country_main) > 1:
        try:
          host_city = host_country_main[1].split(', ')[4]
          if re.search("N/A", host_city):
            host_city = "Unknown: " + host_country_main[1].split(', ')[6] + ', ' + host_country_main[1].split(', ')[7]
        except:
          pass

      return {
        'host_country': host_country,
        'host_city':    host_city
      }
    return None

  """
  Status code filter
  """
  def filter_status_code(self, status_codes, final_status):

    skip_line = True

    for status in status_codes:

      # Status consists of numerical status value (num) and validity boolean value (num_ok)
      if len(status) != 2:
        continue

      num, num_ok = status

      if num_ok:
        status = int(num)

        if status == final_status:
          skip_line = False
          break

    return skip_line

  """
  Country name filter
  """
  def filter_country(self, countries, host_country):

    skip_line = True

    for country in countries:
      if country[1] == "!":
        country = country[2:]
        if country.lower() == host_country.lower():
          skip_line = True
          break
        else:
          skip_line = False

      elif country.lower() == host_country.lower():
        skip_line = False
        break

    return skip_line

  """
  Get total number of lines in files
  """
  def get_file_line_count(self, sfiles):

    lines_in_files = []

    for sfile in sfiles:
      try:
        with open(sfile, 'r') as f:
          line_count = len(list(f))
          f.close()
          lines_in_files.append({
            'file': str(sfile),
            'lines': int(line_count)
          })
      except:
        raise Exception("Couldn't read input file " + sfile)

    return lines_in_files

  """
  Date checker
  """
  def date_checker(self, date_lower, date_upper, entry_time):

    # TODO Handle situations where date_upper & date_lower are equal

    if date_upper is not None and date_lower is not None:
      if date_lower > date_upper:
        raise Exception("Earlier day can't be later than later day")

    if date_upper is not None:
      if date_upper > datetime.now():
        raise Exception("Day can't be in the future")

    if date_lower is not None:
      if date_lower > datetime.now():
        raise Exception("Day can't be in the future")

    if date_lower is not None:
      if entry_time <= date_lower: return False

    if date_upper is not None:
      if entry_time >= date_upper: return False

    return True

  """
  Get output field definitions (sortby)
  """
  def get_out_field(self, fields, field_input):

    i = 0
    for field in fields:
      if field == field_input:
        return [True, i]
      i += 1
    return [False, i]

  """
  Get included fields
  """
  def get_included_fields(self, fields, included_fields, excluded_fields=None):

    included_values    = []
    all_defined_fields = []

    if 'all' in included_fields or included_fields is None:
      included_fields = [i for i in fields.keys()]

    if excluded_fields is not None:
      if 'all' in excluded_fields:
        raise Exception("No output fields defined.")
#      for i in excluded_fields:
#        if i in included_fields:
#          raise Exception("Field can't be both included and excluded. Offending field: {}".format(i))
      included_fields = [i for i in included_fields if i not in excluded_fields]
      all_defined_fields = included_fields + excluded_fields
    else:
      all_defined_fields = included_fields

    for i in all_defined_fields:
      if i not in fields.keys():
        raise Exception("Unknown field value: {}. Accepted values: {}".format(i, ', '.join(fields.keys())))

    for key, value in fields.items():
      if key in included_fields:
        value['included'] = True
      else:
        value['included'] = False
      included_values.append(value['included'])

    if True not in included_values:
      raise Exception("No output fields defined.")
    return fields

  """
  Process input files
  """
  def process_files(self, user_arguments):

    prev_host    = ""
    log_entries  = []
    codes        = []
    countries    = []

    # Log format as defined in Apache/HTTPD configuration file (LogFormat directive) or manually by user
    if user_arguments.log_format:
      log_format = user_arguments.log_format
    else:
      log_format = self.get_httpd_logformat_directive(user_arguments.httpd_conf_file, user_arguments.httpd_log_nickname)

    parser = LogParser(log_format)

    if user_arguments.codes:
      codes = self.get_input_status_codes(self.populate_status_codes(), user_arguments.codes)

    if user_arguments.countries:
      countries = user_arguments.countries

    date_lower = user_arguments.date_lower
    date_upper = user_arguments.date_upper
    day_format = "%d-%m-%Y"

    if date_lower is not None:
      date_lower = datetime.strptime(date_lower, day_format)
    if date_upper is not None:
      date_upper = datetime.strptime(date_upper, day_format)

    files = self.get_files(user_arguments.files_regex, user_arguments.files_list)

    show_progress   = user_arguments.show_progress
    use_geolocation = user_arguments.use_geolocation

    geotool_exec          = user_arguments.geotool_exec
    geo_database_location = user_arguments.geo_database_location

    incl_fields = user_arguments.incl_fields
    if isinstance(user_arguments.incl_fields, str):
      incl_fields = user_arguments.incl_fields.replace(' ','').split(',')

    fields = self.get_included_fields(
      self.get_out_fields(),
      incl_fields,
      user_arguments.excl_fields
    )

    if use_geolocation:
      fields['country']['included'] = True
      fields['city']['included']    = True

    if fields['country']['included'] or fields['city']['included']:
      use_geolocation = True

    invalid_lines        = []
    field_names          = []
    i                    = 0
    country_seen         = False
    geo_data             = None
    skip_line_by_status  = False
    skip_line_by_country = False

    lines_total = sum([i['lines'] for i in self.get_file_line_count(files)])

    if show_progress:
      print(
        "File count: {}\nLines in total: {}".format(
          str(len(files)),
          str(lines_total)
        ))

    for lfile in files:

      if show_progress:
        print("Processing file: {} (lines: {})".format(
          lfile,
          str(self.get_file_line_count([lfile])[0]['lines'])
        ))

      with open(lfile, 'r') as f:

        for line in f:

          if show_progress:
            print("Processing log entry: {} ({}%)".format(
              str(i),
              round(100 * (i/lines_total), 2)
            ), end = "\r")

          if i != 0 and not (skip_line_by_status or skip_line_by_country) and entry_data:
            prev_host      = entry_data['remote_host']
            prev_host_time = entry_data['time']

          try:
            entry = parser.parse(line)
          except InvalidEntryError:
            invalid_lines.append((lfile, i + 1))
            continue

          entry_data = {
            'time':         entry.request_time.replace(tzinfo = None),
            'user_agent':   entry.headers_in["User-Agent"],
            'http_request': str(entry.request_line).encode('unicode_escape').decode(),
            'remote_host':  entry.remote_host,
            'status':       entry.final_status
          }

          if not self.date_checker(date_lower, date_upper, entry_data['time']):
            i += 1
            continue

          if len(codes) > 0:
             skip_line_by_status = self.filter_status_code(codes, entry_data['status'])

          if use_geolocation:
            if prev_host == entry_data['remote_host']:
                country_seen = True
            else:
              country_seen = False

            if not country_seen:
              geo_data = self.geotool_get_data(geotool_exec, geo_database_location, entry_data['remote_host'])

            if len(countries) > 0 and geo_data is not None:
              skip_line_by_country = self.filter_country(countries, geo_data['host_country'])

          else:
            skip_line_by_country = False

          if skip_line_by_status or skip_line_by_country:
            i += 1
            continue

          time_diff = str('NEW_CONN')
          if prev_host == entry_data['remote_host']:
            time_diff = (entry_data['time'] - prev_host_time).total_seconds()
            if isinstance(time_diff, float):
              time_diff = int(time_diff)
            if time_diff > 0:
              time_diff = "+" + str(time_diff)
          if i == 0:
            time_diff = int(0)

          if fields['log_file_name']['included']:
            fields['log_file_name']['data'] = lfile
          if fields['http_status']['included']:
            fields['http_status']['data'] = entry_data['status']
          if fields['remote_host']['included']:
            fields['remote_host']['data'] = entry_data['remote_host']

          if geo_data is not None:
            if fields['country']['included']:
              fields['country']['data'] = geo_data['host_country']
            if fields['city']['included']:
              fields['city']['data'] = geo_data['host_city']

          if fields['time']['included']:
            fields['time']['data'] = entry_data['time']
          if fields['time_diff']['included']:
            fields['time_diff']['data'] = time_diff
          if fields['user_agent']['included']:
            fields['user_agent']['data'] = entry_data['user_agent']
          if fields['http_request']['included']:
            fields['http_request']['data'] = entry_data['http_request']

          stri = ""
          printargs = []

          for key, value in fields.items():
            if not use_geolocation and (key == 'country' or key == 'city'):
              continue
            if value['included']:
              stri += "\t" + value['format']
              printargs.append(value['data'])

              if not any(key in i for i in field_names):
                field_names.append((key, value['human_name']))

          log_entries.append(printargs)
          i += 1

    return [log_entries, files, i, stri, field_names, invalid_lines]

  """
  Execute
  """
  def execute(self):

    user_arguments = self.get_args()

    print_headers  = user_arguments.column_headers
    show_progress  = user_arguments.show_progress
    show_stats     = user_arguments.show_stats
    output_format  = user_arguments.output_format

    sortby_field   = user_arguments.sortby_field
    reverse_order  = bool(user_arguments.sortby_reverse)

    if 'all' not in user_arguments.incl_fields:
      if sortby_field and sortby_field not in user_arguments.incl_fields:
        raise Exception("Sort-by field must be included in output fields.")

    results = self.process_files(user_arguments)
    result_entries = results[0]
    result_files   = results[1]
    result_lines   = results[2]
    stri           = results[3]
    out_fields     = [i[0] for i in results[4]]
    out_fields_human_names = [i[1] for i in results[4]]
    invalid_lines  = results[5]

    if sortby_field is not None:
      out_field_validation = self.get_out_field(out_fields, sortby_field)
      if out_field_validation[0]:
        result_entries.sort(
          key = lambda result_entries : result_entries[out_field_validation[1]] or '',
          reverse = reverse_order
        )

    if not show_progress:
      print("\n")

    if output_format == 'table':

      if print_headers:
        print("\n")
        print(stri.format(*out_fields_human_names).lstrip())

      for entry in result_entries:
        c = 0
        entry_items = []
        while c < len(entry):
          entry_items.append(str(entry[c]))
          c += 1
        print(stri.format(*entry_items).lstrip())

    if output_format == 'csv':

      if print_headers:
        print("\n")
        print(','.join(out_fields_human_names))

      for entry in result_entries:
        c = 0
        entry_items = []
        while c < len(entry):
          entry_items.append(str(entry[c]))
          c += 1
        print(','.join(entry_items))

    if show_stats:
      print(("\n" +
        "Processed files:       {:s}\n" +
        "Processed log entries: {:d}\n" +
        "Matched log entries:   {:d}\n"
             ).format(
          ', '.join(result_files),
          result_lines,
          len(result_entries)
        )
      )
      if len(invalid_lines) > 0:
        print("Invalid lines:")
        for i in invalid_lines:
          print("\tFile: {:s}, line: {:d}".format(i[0], i[1]))
        print("\n")

if __name__ == "__main__":
  app = program()
  app.execute()
