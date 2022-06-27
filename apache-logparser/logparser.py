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

# TODO: prev_host: instead of comparing to previous entry, check if such IP has been seen in XXX seconds
# TODO: store IP values for temporary list for XXX seconds, and check list values
# TODO: implement warning check for geoiplookup tool database files, i.e. "warning, some geo database files are very old. Please consider updating geo database information."

import argparse
import os
import re
import subprocess

from datetime import datetime
from apachelogs import LogParser, InvalidEntryError

class text_processing(object):

  """
  Init
  """
  def __init__(self, verbose):
    self.show_verbose = verbose

  """
  Verbose output format (we do not use logger library)
  """

  def print_verbose(self, prefix='output', *args):
    if self.show_verbose:
      print('VERBOSE [{:s}]: {:s}'.format(prefix, ', '.join([str(i) for i in args])))

class program(object):

  """
  Init
  """
  def __init__(self):
    self.args = self.get_args()

    # Exclude private IP address classes from geo lookup process
    # Strip out %I and %O flags from Apache log format
    # 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    self.private_class_ip_networks = ['^127\.', '^172\.(1[6-9]{1}|2[0-9]{1}|3[0-1]{1})\.', '^192\.168\.']

    self.txt = text_processing(verbose = self.args.verbose)

  """
  Define & get output fields
  """
  def get_out_fields(self):
    out_fields = {
      'log_file_name': {'data': None, 'format': '{:s}',   'included': False, 'human_name': 'Log file name', 'sort_index': 0},
      'http_status':   {'data': None, 'format': '{:3s}',  'included': True,  'human_name': 'Status',        'sort_index': 1},
      'remote_host':   {'data': None, 'format': '{:15s}', 'included': True,  'human_name': 'Remote IP',     'sort_index': 2},
      'country':       {'data': None, 'format': '{:20s}', 'included': False, 'human_name': 'Country',       'sort_index': 3},
      'city':          {'data': None, 'format': '{:15s}', 'included': False, 'human_name': 'City',          'sort_index': 4},
      'time':          {'data': None, 'format': '{:20s}', 'included': True,  'human_name': 'Date/Time',     'sort_index': 5},
      'time_diff':     {'data': None, 'format': '{:8s}',  'included': True,  'human_name': 'Time diff',     'sort_index': 6},
      'user_agent':    {'data': None, 'format': '{:s}',   'included': True,  'human_name': 'User agent',    'sort_index': 7},
      'http_request':  {'data': None, 'format': '{:s}',   'included': True,  'human_name': 'Request',       'sort_index': 8}
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
      default  = ','.join(incl_fields)
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
      '-ro', '--reverse',
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
      '-ph', '--print-header',
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
    argparser.add_argument(
      '--head',
      help     = 'Read first N lines from all log entries.',
      dest     = 'read_first_lines_num',
      required = False,
      nargs    = '?',
      type     = int
    )
    argparser.add_argument(
      '--tail',
      help     = 'Read last N lines from all log entries.',
      dest     = 'read_last_lines_num',
      required = False,
      nargs    = '?',
      type     = int
    )
    argparser.add_argument(
      '--sort-logs-by',
      help     = 'Sorting order for input log files.',
      dest     = 'sort_logs_by_info',
      required = False,
      default  = 'name',
      choices  = ['date', 'size', 'name']
    )
    argparser.add_argument(
      '--verbose',
      help     = 'Verbose output.',
      dest     = 'verbose',
      required = False,
      action   = 'store_true'
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

    self.txt.print_verbose('Available status codes', codes)

    return codes

  """
  Get log file list
  """
  def get_files(self, files_regex = None, files_list = None):

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

    self.txt.print_verbose('Input files', files)
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
      self.txt.print_verbose('File check', file_path, 'flags: ' + flag)
      return True
    return False

  """
  Get Apache HTTPD LogFormat directive syntax
  """
  def get_httpd_logformat_directive(self, cfile, tag = None):

    try:
      log_format = None
      self.txt.print_verbose('Apache configuration file', cfile)
      with open(cfile, 'r') as f:
        for line in f:
          if re.search('^[ ]+LogFormat ".*' + tag, line):
            r = re.search('^[ ]+LogFormat "(.*)(!?("))', line)
            log_format = r.groups()[0].replace('\\', '')
            break
        f.close()
        self.txt.print_verbose('Log format', log_format)
        return log_format

    except:
      raise Exception("Couldn't open Apache HTTPD configuration file.")

  """
  Geotool processing
  """
  def geotool_get_data(self, geotool_ok, geotool_exec, database_file, remote_host):

    host_country = None
    host_city    = None

    if re.match('|'.join(self.private_class_ip_networks), remote_host):
      host_country = "Local"
      host_city    = "Local"
      return {
        'host_country': host_country,
        'host_city':    host_city
      }

    if geotool_ok:

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
  Get lines to be processed from input files and min/max input
  min and max work much like Unix tools 'head' and 'tail'
  Only a single value (min or max) is allowed
  """

  def get_file_lines_head_tail(self, sfiles, line_range_min = None, line_range_max = None, files_order = None):

    files_and_lines = {'files': [], 'lines_total': 0, 'range_min': 0, 'range_max': 0}
    files_tmp = []

    lines_count = 0
    line_start  = 0
    line_end    = 0

    if line_range_min and line_range_max:
      raise Exception("Either first or last line limit can be used, not both.")

    if files_order is None:
      raise Exception("Sorting order for input files missing.")

    if line_range_min is not None:
      if line_range_min < 0:
        line_range_min = None

    if line_range_max is not None:
      if line_range_max < 0:
        line_range_max = None

    for sfile in sfiles:

      try:
        with open(sfile, 'r') as f:
          line_count = len(list(f))
          f.close()

          files_tmp.append({
            'file':          str(sfile),
            'modified_date': os.path.getmtime(sfile),
            'size':          os.path.getsize(sfile),
            'line_count':    line_count
          })

      except:
        raise Exception("Couldn't read input file " + sfile)

      if files_order == 'date':
        files_tmp.sort(key = lambda d: d['modified_date'])
      elif files_order == 'size':
        files_tmp.sort(key = lambda d: d['size'])
      elif files_order == 'name':
        files_tmp.sort(key = lambda d: d['file'])

    i = 0
    for sfile in files_tmp:

      line_end = (line_start + sfile['line_count']) - 1

      files_and_lines['files'].append({
        'file':              sfile['file'],
        'line_start_global': line_start,
        'line_end_global':   line_end,
        'line_start_local':  0,
        'line_end_local':    sfile['line_count'] - 1,
      })

      lines_count += line_count
      line_start = files_and_lines['files'][i]['line_end_global'] + 1
      i += 1

    range_line_start = files_and_lines['files'][0]['line_start_global']
    full_range                     = files_and_lines['files'][-1]['line_end_global']
    files_and_lines['range_min']   = range_line_start
    files_and_lines['range_max']   = full_range
    files_and_lines['lines_total'] = full_range - range_line_start
    i = 0

    # Read last N lines
    if line_range_max is not None:
      range_start = full_range - line_range_max
      if range_start <= 0:
        range_start = 0

      for l in files_and_lines['files']:
        if range_start >= l['line_start_global'] and range_start <= l['line_end_global']:
          l['line_start_global'] = range_start
          l['line_start_local']  = l['line_end_local'] - (l['line_end_global'] - range_start)
          del files_and_lines['files'][:i]
        i += 1

    # Read first N lines
    if line_range_min is not None:
      range_end = line_range_min
      if range_end >= full_range:
        range_end = full_range

      for l in files_and_lines['files']:
        if range_end >= l['line_start_global'] and range_end <= l['line_end_global']:
          l['line_end_local']  = l['line_end_local'] - l['line_start_local'] - (l['line_end_global'] - range_end)
          l['line_end_global'] = range_end
          del files_and_lines['files'][i + 1:]
        i += 1

    return files_and_lines

  """
  Get lines to be processed from input files and range input
  Range: <min> - <max>
  """

  def get_file_lines_range(self, sfiles, line_range_min=None, line_range_max=None):

    files_and_lines = {'files': [], 'lines_total': 0, 'range_min': 0, 'range_max': 0}

    lines_count            = 0
    line_start             = 0
    line_end               = 0
    range_line_start       = 0
    range_line_end         = 0
    range_line_start_found = False

    if line_range_min is not None:
      if line_range_min < 0:
        line_range_min = None

    if line_range_max is not None:
      if line_range_max < 0:
        line_range_max = None

    for sfile in sfiles:
      append = False
      try:
        with open(sfile, 'r') as f:
          line_count = len(list(f))
          f.close()

          line_end = line_start + line_count

          if line_range_min is not None:
            if line_range_min >= line_start and line_range_min <= line_end:
              append = True
              line_start = line_range_min
          if line_range_min is None and line_end < line_range_max:
            append = True

          if line_range_max is not None:
            if line_range_max >= line_start and line_range_max <= line_end:
              append = True
              line_end = line_range_max
            if line_range_min < line_end and line_range_max > line_end:
              append = True
          if line_range_max is None and line_start > line_range_min:
            append = True

          if append:
            files_and_lines['files'].append({
              'file':              str(sfile),
              'line_start_global': line_start,
              'line_end_global':   line_end,
              'modified_date':     os.path.getmtime(sfile),
              'size':              os.path.getsize(sfile)
            })

            # Use only the first matching line_start value
            if not range_line_start_found:
              range_line_start_found = True
              range_line_start = line_start
            # Use the last matching line_end value
            range_line_end = line_end

          lines_count += line_count
          line_start  = lines_count + 1

      except:
        raise Exception("Couldn't read input file " + sfile)

    files_and_lines['lines_total'] = range_line_end - range_line_start
    files_and_lines['range_min']   = range_line_start
    files_and_lines['range_max']   = range_line_end

    return files_and_lines

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

    if included_fields:

      # TODO: simplify logic
      n = 0
      included_fields = [[i.replace(' ',''), 0] for i in included_fields]
      for a in included_fields:
        a[1] += n
        n += 1
    if excluded_fields:
      excluded_fields = [i.replace(' ','') for i in excluded_fields]

    all_defined_fields = []
    fields_out         = {}

    if 'all' in included_fields or included_fields is None:
      included_fields = [[i, int(i['sort_index'])] for i in fields.keys()]

    if excluded_fields is not None:
      if 'all' in excluded_fields:
        raise Exception("No output fields defined.")

      # TODO: simplify logic
      n = 0
      included_fields = [[i, 0] for i in included_fields if i not in excluded_fields]
      for a in included_fields:
        a[1] += n
        n += 1
      all_defined_fields = [i[0] for i in included_fields] + excluded_fields
    else:
      all_defined_fields = included_fields

    for i in all_defined_fields:
      if i[0] not in fields.keys():
        raise Exception("Unknown field value: {}. Accepted values: {}".format(i, ','.join(fields.keys())))

    for a in included_fields:
      for key, value in fields.items():
        if key == a[0]:
          value['sort_index'] = a[1]
          value['included']   = True
          fields_out[key]     = value

    if len(fields_out.keys()) == 0:
      raise Exception("No output fields defined.")

    return fields_out

  """
  Process input files
  """
  def process_files(self):

    prev_host    = ""
    log_entries  = []
    codes        = []
    countries    = []

    # Log format as defined in Apache/HTTPD configuration file (LogFormat directive) or manually by user
    if self.args.log_format:
      log_format = self.args.log_format
    else:
      log_format = self.get_httpd_logformat_directive(self.args.httpd_conf_file, self.args.httpd_log_nickname)

    # Remove bytes in & out fields from local traffic pattern
    log_format_local = log_format.replace('%I','').replace('%O','').strip()

    parser = LogParser(log_format)
    parser_local = LogParser(log_format_local)

    if self.args.codes:
      codes = self.get_input_status_codes(self.populate_status_codes(), self.args.codes)

    if self.args.countries:
      countries = self.args.countries

    date_lower = self.args.date_lower
    date_upper = self.args.date_upper
    day_format = "%d-%m-%Y"

    if date_lower is not None:
      date_lower = datetime.strptime(date_lower, day_format)
    if date_upper is not None:
      date_upper = datetime.strptime(date_upper, day_format)

    geotool_exec          = self.args.geotool_exec
    geo_database_location = self.args.geo_database_location

    incl_fields = self.args.incl_fields
    if isinstance(self.args.incl_fields, str):
      incl_fields = self.args.incl_fields.split(',')

    use_geolocation = self.args.use_geolocation
    geotool_ok      = False

    if use_geolocation:
      if self.check_file(geotool_exec, "os.X_OK", "PATH") and self.check_file(geo_database_location, "os.R_OK"):
        geotool_ok = True

    if use_geolocation:
      if 'country' not in incl_fields:
        incl_fields.append('country')
      if 'city' not in incl_fields:
        incl_fields.append('city')

    if 'country' in incl_fields or 'city' in incl_fields:
      use_geolocation = True

    fields = self.get_included_fields(
      self.get_out_fields(),
      incl_fields,
      self.args.excl_fields
    )

    invalid_lines        = []
    field_names          = []
    country_seen         = False
    geo_data             = None
    skip_line_by_status  = False
    skip_line_by_country = False
    file_num             = 0
    stri                 = ""

    files_input        = self.get_files(self.args.files_regex, self.args.files_list)
    files_process_data = self.get_file_lines_head_tail(
      files_input,
      self.args.read_first_lines_num,
      self.args.read_last_lines_num,
      self.args.sort_logs_by_info
    )

    lines_total        = files_process_data['lines_total']
    files_total        = len(files_process_data['files'])

    self.txt.print_verbose(
      'Log entry range',
      str(files_process_data['files'][0]['line_start_global'])
      + ' - ' +
      str(files_process_data['files'][-1]['line_end_global'])
    )

    if self.args.show_progress or self.args.verbose:
      print(
        "File count: {}\nLines in total: {}".format(
          str(files_total),
          str(lines_total)
        ))

    for lfile in files_process_data['files']:

      if self.args.show_progress or self.args.verbose:
        print("Processing file: {:s} (lines: {:d}-{:d})".format(
          lfile['file'],
          lfile['line_start_global'], lfile['line_end_global']
        ))

      with open(lfile['file'], 'r') as f:
        f = list(f)
        range_start = files_process_data['files'][file_num]['line_start_local']
        range_end   = files_process_data['files'][file_num]['line_end_local']

        lines = range(range_start, range_end)
        line_num = 1

        for line in lines:

          if self.args.show_progress or self.args.verbose:
            print("Processing log entry: {:d}/{:d} ({}%)".format(
              line_num,
              len(lines),
              round(100 * (line_num/len(lines)), 2)
            ), end = "\r")

          if line_num != 1 and not (skip_line_by_status or skip_line_by_country) and entry_data:
            prev_host      = entry_data['remote_host']
            prev_host_time = entry_data['time']

          try:
            if re.match('|'.join(self.private_class_ip_networks), f[line]):
              entry = parser_local.parse(f[line])
            else:
              entry = parser.parse(f[line])
          except InvalidEntryError:
            invalid_lines.append((lfile['file'], line_num))
            line_num += 1
            continue

          entry_data = {
            'time':         entry.request_time.replace(tzinfo = None),
            'user_agent':   entry.headers_in["User-Agent"],
            'http_request': str(entry.request_line).encode('unicode_escape').decode(),
            'remote_host':  entry.remote_host,
            'status':       entry.final_status
          }

          if not self.date_checker(date_lower, date_upper, entry_data['time']):
            line_num += 1
            continue

          if len(codes) > 0:
             skip_line_by_status = self.filter_status_code(codes, entry_data['status'])

          if use_geolocation:
            if prev_host == entry_data['remote_host']:
                country_seen = True
            else:
              country_seen = False

            if not country_seen:
              geo_data = self.geotool_get_data(geotool_ok, geotool_exec, geo_database_location, entry_data['remote_host'])

            if len(countries) > 0 and geo_data is not None:
              skip_line_by_country = self.filter_country(countries, geo_data['host_country'])

          else:
            skip_line_by_country = False

          if skip_line_by_status or skip_line_by_country:
            line_num += 1
            continue

          time_diff = str('NEW_CONN')
          if prev_host == entry_data['remote_host']:
            time_diff = (entry_data['time'] - prev_host_time).total_seconds()
            if isinstance(time_diff, float):
              time_diff = int(time_diff)
            if time_diff > 0:
              time_diff = "+" + str(time_diff)
          if line_num == 1 and file_num == 0:
            time_diff = int(0)

          if 'log_file_name' in fields:
            fields['log_file_name']['data'] = lfile
          if 'http_status' in fields:
            fields['http_status']['data'] = entry_data['status']
          if 'remote_host' in fields:
            fields['remote_host']['data'] = entry_data['remote_host']

          if geo_data is not None:
            if 'country' in fields:
              fields['country']['data'] = geo_data['host_country']
            if 'city' in fields:
              fields['city']['data'] = geo_data['host_city']

          if 'time' in fields:
            fields['time']['data'] = entry_data['time']
          if 'time_diff' in fields:
            fields['time_diff']['data'] = time_diff
          if 'user_agent' in fields:
            fields['user_agent']['data'] = entry_data['user_agent']
          if 'http_request' in fields:
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
          line_num += 1

      file_num += 1

    return [log_entries, files_process_data['files'], lines_total, stri, field_names, invalid_lines]

  """
  Execute
  """
  def execute(self):

    print_headers  = self.args.column_headers
    show_progress  = self.args.show_progress
    show_stats     = self.args.show_stats
    output_format  = self.args.output_format

    sortby_field   = self.args.sortby_field
    reverse_order  = self.args.sortby_reverse

    if self.args.incl_fields:
      if 'all' not in self.args.incl_fields:
        if sortby_field and sortby_field not in self.args.incl_fields:
          raise Exception("Sort-by field must be included in output fields.")

    results = self.process_files()
    result_entries = results[0]
    result_files   = results[1]
    result_lines   = results[2]
    stri           = results[3]
    out_fields     = [i[0] for i in results[4]]
    out_fields_human_names = [i[1] for i in results[4]]
    invalid_lines  = results[5]

    if sortby_field is None and reverse_order:
      raise Exception("You must define a field for reverse sorting.")

    if sortby_field is not None:
      out_field_validation = self.get_out_field(out_fields, sortby_field)
      if out_field_validation[0]:
        result_entries.sort(
          key = lambda r : r[out_field_validation[1]] or '',
          reverse = reverse_order
        )

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
          ', '.join([i['file'] for i in result_files['files']]),
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
