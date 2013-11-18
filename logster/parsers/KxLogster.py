###  An attempt at parsing some non standard nginx log files
###
###  Our Nginx is configured to produce:
###
###   IP  user user [timestamp] "request" status size "referer" "useragent" host backend:port requesttime - - -
###
###   5.10.83.100 - - [18/Nov/2013:06:26:28 +1300] "GET /layer/183-nz-mainland-river-polygons-topo-1250k/data/ HTTP/1.1" 200 3599 "-" "Mozilla/5.0 (compatible; AhrefsBot/5.0; +http://ahrefs.com/robot/)" data.linz.govt.nz kxWebHosts:80 0.191 - - -
###
###  We want to produce a metrics report with:
###
###       Time period (1 minute)
###       Number of requests
###       Count of 5xx status codes (errors, our fault)
###       Count of 2/3xx status codes (success)
###       Maximum request time
###       Average request time
###
###  For user-facing web traffic, but filtering out monitoring traffic.
###  Will produce one event for each complete minute in the log. Doesn't assume
###  log entries are completely in time order - instead will remember state
###  Between calls and output results for every time period at least three minutes
###  in the past that hasn't yet been output.
###
###  For example:
###  sudo ./logster --dry-run --output=json KxLogster /var/log/nginx/access_log
###
###  { '18/Nov/2013:06:26': { 
###        'num_requests': 23,
###        'status_5xx': 2,
###        'status_4xx': 6,
###        'status_success': 15,
###        'max_time': 3.234,
###    },
###    ...
###  }
###
###  2013 Colin Coghill
###  based on code:  Copyright 2011, Etsy, Inc.
###
###  This file is part of Logster.
###
###  Logster is free software: you can redistribute it and/or modify
###  it under the terms of the GNU General Public License as published by
###  the Free Software Foundation, either version 3 of the License, or
###  (at your option) any later version.
###
###  Logster is distributed in the hope that it will be useful,
###  but WITHOUT ANY WARRANTY; without even the implied warranty of
###  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
###  GNU General Public License for more details.
###
###  You should have received a copy of the GNU General Public License
###  along with Logster. If not, see <http://www.gnu.org/licenses/>.
###

UA_FILTER = ['nagios-plugin', 'pingdom']



import dateutil.parser 
import datetime
import time
import re
import json

from logster.logster_helper import MetricObject, LogsterParser
from logster.logster_helper import LogsterParsingException

class KxLogster(LogsterParser):

    def __init__(self, option_string=None):
        '''Initialize any data structures or variables needed for keeping track
        of the tasty bits we find in the log we are parsing.'''

        # We fetch current status from a state file, if it exists.

        self.state_fname = "state"
        try:
            self.state = json.loads(self.state_fname)
        except: 
            self.state = {}

        if 'time_sent' in self.state:
            self.time_sent = self.state['time_sent']
        else:
            self.time_sent = datetime.datetime(year=1970, month=1, day=1)

        self.time_now = datetime.datetime.now()   # don't want it changing while we're running
        
        # Regular expression for matching lines we are interested in, and capturing
        # fields from the line (in this case, http_status_code).
        self.reg = re.compile(r'(?P<host>\S+).*\[(?P<date>[^:]+):(?P<time>.+)\].*HTTP/1.\d\" (?P<http_status_code>\d{3}) (?P<size>\d+).*\"(?P<uagent>[^\"]*)" \S+ \S+ (?P<rtime>\S+) .*')

###   5.10.83.100 - - [18/Nov/2013:06:26:28 +1300] "GET /layer/183-nz-mainland-river-polygons-topo-1250k/data/ HTTP/1.1" 200 3599 "-" "Mozilla/5.0 (compatible; AhrefsBot/5.0; +http://ahrefs.com/robot/)" data.linz.govt.nz kxWebHosts:80 0.191 - - -

    def parse_line(self, line):
        '''This function should digest the contents of one line at a time, updating
        object's state variables. Takes a single argument, the line to be parsed.'''

#        import pdb;  pdb.set_trace()

        try:
            # Apply regular expression to each line and extract interesting bits.
            regMatch = self.reg.match(line)

            if regMatch:
                linebits = regMatch.groupdict()
                status = int(linebits['http_status_code'])
                size = int(linebits['size'])
                rtime = float(linebits['rtime'])
                uagent = linebits['uagent']

                if any(filt in uagent for filt in UA_FILTER):
                    raise LogsterParsingException, "Bot detected %s" % uagent

                rawwhen = dateutil.parser.parse(linebits['date']+" "+linebits['time'])
                when = rawwhen.strftime("%Y-%m-%d %H:%M")  # minute sized bucket

                if not when in self.state:
                    self.state[when] = {}
                if not "num_requests" in self.state[when]:
                    self.state[when]['num_requests'] = 0
                if not "status_5xx" in self.state[when]:
                    self.state[when]['status_5xx'] = 0
                if not "status_success" in self.state[when]:
                    self.state[when]['status_success'] = 0
                if not "max_time" in self.state[when]:
                    self.state[when]['max_time'] = 0

                self.state[when]['num_requests'] += 1
                if rtime > self.state[when]['max_time']:
                    self.state[when]['max_time'] = rtime

                if 200 <= status <=299:
                    self.state[when]['status_success'] += 1
                if 300 <= status <=399:
                    self.state[when]['status_success'] += 1
                if 400 <= status <=499:
                    self.state[when]['status_success'] += 1
                if 500 <= status <=599:
                    self.state[when]['status_5xx'] += 1
            else:
                raise LogsterParsingException, "regmatch failed to match"

        except Exception, e:
            raise LogsterParsingException, "regmatch or contents failed with %s" % e


    def get_state(self, duration):
        '''Run any necessary calculations on the data collected from the logs
        and return a list of metric objects.'''
        self.duration = duration

        # Return a list of metrics objects
        res = []
        for when,v in self.state.iteritems():
            res.append( MetricObject(timestamp = when, name = "status_5xx", units=" requests", value=v['status_5xx']))
            res.append( MetricObject(timestamp = when, name = "num_requests", units=" requests", value=v['num_requests']))
            res.append( MetricObject(timestamp = when, name = "status_success", units=" requests", value=v['status_success']))
            res.append( MetricObject(timestamp = when, name = "max_time", units=" requests", value=v['max_time']))

        return res
