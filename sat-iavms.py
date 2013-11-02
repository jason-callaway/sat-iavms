#!/usr/bin/python

# This is a utility to create errata in Satellite 5.6 named after IAVMs.  It 
# will pull IAVM definitions from disa.mil.  Errata CVE information can be 
# pulled from RHN or a local Spacewalk server.
# 
# This tool was authored by Jason Callaway, jason@jasoncallaway.com
#
# The latest version of this tool can be downloaded from:
#   http://github.com/jason-callaway/sat-iavms
# 
# This tool is licensed under the GPLv3.  See LICENSE for details.

import StringIO
import argparse
import calendar
import datetime
import re
from sets import Set
import urllib

from lxml import etree, html

IAVMURL = 'http://iase.disa.mil/stigs/downloads/xml/iavm-to-cve(u).xml'


