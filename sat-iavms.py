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

class IAVMList:
    def __init__(self):
        IAVMURL = 'http://iase.disa.mil/stigs/downloads/xml/iavm-to-cve(u).xml'

    # Returns a dictionary:
    # iavm_dict['iavm name'] = cve_list
    def build(self):
        if argv.verbose == True:
            print 'Building IAVM list...'
            
        iavm_dict = {}
        iavm_handler = urllib.urlopen(IAVMURL)
        iavm_content = iavm_handler.read()

        # The root XML element is <IAVMtoCVE>. for knows how to iterate over its
        # child elements.
        xml_root = etree.fromstring(iavm_content)
        for iavm in xml_root:
            iavm_name = ''
            cve_list = []
            # Gets the child elements of <IAVM>
    
            children = list(iavm)
            for child in children:
                # In the S tag, we just care about the IAVM name attribute
    
                if child.tag == 'S':
                    iavm_name = child.attrib['IAVM']
                # Now we need to iterate over the CVE tags...
    
                if child.tag == 'CVEs':
                    cves = list(child)
                    for cve in cves:
                        # ...and append their text to the cve_list
    
                        cve_list.append(cve.text)
            iavm_dict[iavm_name] = cve_list
        if argv.verbose == True:
            print 'Done.'
        return iavm_dict
