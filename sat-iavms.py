#!/usr/bin/python

# This utility generates errata named after IAVM (IAVA, IAVB, etc.) from the
# list published by DISA.
# 
# Written by Jason Callaway
# To get the latest version, go to http://github.com/jason-callaway/sat-iavms

import xmlrpclib
import urllib
from lxml import etree

# Specify your Satellite FQDN, admin username, and password
SATELLITE_FQDN = '192.168.122.103'
SATELLITE_LOGIN = 'admin'
SATELLITE_PASSWORD = 'password'

SATELLITE_URL = 'http://' + SATELLITE_FQDN + '/rpc/api'

# You can increase performance a bit by using a local iavm-to-cve file
#IAVM_URL = 'http://iase.disa.mil/stigs/downloads/xml/iavm-to-cve(u).xml'
IAVM_URL = "http://192.168.122.1/iavm-to-cve(u).xml"

# NOTE: Before this program will work, you need to create a custom channel for
# your IAVM content.  The default name is below.
IAVM_CHANNEL = 'rhel-6-iavm'

# Start the XML-RPC connection to the Satellite API
client = xmlrpclib.Server(SATELLITE_URL, verbose=0)

# Initialize a few dictionaries we'll need
iavm_dict = {}
cve_to_iavm_dict = {}

# Grab and read the IAVM file
iavm_handler = urllib.urlopen(IAVM_URL)
iavm_content = iavm_handler.read()

# Now walk through the XML of the IAVM file and grab the CVE names
xml_root = etree.fromstring(iavm_content)
for iavm in xml_root:
    iavm_name = ''
    cve_list = []
    children = list(iavm)
    for child in children:
        if child.tag == 'S':
            iavm_name = child.attrib['IAVM']
        if child.tag == 'CVEs':
            cves = list(child)
            for cve in cves:
                cve_list.append(cve.text)
                cve_to_iavm_dict[cve.text] = iavm_name
        iavm_dict[iavm_name] = cve_list

# Build a list of the existing IAVM Errata
extant_iav_errata = []
try:
    extant_iav_errata = client.channel.software.listErrataByType(key, IAVM_CHANNEL, 
                                                      'Security Advisory')
except:
    # If we get here, no IAV Errata exist yet.  That's ok
    pass

iav_errata = []
for iav in extant_iav_errata:
    iav_errata[iav['advisory']] = 1
    
# First, scan Satellite for all Security Advisories, and build the errata list
# For additional information on the Satellite API, refer to:
# https://access.redhat.com/site/documentation/en-US/Red_Hat_Satellite/5.6/html/API_Overview/
key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)
channel_list = client.channel.listAllChannels(key)
errata = []
for channel in channel_list:
    channel_label = channel['label']
    errata_list = client.channel.software.listErrataByType(key, channel_label, 
                                                           'Security Advisory')
    for erratum in errata_list:
        if erratum['advisory']:
            #print erratum
            errata.append(erratum)
    #errata.append(client.channel.software.listErrataByType(key, channel_label, 
     #                                                      'Security Advisory'))
#errata = client.channel.software.listErrataByType(key, 'rhel-x86_64-server-6', 'Security Advisory)



# Now, for each erratum, we'll see if we need to create a new IAV Erratum
for erratum in errata:
    #print erratum['advisory']
    #print client.errata.listCves(key, erratum['advisory'])
    cves = client.errata.listCves(key, erratum['advisory'])
    for cve in cves:
        # We're using a try block here, you'll see way...
        try:
            # Instead of searching a list for each erratum, it's faster to see
            # if we have an entry in the cve_to_iavm dictionary.  If we don't,
            # an exception is thrown, and we break out of the try block, and
            # move onto the next erratum
            iav_name = 'IAV-' + cve_to_iavm_dict[cve]
            print "+++iava found: " + iav_name
                        
            # Get the list of packages associated with this erratum
            package_list = client.errata.listPackages(key, erratum['advisory'])
            packages = []
            for package in package_list:
                packages.append(package['id'])
            
            # Check to see if an IAVM erratum already exists.  If it doesn't go
            # head and clone the new erratum and populate it with data
            try:
                iav_erratum_exists = iav_errata[iav_name]
                print "   but it already exists"
            except:
                new_erratum = client.errata.clone(key, IAVM_CHANNEL, 
                                                  [erratum['advisory']])
                print "++++++new erratum created: %s" % new_erratum['advisory']
                return_value = client.errata.setDetails(key, 
                                                new_erratum['advisory'], 
                                                [{'advisory_name': iav_name}])
                print "++++++errata.setDetails return number: %d" % return_value
                packages_added = client.errata.addPackages(key,
                                                           iav_name,
                                                           packages)
        # This is the except / pass statement for the try block under
        # for cve in cves
        # except:
        except Exception, e:
            #print "EXCEPTION: %s" % e
            pass


# Log out cleanly
client.auth.logout(key)
