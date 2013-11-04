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
key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)

# delete the existing iavm channel
try:
    return_value = client.channel.software.delete(key, IAVM_CHANNEL)
except:
    pass

# now re-create it
return_value = client.channel.software.create(key, 
                                              IAVM_CHANNEL,
                                              'RHEL 6 IAVM',
                                              'IAVM updates for RHEL 6',
                                              'channel-x86_64',
                                              '')    
