from pymisp import PyMISP
from pymisp import MISPEvent
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


misp_url = 'https://misp_ip' # IP address of MISP Server
misp_key = 'misp_key'  # put  here of MISP API KEY 
misp_verifycert = False  
event_info = 'Bad IP'   # description of event will be created
ip_list_file = '#PATH#'  # Path to the file containing the list of malicious IPs


misp = PyMISP(misp_url, misp_key, misp_verifycert)


event = MISPEvent()
event.info = event_info


with open(ip_list_file, 'r') as file:
    ip_list = file.read().splitlines()

for ip in ip_list:
    event.add_attribute('ip-dst', ip)


response = misp.add_event(event)


if response and response.get('errors'):
    print("Error occurred while adding the event to MISP:")
    print(response['errors'])
else:
    print("Event successfully added to MISP.")