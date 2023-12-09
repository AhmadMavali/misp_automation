#this example for IP, for other IOC such as domain, hash, ....change title of line 12 according of your IOC

import requests
from concurrent.futures import ThreadPoolExecutor
import logging
logging.captureWarnings(True)

misp_url = 'https://misp_ip' # IP address of MISP Server
misp_key = 'misp_key'  # put  here of MISP API KEY 

search_type = ['ip-src', 'ip-dst']

with open('#PATH#', 'r') as file:  #Path of file containing IOC per line 
    ip_addresses = file.read().splitlines()

def perform_search(ip_address):
    results = set()
    for type in search_type:

        search_payload = {
            'returnFormat': 'json',
            'type': type,
            'value': ip_address
        }

        search_url = f'{misp_url}/attributes/restSearch'
        headers = {
            'Authorization': misp_key
        }
        with requests.Session() as session:
            response = session.post(search_url, headers=headers, data=search_payload, verify=False)

            if response.status_code == 200:
          
                data = response.json()
                result = response.content.decode('utf-8')

   
                if result.strip() != '{"response": {"Attribute": []}}':
                    results.add(ip_address)
    return results

with ThreadPoolExecutor() as executor:

    futures = [executor.submit(perform_search, ip_address) for ip_address in ip_addresses]
    found_ip_count = 0
#Path of result file 
    with open('#Path#', 'w') as result_file:
        for future in futures:
            results = future.result()
            found_ip_count += len(results)
            for ip_address in results:
                print(ip_address)
                result_file.write(ip_address + '\n')
    print(f"Total number of found IP addresses: {found_ip_count}")
