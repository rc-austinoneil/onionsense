import json,requests,os
from dotenv import load_dotenv,dotenv_values
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

## Ignore Warnings ##
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore',InsecureRequestWarning)

opnsense_api_key = config["OPNSENSE_API_KEY"]    
opnsense_api_secret = config["OPNSENSE_API_SECRET"] 
opnsense_base_url=config["OPNSENSE_BASE_URL"]
min_repeat_offenders_count = config['MIN_REPEAT_OFFENDERS_COUNT']

headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

def add_to_blocklist(blocklist, address):
    blocklist_url = (f'{opnsense_base_url}/firewall/alias_util/add/{blocklist}')
    addressToAdd = {"address":f"{address}"}
    block = requests.post(blocklist_url,verify=False,data=json.dumps(addressToAdd), headers=headers, auth=(opnsense_api_key, opnsense_api_secret ))
    if block.status_code == 200:
        blocked_address = True
    else:
        blocked_address = False
        raise Exception(f"Failed to add {address} to {blocklist}!\n{block.text}")
    return blocked_address
    
def apply_alias_changes():
    data = ''
    reconfigure_url=(f'{opnsense_base_url}/firewall/alias/reconfigure')
    reconfigure = requests.post(reconfigure_url,verify=False,data=json.dumps(data),headers=headers,auth=(opnsense_api_key, opnsense_api_secret))
    if reconfigure.status_code == 200:
        applied_changes = True
    else:
        applied_changes = False
        raise Exception(f"Failed to apply changes!\n{reconfigure.text}")
    return applied_changes

def get_blocklist(blocklist):
    blocklist_url = (f'{opnsense_base_url}/firewall/alias_util/list/{blocklist}')
    data = ''
    block = requests.post(blocklist_url,verify=False,data=json.dumps(data), headers=headers, auth=(opnsense_api_key, opnsense_api_secret ))
    return block.json()['rows']

def check_if_address_on_blocklist(blocklist,address):
    formatted_address={'ip': f'{address}'}
    ip_blocklist = get_blocklist(blocklist)
    if formatted_address in ip_blocklist:
        return True
    else:
        return False

def clear_blocklist(blocklist):
    data = ''
    blocklist_url_list = (f'{opnsense_base_url}/firewall/alias_util/list/{blocklist}')
    block = requests.post(blocklist_url_list,verify=False,data=json.dumps(data), headers=headers, auth=(opnsense_api_key, opnsense_api_secret ))
    blocklist_addresses = block.json()['rows']

    for x in blocklist_addresses:
        address = x['ip']
        formatted_address={'address': f'{address}'}
        blocklist_url = (f'{opnsense_base_url}/firewall/alias_util/delete/{blocklist}')
        clear_blocklist = requests.post(blocklist_url,verify=False,data=json.dumps(formatted_address), headers=headers, auth=(opnsense_api_key, opnsense_api_secret ))
    apply_alias_changes()

def add_to_repeat_offenders_dict(input_json):
    output = {} 
    for x in input_json:
        try:
            src_ip = x["src_ip"]
            alert_action = x['alert_action']
            if alert_action == "allowed":
                count = output.get(src_ip,0)
                output[src_ip] = count + 1        
        except KeyError:
            pass
    return output

def get_ids_alerts():
    data = ''
    ids_alerts_url=(f'{opnsense_base_url}/ids/service/queryAlerts')
    ids_alerts = requests.post(ids_alerts_url,verify=False,data=json.dumps(data),headers=headers,auth=(opnsense_api_key, opnsense_api_secret))
    return ids_alerts.json()['rows']

def all_allowed_suricata_alerts():
    ids_events = get_ids_alerts()
    address_list = add_to_repeat_offenders_dict(ids_events)
    repeat_offenders = {key: value for key, value in address_list.items() if value >= int(min_repeat_offenders_count)}   
    return repeat_offenders