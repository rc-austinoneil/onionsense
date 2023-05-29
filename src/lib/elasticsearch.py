import requests,json,os
from dotenv import dotenv_values,load_dotenv
from requests.auth import HTTPBasicAuth
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

elastic_url = config['ELASTIC_URL']
elastic_search_folder_path = config['ELASTIC_SEARCH_FOLDER_PATH']
elastic_auth = HTTPBasicAuth(config["ELASTIC_USER"],config["ELASTIC_PASSWORD"] )
min_repeat_offenders_count = config['MIN_REPEAT_OFFENDERS_COUNT']

headers={'Accept': 'application/json', 'Content-type': 'application/json'}

def elastic_search(elastic_index,search_query):
    ''' Perform an Elasticsearch query
    Requires an index and search json block passed into the function
    Index Examples:
    "*:so-ids*","*:so-*","*:so-ossec*"
    '''
    elastic_get_url=(f'{elastic_url}/{elastic_index}/_search')
    request = requests.get(elastic_get_url,verify=False,data=json.dumps(search_query),headers=headers, auth=elastic_auth)
    return request.json()

def add_to_repeat_offenders_dict(input_json):
    output = {} 
    for x in input_json["hits"]["hits"]:
        try:
            src_ip = x["_source"]["source"]["geo"]["ip"]
            count = output.get(src_ip,0)
            output[src_ip] = count + 1        
        except KeyError:
            pass
    return output

def all_allowed_suricata_alerts():
    search = json.load(open(f'{elastic_search_folder_path}/1_all_allowed_suricata_alerts.json'))
    all_alerts_scan = elastic_search("*:so-ids*", search)
    address_list = add_to_repeat_offenders_dict(all_alerts_scan)
    repeat_offenders = {key: value for key, value in address_list.items() if value >= int(min_repeat_offenders_count)} 
    return repeat_offenders

def suricata_ssh_scan():
    search = search = json.load(open(f'{elastic_search_folder_path}/2_suricata_ssh_scan.json'))
    suricata_ssh_scan = elastic_search("*:so-ids*", search)
    address_list = add_to_repeat_offenders_dict(suricata_ssh_scan)
    repeat_offenders = {key: value for key, value in address_list.items() if value >= int(min_repeat_offenders_count)} 
    return repeat_offenders
