import requests,datetime,os
from dotenv import dotenv_values,load_dotenv
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

virustotal_api = config["VIRUSTOTAL_API"]
vt_min_score = config['VT_MIN_SCORE']

headers = {"accept": "application/json","x-apikey": f"{virustotal_api}"}

def malicious_lookup(address):
    ''' Return true if >= min_score sources classifies the IP address as malicious. '''
    # Run request
    malicious_ruling = False
    response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{address}", headers=headers)
    result = response.json()['data']['attributes']    
    
    # Get last modification time
    if result.get('last_analysis_date',''):
        last_mofification_epoch = result.get('last_analysis_date','')
        last_mofification = datetime.datetime.fromtimestamp(last_mofification_epoch).strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_mofification = "N/A"

    # Get ruling on if the address is malicious
    last_analysis_stats = result.get('last_analysis_stats','')
    if last_analysis_stats.get('malicious',''):
        if last_analysis_stats.get('malicious','') >= int(vt_min_score):
            malicious_ruling = True
    
    # Build the output dictionary
    output = {}
    output['vt_malicious_verdict'] = malicious_ruling
    output['vt_network'] = result.get('network','')
    output['vt_registry'] = result.get('regional_internet_registry','')
    output['vt_Country'] = result.get('country','')
    output['vt_last_modification'] = last_mofification
    output['vt_score'] = result.get('last_analysis_stats','')
    
    return output


