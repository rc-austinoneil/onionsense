import os
from dotenv import load_dotenv,dotenv_values
from maltiverse import Maltiverse
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

maltiverse = Maltiverse(auth_token=config["MALTIVERSE_API"])

def ip_enrichment_lookup(address):
    '''Query Maltiverse for IP enrichment'''
    # Run request
    result = maltiverse.ip_get(address)
    
    # Parse out blacklist results
    blacklist = result.get("blacklist")
    blacklist_results = []
    if blacklist:
        for x in blacklist:
            description = x.get("description","")
            blacklist_results.append(description.strip())

    # Build the output dictionary
    output = {}
    output["maltiverse_classification"] = result.get("classification","")
    output["maltiverse_registrant_name"] = result.get("registrant_name","")
    output["maltiverse_tag"] = " ".join(map(str, result.get("tag")))
    output["maltiverse_email"] = " ".join(map(str, result.get("email")))
    output["maltiverse_is_cdn"] = str(result.get("is_cdn",""))
    output["maltiverse_is_cnc"] = str(result.get("is_cnc",""))
    output["maltiverse_is_distributing_malware"] = str(result.get("is_distributing_malware",""))
    output["maltiverse_is_hosting"] = str(result.get("is_hosting",""))
    output["maltiverse_is_mining_pool"] = str(result.get("is_mining_pool",""))
    output["maltiverse_is_open_proxy"] = str(result.get("is_open_proxy",""))
    output["maltiverse_is_sinkhole"] = str(result.get("is_sinkhole",""))
    output["maltiverse_is_tor_node"] = str(result.get("is_tor_node",""))
    output["maltiverse_is_vpn_node"] = str(result.get("is_vpn_node",""))
    output["maltiverse_blacklist_results"] = " ".join(map(str, blacklist_results))

    return output