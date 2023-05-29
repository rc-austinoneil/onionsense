import os
from shodan import Shodan
from dotenv import load_dotenv,dotenv_values
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

shodan = Shodan(config["SHODAN_API"])

def ip_enrichment_lookup(address):
    # Run request
    result = shodan.host(address)
    data = result.get("data")
    
    if data:
        service_data = []
        for x in data:
            port = x.get("port","")
            product = x.get("product","")
            transport = x.get("transport","")
            info = x.get("info","")
            data = [port,product,transport,info]
            service_data.append(data)
    
    
    # Build the output dictionary
    output = {}
    output["shodan_domains"] = " ".join(map(str, result.get("domains","")))
    output["shodan_hostnames"] = " ".join(map(str, result.get("hostnames","")))
    output["shodan_org"] = result.get("org","")
    output["shodan_os"] = result.get("os","")
    output["shodan_tags"] = " ".join(map(str, result.get("tags","")))
    output["shodan_service_data"] = " ".join(map(str,service_data))
    
    return output