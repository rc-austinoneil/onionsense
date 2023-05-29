import time,requests,datetime,os,traceback
from lib import maltiverse_api,opnsense,elasticsearch,slack,shodan_api,virustotal_api,local_commands,gsheets_api
from dotenv import load_dotenv,dotenv_values
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

## Ignore Warnings ##
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore",InsecureRequestWarning)

# Setup date and other constant variables
currentDate = datetime.date.today()
my_external_address = requests.get('https://wtfismyip.com/text').text
min_enrichment_score = config['MIN_ENRICHMENT_SCORE']

# Opnsense / Slack output
opnsense_blocklist = config['OPNSENSE_BLOCKLIST']
slack_default_channel = config['SLACK_DEFAULT_CHANNEL']
error_slack_channel = config['ERROR_SLACK_CHANNEL']

# Error Handling
def script_failure(e,failure_reason):
    '''Function to post to slack for error handling'''
    slack.post_message(message=f"*OnionSense Failure!*\n{failure_reason}\n{e}",channel=error_slack_channel)  
def failed_virustotal(e,address):
    script_failure(e,f"Failed attempting to query Virus Total results for {address}.")
def failed_to_block(e,address):
    script_failure(e,f"Failed attempting to add {address} to the Opnsense blocklist.")
def failed_ip_enrichment(e,address):
    script_failure(e,f"Failed attempting to perform IP enrichment for {address}")
def general_failure(e):
    script_failure(e,"OnionSense had an unexpected exception.")

# Run
def run_enrichment(address):
    try:
        output = {}
        print(f"Enrichment: {address} is being enriched.")
        
        try:
            maltiverse = maltiverse_api.ip_enrichment_lookup(address)
        except Exception:
            maltiverse = False

        try:
            shodan = shodan_api.ip_enrichment_lookup(address)
        except Exception:
            shodan = False
        
        if maltiverse:
            output.update(maltiverse)
        if shodan:
            output.update(shodan)

        return output

    except Exception:
        e = traceback.format_exc()                       
        failed_ip_enrichment(e,address)
        
def attempt_to_block(address):
    '''Main function to attempt to block an address on Opnsense after querying APIs to determine if malicious.'''
        
    # Check if the address is public and make sure the address is not my external
    if local_commands.get_ip_type(address) != "PUBLIC":
        print(f"Skipping: {address} is not a public IP address.")
        return

    # Check if the address is my external address
    if address == my_external_address:
        print(f"Skipping: {address} is my external IP address.")
        return

    # Check if the address is already on the blocklist
    if opnsense.check_if_address_on_blocklist(blocklist=opnsense_blocklist,address=address):
        print(f"Skipping: {address} has already been blocked.")
        return

    gsheets_api.addto_scanned_addresses(address)
    print(f"Scanning: {address}...")

    # Check if the address is malicious
    try:
        vt_results = virustotal_api.malicious_lookup(address)
        score = vt_results.get("vt_score")
        malicious_score = score.get("malicious")
        time.sleep(15)
    except Exception:
        e = traceback.format_exc()
        failed_virustotal(e,address)

    # If the address is not malicious
    if vt_results.get("vt_malicious_verdict") != True:
        print(f"Skipping: {address} is not malicious according to VT. ({malicious_score})")
        return

    try:
        nslookup = local_commands.perform_nslookup(address)                        
        timestamp = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        block = opnsense.add_to_blocklist(blocklist=opnsense_blocklist,address=address)    
        print(f"Blocked: {address} with a malicious score of {malicious_score}")
        
               
        # If VT returns >= min_enrichment_score scanners saying this IP is a threat...
        if malicious_score >= int(min_enrichment_score):
            enriched = True
            enrichment_results = run_enrichment(address)
        else:
            enriched = False
            enrichment_results = {}

        # Output rows to google sheets.
        row = [
            timestamp,
            address,
            block,

            # Virus Total
            vt_results.get("vt_malicious_verdict",""),
            vt_results.get("vt_network",""),
            vt_results.get("vt_registry",""),
            vt_results.get("vt_Country",""),
            vt_results.get("vt_last_modification",""),
            score.get("harmless",""),
            score.get("malicious",""),
            score.get("suspicious",""),
            score.get("undetected",""),
            
            # Enrichment
            nslookup,
            enrichment_results.get("maltiverse_registrant_name",""),
            enrichment_results.get("maltiverse_classification",""),
            enrichment_results.get("maltiverse_tag",""),
            enrichment_results.get("maltiverse_email",""),
            enrichment_results.get("maltiverse_is_cdn",""),
            enrichment_results.get("maltiverse_is_cnc",""),
            enrichment_results.get("maltiverse_is_distributing_malware",""),
            enrichment_results.get("maltiverse_is_hosting",""),
            enrichment_results.get("maltiverse_is_mining_pool",""),
            enrichment_results.get("maltiverse_is_open_proxy",""),
            enrichment_results.get("maltiverse_is_sinkhole",""),
            enrichment_results.get("maltiverse_is_tor_node",""),
            enrichment_results.get("maltiverse_is_vpn_node",""),
            enrichment_results.get("maltiverse_blacklist_results",""),
            enrichment_results.get("shodan_domains",""),
            enrichment_results.get("shodan_hostnames",""),
            enrichment_results.get("shodan_org",""),
            enrichment_results.get("shodan_os",""),
            enrichment_results.get("shodan_tags",""),
            enrichment_results.get("shodan_service_data","")
            ]
        
        # Save row to google sheets.
        gsheets_api.addto_blocked_addresses(row)
        
        # Post To Slack       
        block = [
            {
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "OnionSense Blocked An IP"
			}
		},
		{
			"type": "section",
			"fields": [
				{
					"type": "mrkdwn",
					"text": "*Address*"
				},
				{
					"type": "mrkdwn",
					"text": f"{address}"
				},
				{
					"type": "mrkdwn",
					"text": "*Timestamp*"
				},
				{
					"type": "mrkdwn",
					"text": f"{timestamp}"
				},
				{
					"type": "mrkdwn",
					"text": "*VT Score*"
				},
				{
					"type": "mrkdwn",
					"text": f"{malicious_score}"
				},
				{
					"type": "mrkdwn",
					"text": "*Enriched?*"
				},
				{
					"type": "mrkdwn",
					"text": f"{enriched}"
				}
			]
		}]

        slack.post_block(slack_default_channel,blocks=block)

    except Exception:
        e = traceback.format_exc()
        failed_to_block(e,address)

# If executing the file directly, run the tool.
if __name__ == "__main__":
    try:
        start_time_string = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        start_time = datetime.datetime.now()
        
        print(f'Starting OnionSense Run: {start_time_string}')        
        
        ids_events = opnsense.all_allowed_suricata_alerts()
        alerts = elasticsearch.all_allowed_suricata_alerts()
        already_scanned_addresses = gsheets_api.get_scanned_addresses()

        print('\nOpnsense Alerts:')
        opensense_alert_count = 0
        for address in ids_events.keys():
            if not address in already_scanned_addresses:
                attempt_to_block(address)
                opensense_alert_count += 1
            else:
                print(f"Skipping: {address} has already been scanned.")

        print('\nElastic Search Results:')
        elastic_alert_count = 0
        for address in alerts.keys():
            if not address in already_scanned_addresses:
                attempt_to_block(address)
                elastic_alert_count += 1
            else:
                print(f"Skipping: {address} has already been scanned.")

        total_count = opensense_alert_count + elastic_alert_count  
        applied_changes = opnsense.apply_alias_changes()
        finish_time_string = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        finish_time = datetime.datetime.now()

        completion_message = f"\nFinished OnionSense Run: {finish_time_string}\nApplied Changes: {applied_changes}\nTime to Complete: {finish_time - start_time}\nTotal Scanned Addresses: {total_count}\nOpnsense: {opensense_alert_count}\nElastic: {elastic_alert_count}\n"
        print(completion_message)  
    
    except Exception:
        e = traceback.format_exc()
        general_failure(e)