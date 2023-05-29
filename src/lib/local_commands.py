import subprocess,os 
from IPy import IP
from dotenv import load_dotenv,dotenv_values
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

def get_ip_type(address):
    '''Function to determine what IP class the address is.'''
    iptype = IP(address).iptype()
    return iptype

def perform_nslookup(address):
    '''Function to perform a local nslookup of the passed in address.'''
    result = subprocess.run(['nslookup',f'{address}'], stdout=subprocess.PIPE)
    result_decoded = result.stdout.decode("utf-8")
    nslookup = result_decoded.replace('Authoritative answers can be found from:','')
    return nslookup.strip()