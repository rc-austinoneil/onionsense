import datetime,gspread,os
from dotenv import load_dotenv,dotenv_values
from itertools import chain
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

sheets_auth = gspread.service_account(filename=config['GDRIVE_TOKEN_PATH'])
sheet = sheets_auth.open(config['GDRIVE_SPREADSHEET_NAME'])

def get_scanned_addresses():
    '''Function to check if the address has been scaned by the tool before.'''
    wks = sheet.worksheet(config['GDRIVE_SPREADSHEET_SCANNED_TAB_NAME'])
    scanned_addresses = wks.batch_get(['B2:B'])
    return list(chain.from_iterable(chain.from_iterable(scanned_addresses)))

def addto_scanned_addresses(address):
    '''Function to write the scanned addresses to google spreadsheet.'''
    wks = sheet.worksheet(config['GDRIVE_SPREADSHEET_SCANNED_TAB_NAME'])
    timestamp = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    scanned_row = [timestamp,address]
    wks.append_row(scanned_row)

def addto_blocked_addresses(row):
    '''Function to write the blocked addresses to google spreadsheet.'''
    wks = sheet.worksheet(config['GDRIVE_SPREADSHEET_TAB_NAME'])
    wks.append_row(row)
