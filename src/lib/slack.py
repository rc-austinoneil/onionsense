import os
from slack_sdk import WebClient
from dotenv import load_dotenv,dotenv_values
load_dotenv()
config=dotenv_values(os.getenv('ENVLOCATION'))

SLACK_BOT_TOKEN = config["SLACK_BOT_TOKEN"]    
SLACK_DEFAULT_CHANNEL = config["SLACK_DEFAULT_CHANNEL"] 
slack_client = WebClient(SLACK_BOT_TOKEN)

def post_message(message=None, channel=SLACK_DEFAULT_CHANNEL, blocks=None, files=None):
    slack_client.chat_postMessage(channel=channel, text=message, blocks=blocks, file=files)

def post_file(files=None, channel=SLACK_DEFAULT_CHANNEL, title="Upload"):
    slack_client.files_upload(channels=channel, title=title, file=files)

def post_block(channel=SLACK_DEFAULT_CHANNEL,text=None,blocks=None):
    slack_client.chat_postMessage(channel=channel,text=text,blocks=blocks)
