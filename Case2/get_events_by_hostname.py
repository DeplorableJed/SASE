import requests
import config
import pprint
import json
import datetime


HOSTNAME = 'SRW01'
AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY
def getEvents(params):
    HOSTNAME = input('Pleae enter your Jumpbox hostname Ex: SRW01: ')
    print('-'*120)
    print('{:^10}{:^20}{:^40}{:^40}'.format('Hostname','Time','Event Type', 'GUID'))
    url = 'https://api.amp.cisco.com/v1/events'
    request = requests.get(url, auth=(AMP_CLIENT_ID, AMP_KEY),params=params)
    input_dict = request.json()
    for item in input_dict['data']:
        if 'computer' in item:
            if (HOSTNAME in item['computer']['hostname']):
                #pprint.pprint(item)
                print('{:^10}{:^20}{:^40}{:^40}'.format(
        			item['computer']['hostname'],
        			item['date'][:19],
        			item['event_type'],
        			item['connector_guid']
        		))


if __name__ == '__main__':

    hours = input(' Hours before(default - 2):  ')
    hours = hours.strip()
    if not hours:
        hours = 2
    hours = int(hours)
    start_date = (datetime.datetime.now()  - datetime.timedelta(hours=hours)).isoformat()

    params = {'start_date': start_date}

    getEvents(params)
    print('-'*120)
