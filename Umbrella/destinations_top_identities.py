import sys
import requests
import json
from datetime import datetime
import config

API_KEY = config.UMBRELLA_REPORT_API_KEY
API_SECRET = config.UMBRELLA_REPORT_API_SECRET
ORG_ID = config.UMBRELLA_ORG_ID

def getTopIdentities():
    url = 'https://reports.api.umbrella.com/v1/organizations/' + ORG_ID + '/destinations/internetbadguys.com/identities'
    print(url)
    # do GET request for the domain status and category
    req = requests.get(url, auth = (API_KEY, API_SECRET))

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    print(output)

    print('{:^20}{:^20}{:^20}{:^20}'.format(
        'Origin ID',
        'Origin Type',
        'Origin Label',
        'Number of Requests'
    ))

    for item in output['identities']:
        origin_id = item['originId'] 
        if item['originType']:
           origin_type = item['originType'] 
        else:
           origin_type = '' 
 #      origin_type = item['originType'] 
        origin_label = item['originLabel'] 
        number_of_requests = item['numberOfRequests']

        print('{:^20}{:^20}{:^20}{:^20}'.format(
            origin_id,
            origin_type,
            origin_label,
            number_of_requests
        ))

def main():
    # Print the menu
    print('''
                 Umbrella - Retrieve Destinations: Top Identities Report
                             SRW Blitz, Lab
                   ''')

    getTopIdentities()


if __name__ == '__main__':
    main()