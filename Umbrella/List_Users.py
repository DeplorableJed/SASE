import sys
import requests
import json
from datetime import datetime
import config

API_KEY = config.UMBRELLA_MGMT_API_KEY
API_SECRET = config.UMBRELLA_MGMT_API_SECRET

def getTopIdentities():
    url = 'https://management.api.umbrella.com/v1/organizations/5326453/users'

    # do GET request for the domain status and category
    req = requests.get(url, auth = (API_KEY, API_SECRET))

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    #print (output)

    print('{:^20}{:^20}{:^20}{:^20}{:^20}'.format(
        'First Name',
        'Last Name',
        'ID',
        'Role',
        'Email'
    ))

    for item in output:
        firstname = item['firstname']  
        lastname = item['lastname'] 
        ID = item['id'] 
        role = item['role']
        email = item['email']

        print('{:^20}{:^20}{:^20}{:^20}{:^20}'.format(
            firstname,
        	lastname,
            ID,
            role,
            email
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