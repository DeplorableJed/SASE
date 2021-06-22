import requests
import config

AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY


	
def listEventTypes():
    url = 'https://api.amp.cisco.com/v1/event_types'

    # do GET request for the domain status and category
    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY))

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    print (output)

    print('{:^20}{:^20}{:^120}'.format(
        'ID',
        'Name',
        'Description'
    ))

    for item in output['data']: 
        ID = item['id'] 
        name = item['name']
        description = item['description']

        print('{:^20}{:^20}{:^120}'.format(
            ID,
            name,
            description[:80]
        ))

def main():
    # Print the menu
    print('''
            Cisco Secure - List Event Types
                     SRW Blitz, Lab
                   ''')

    listEventTypes()


if __name__ == '__main__':
    main()

