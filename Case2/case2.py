import requests
import config

AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY


	
def listEventTypes():
    url = 'https://api.amp.cisco.com/v1/events?event_type[]=1090519054'

    # do GET request for the domain status and category
    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY))

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    print (output)

    print('{:^20}{:^20}{:^40}{:^20}'.format(
        'Datetime',
        'Event',
        'Description',
        'Computer'
    ))

    for item in output['data']: 
        datetime = item['date'] 
        event = item['event_type_id']
        description = item['event_type']
        computer = item['computer']['hostname']

        print('{:^20}{:^20}{:^40}{:^20}'.format(
            datetime[:19],
            event,
            description,
            computer
        ))

def main():
    # Print the menu
    print('''
            Cisco Secure - Case Study 2
                     SRW Blitz, Lab
                   ''')

    listEventTypes()


if __name__ == '__main__':
    main()

