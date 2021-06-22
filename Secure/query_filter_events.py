import requests
import config
import datetime


AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY
#print(AMP_CLIENT_ID)
#print(AMP_KEY)


def queryEvents(params):
    url = 'https://api.amp.cisco.com/v1/events'

    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY),params=params)

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    print (output)
    
    print('{:^20} {:^30}{:^15}{:^20}'.format('ID', 'Date', 'Disposition', 'File Path'))

    for item in output['data']:
        file_disposition = ''
        file_path = ''
        if 'file' in item:
            if 'disposition' in item['file']:
                file_disposition = item['file']['disposition']
            if 'file_path' in item['file']:
                file_path = item['file']['file_path']
            else:
                i = 0
        else:
            k = 0

        print('{:^20}{:^30}{:^15}{:^20}'.format(
			item['id'],
			item['date'],
			file_disposition,
			file_path
		))
		
        print('='*40)
        #print(f'Total:{len(response['data'])} results')
        print('='*40)
		

if __name__ == '__main__':
    while True:
        # Print the menu
        print("""
				Cisco Secure
				
					Query and Filter Event Types :
					""")
		
        hours = input(' Hours before(default - 20):  ')
        hours = hours.strip()
        if not hours:
            hours = 20
        hours = int(hours)
        start_date = (datetime.datetime.now()  - datetime.timedelta(hours=hours)).isoformat()
		
        event_type = input(' Event Type(default - 1090519054):  ')
        event_type = event_type.strip()
        if not event_type:
            event_type = 1090519054
        event_type = int(event_type)
		
        params = {'event_type': event_type, 'start_date': start_date}
		
        queryEvents(params)
					