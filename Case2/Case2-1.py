import requests
import config
import datetime


AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY


def queryEvents(params):
    url = 'https://api.amp.cisco.com/v1/events'

    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY),params=params)

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    #print (output)
    
    print('{:^20} {:^30}{:^15}{:^20}{:^20}{:^20}'.format('ID', 'Date', 'Disposition', 'Computer','File Name','File Path'))

    for item in output['data']:
        file_disposition = ''
        file_path = ''
        file_name = ''
        if 'file' in item:
            if 'disposition' in item['file']:
                file_disposition = item['file']['disposition']
            if 'file_path' in item['file']:
                file_path = item['file']['file_path']
            if 'file_name' in item['file']:
                file_path = item['file']['file_name']
            else:
                i = 0
        else:
            k = 0

        print('{:^20}{:^30}{:^15}{:^20}{:^20}{:^30}'.format(
			item['id'],
			item['date'][:19],
			file_disposition,
			item['computer']['hostname'],
			file_name,
			file_path
		))

    print()
    print('='*20)
    msg='Total of {} results'.format(len(output['data']))
    print(msg)
    print('='*20)
    
        
def isolateEndpoint(params):
    url = 'https://api.amp.cisco.com/v1/events'

    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY),params=params)

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    #print (output)
    
    print('{:^20} {:^30}{:^15}{:^20}{:^20}{:^20}'.format('ID', 'Date', 'Disposition', 'Computer','File Name','GUID'))

    for item in output['data']:
        file_disposition = ''
        file_path = ''
        file_name = ''
        if 'file' in item:
            if 'disposition' in item['file']:
                file_disposition = item['file']['disposition']
            if 'file_path' in item['file']:
                file_path = item['file']['file_path']
            if 'file_name' in item['file']:
                file_path = item['file']['file_name']
            else:
                i = 0
        else:
            k = 0

        print('{:^20}{:^30}{:^15}{:^20}{:^20}{:^30}'.format(
			item['id'],
			item['date'][:19],
			file_disposition,
			item['computer']['hostname'],
			file_name,
			file_path
		))

    print()
    print('='*20)
    msg='Total of {} results'.format(len(output['data']))
    print(msg)
    print('='*20)
    
    return guid
        		

if __name__ == '__main__':
    print("""
			Cisco Secure
			Case Study 2 :""")
    print()

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
    print('-'*120)
    
    guid = queryEvents(params)
    
    isolate = input('Would you like to Isolate the endpoint( y or n )')
    if isolate == ("n"):
        print("Goodbye")
        exit()
    elif isolate == ("y"):
        print()
        print("Isolating the Endpoint")
        
        
        
        
        
        
        
        
        
					