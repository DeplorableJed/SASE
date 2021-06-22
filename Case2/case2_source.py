#-------------------Section 1-------------------
import requests
import config
import datetime
import sys
import pprint
import webex_teams_apis
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings

#-------------------Section 2-------------------
WEBEX_TEAMS_URL = config.WEBEX_TEAMS_URL
WEBEX_TEAMS_AUTH = config.WEBEX_TEAMS_AUTH
WEBEX_TEAMS_SPACE_NAME = config.WEBEX_TEAMS_SPACE_NAME
WEBEX_MESSAGE = ''

AMP_CLIENT_ID = config.AMP_CLIENT_ID
AMP_KEY = config.AMP_KEY

#-------------------Section 3-------------------
def queryEvents(params):
    url = f'https://FIXME/v1/events'

    req = requests.get(url, auth = (AMP_CLIENT_ID, AMP_KEY),params=params)

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    pprint.pprint(output)

    print('{:^25} {:^20}{:^15}{:^20}{:^40}{:^40}'.format('Event', 'Date', 'Disposition', 'FIXME','GUID','Path'))

    for item in output['data']:
        file_disposition = ''
        file_path = ''
        file_name = ''
        hostname = ''
        connector_guid = ''
        if 'file' in item:
            if 'disposition' in item['file']:
                file_disposition = item['file']['disposition']
            if 'file_path' in item['file']:
                file_path = item['file']['file_path']
            if 'file_name' in item['file']:
                file_name = item['file']['file_name']
            if 'hostname' in item['computer']:
                hostname = item[FIXME]['hostname']
            if 'connector_guid' in item:
                connector_guid = item[FIXME]
            else:
                i = 0
        else:
            k = 0

        print('{:^25}{:^20}{:^15}{:^20}{:^40}{:^40}'.format(
			item['event_type'],
			item['date'][:19],
			file_disposition,
			hostname,
			connector_guid,
			file_path
		))

    print()
    print('='*20)
    msg='Total of {} results'.format(len(output['data']))
    print(msg)
    print('='*20)
#-------------------Section 4-------------------
if __name__ == '__main__':
    print("""
			Cisco Secure
			Case Study 2 :""")
    print()

    hours = input(' Hours before(default - 4):  ')
    hours = hours.strip()
    if not hours:
        hours = 4
    hours = int(hours)
    start_date = (datetime.datetime.now()  - datetime.timedelta(hours=hours)).isoformat()
    # Insert section 7 here when instructed!
    params = {'start_date': start_date}
    guid = queryEvents(params)
#-------------------Section 5-------------------
def getGroups():
    url = f'https://api.amp.cisco.com/v1/groups'

    req = requests.get(url, auth = (FIXME, AMP_KEY))

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 200):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    #print (output)

    print('{:<30} {:^30}'.format('Name', 'GUID'))
    print('{:<30} {:^30}'.format('----', '----'))


    for item in output['data']:
       print('{:<30}{:^30}'.format(
			item['name'],
			item['FIXME']
		))

    print()
    print('='*20)
    msg='Total of {} results'.format(len(output['data']))
    print(msg)
    print('='*20)
#-------------------Section 6-------------------
    isolate = input(' Would you like to move the endpoint to triage or another group? ( y or n ): ')
    if isolate == ("n"):
        print("Goodbye")
        sys.exit(0)
    elif isolate == ("y"):
        print()
        guid = input(' Enter the GUID or the device you want to move to Triage: ')
        #print(guid)
    groupInfo=getGroups()
#-------------------Section 7-------------------
    groups=[]
    for item in output['data']:
        groups.append(item['name'])

    guids=[]
    for item in output['data']:
        guids.append(item['guid'])

    print()
    print()
    print('What group would you like to move the endpoint to')
    print('-'*60)
    menu={}
    menu['1']=groups[0]
    menu['2']=groups[1]
    menu['3']=groups[2]
    menu['4']=groups[3]
    menu['5']=groups[4]
    menu['6']=groups[5]
    menu['7']='Stop the script'
    while True:
        options=menu.keys()
        #options.sort()
        for entry in options:
            print (entry, menu[entry])

        selection=input("Please Select: ")
        if selection =='1':
            print ('You selected option 1')
            groupGuid=guids[0]
            groupName=groups[0]
            break
        elif selection == '2':
            print ('You selected option 2')
            groupGuid=guids[1]
            groupName=groups[1]
            break
        elif selection == '3':
            print ('You selected option 3')
            groupGuid=guids[2]
            groupName=groups[2]
            break
        elif selection =='4':
            print ('You selected option 4')
            groupGuid=guids[3]
            groupName=groups[3]
            break
        elif selection == '5':
            print ('You selected option 5')
            groupGuid=guids[4]
            groupName=groups[4]
            break
        elif selection == '6':
            print ('You selected option 6')
            groupGuid=guids[5]
            groupName=groups[5]
            break
        elif selection == '7':
            print('--Goodbye--')
            sys.exit(0)
        else:
            print ('Unknown Option Selected!')
            sys.exit(0)

    print()
    print()
    print('*'*45)
    print(f'The selected group is {groupName}')
    print('*'*45)
    print()
    print()

    return groupGuid, groupName

#-------------------Section 8-------------------
    event_type = input(' Event Type(default - 1090519054):  ')
    event_type = event_type.strip()
    if not event_type:
        event_type = 1090519054
    event_type = int(event_type)

    params = {'event_type': event_type, 'start_date': start_date}
    print('-'*120)

#-------------------Section 9-------------------
def moveGroup(guid, groupGuid, groupName):
    url = f'https://api.amp.cisco.com/v1/FIXME'
    print(url)
    payload = '{"group_guid": "'+str(groupInfo[FIXME])+'"}'
    #print(payload)
    headers = {'content-type': 'application/json'}
    req = requests.patch(url, auth = (AMP_CLIENT_ID, AMP_KEY),data=payload,headers=headers)
    #print(req)

    # error handling if true then the request was HTTP 200, so successful
    if (req.status_code != 202):
        print('An error has ocurred with the following code %s' % req.status_code)
        sys.exit(0)

    output = req.json()
    print()
    print()
    print('*'*110)
    print('The device is now in the {groupName} group with a group GUID of {groupGuid}')
    print('*'*110)
    print()
    print()

#-------------------Section 10-------------------

    moveGroup(guid,groupInfo[0],groupInfo[1])
    WEBEX_MESSAGE = f'The endpoint with GUID of "{guid}" has been moved to the "{groupInfo[1]}" group by StudentXX'
    webex_teams_apis.post_space_message(WEBEX_TEAMS_SPACE_NAME, WEBEX_MESSAGE)


    print('='*30)
    print('Please remediate the endpoint')
    input('Press enter when ready to move from Triage to the home group')
    print('='*30)

    groupInfo=getGroups()
    moveGroup(guid,groupInfo[0],groupInfo[1])
    WEBEX_MESSAGE = f'The endpoint with GUID of "{guid}" has been moved to the "{groupInfo[1]}" group by StudentXX'
    webex_teams_apis.post_space_message(WEBEX_TEAMS_SPACE_NAME, WEBEX_MESSAGE)

    print('='*30)
    print('THE SCRIPT HAS COMPLETED')
    print('='*30)
