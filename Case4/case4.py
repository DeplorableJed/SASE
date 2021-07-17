from webexteamssdk import WebexTeamsAPI
import urllib3
import datetime
import time
import os
import json
import requests
import sys
import click
import tabulate
import cmd
import datetime
import pytz
import config
# Disable Certificate warning
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass
from requests.auth import HTTPBasicAuth
from pprint import pprint


vmanage_host = config.vManage['host']
vmanage_user = config.vManage['username']
vmanage_pass = config.vManage['password']
vmanage_port = config.vManage['port']
vmanage_headers = {'content-type': 'application/json'}

# Details for ServiceNow API Access
snow_url = config.serviceNow['url']
snow_user = config.serviceNow['username']
snow_pass = config.serviceNow['password']

# Details for Webex Teams
WEBEX_TEAMS_URL = config.WEBEX_TEAMS_URL
WEBEX_TEAMS_AUTH = config.WEBEX_TEAMS_AUTH
WEBEX_TEAMS_SPACE_NAME = config.WEBEX_TEAMS_SPACE_NAME
WEBEX_MESSAGE = 'Message from PodXX'
   
# Disable checking for non trusted certificates (lab only)   
requests.packages.urllib3.disable_warnings()

# Create a Cisco Spark object
api = WebexTeamsAPI(access_token=WEBEX_TEAMS_AUTH)


class rest_api_lib:

    def login(self,vmanage_host,vmanage_port, username, password):
        
        '''Login to vmanage'''
        base_url = f'https://{vmanage_host}:{vmanage_port}/'

        login_action = 'j_security_check'

        #Format data for loginForm
        login_data = {'j_username' : username, 'j_password' : password}


        #Url for posting login data
        login_url = base_url + login_action
        url = base_url + login_url

        sess = requests.session()

        #If the vmanage has a certificate signed by a trusted authority change verify to True

        login_response = sess.post(url=login_url, data=login_data, verify=False)

        try:
            cookies = login_response.headers['Set-Cookie']
            jsessionid = cookies.split(';')
            return(jsessionid[0])
        except:
            print('No valid JSESSION ID returned\n')
            exit()

        self.session[vmanage_host] = sess
       
    def get_token(self, vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = f'https://{vmanage_host}:{vmanage_port}'
        api = '/dataservice/client/token'
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None
            
    def get_request(self,mount_point):
        '''GET request'''
        url = f'https://{vmanage_host}:{vmanage_port}/dataservice/{mount_point}'
        #print(url)
      
        response = requests.get(url, headers=headers, verify=False)
        
        return response

    def post_request(self, mount_point, payload):
        '''POST request'''
        url = f'https://{vmanage_host}:{vmanage_port}/dataservice/{mount_point}'
        #print(url)
        payload = json.dumps(payload)
        #print (payload)
        #print (headers)

        response = requests.post(url=url, data=payload, headers=headers, verify=False)
        #print(response.text)
        #data = response
        return response


#Create session with vmanage 
print()
print('*'*100)
vmanage_session = rest_api_lib()
jsessionid = vmanage_session.login(vmanage_host,vmanage_port,vmanage_user,vmanage_pass)
print('The session id is '+jsessionid)
token = vmanage_session.get_token(vmanage_host,vmanage_port,jsessionid)
print('The token is '+token)
print('*'*100)
print()

if token is not None:
    headers = {'Content-Type': 'application/json','Cookie': jsessionid, 'X-XSRF-TOKEN': token}
else:
    headers = {'Content-Type': 'application/json','Cookie': jsessionid}

base_url = f"https://{vmanage_host}:{vmanage_port}/dataservice"



# Alarms
def list_alarms_tags():

    print("\nRetrieving the alarm tags\n")

    url = base_url + "/alarms/rulenamedisplay/keyvalue"

    response = requests.get(url=url, headers=headers,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        click.echo("Failed to get list of devices " + str(response.text))
        exit()

    tags = list()
    cli = cmd.Cmd()

    for item in items:
        if item['key'] == "":
            continue
        tags.append(item['key'])

    print(cli.columnize(tags,displaywidth=120))


def list_alarms(alarm_tag):

    print("\nRetrieving the alarms with tag %s\n"%alarm_tag)

    url = base_url + "/alarms"

    query = {
                "query": {
                    "condition": "AND",         # Logical AND Operation among rules defined below
                    "rules": [
                    {
                        "value": [              # last 24 hours
                            "24"
                        ],
                        "field": "entry_time",
                        "type": "date",
                        "operator": "last_n_hours"
                    },
                    {
                        "value": [              # Return both active and cleared alarms
                        "false","true"
                        ],
                        "field": "active",
                        "type": "string",
                        "operator": "in"
                    },
                    {
                        "value": [              # Alarm tag to filter specific type of alarms
                        alarm_tag
                        ],
                        "field": "rule_name_display",
                        "type": "string",
                        "operator": "in"
                    },
                    {
                        "value":[              
                            "false",
                        ],
                        "field": "acknowledged",
                        "type": "string",
                        "operator": "in"
                    },
                    {
                        "value":[              
                            "Critical",
                        ],
                        "field": "severity",
                        "type": "string",
                        "operator": "in"
                    }
                    ]
                }           
            }

    if token is not None:
        headers = {'Content-Type': 'application/json','Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        headers = {'Content-Type': 'application/json','Cookie': jsessionid}
    
    response = requests.post(url=url, headers=headers, data = json.dumps(query), verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get alarm details " + str(response.text))
        exit()

    table = list()
    PDT = pytz.timezone('America/Los_Angeles')
    headers = ["Date & Time (PDT)", "Alarm tag" , "Active", "Viewed", "Severity", "Details" ]

    for item in items:

        temp_time = datetime.datetime.utcfromtimestamp(item["entry_time"]/1000.)
        temp_time = pytz.UTC.localize(temp_time).astimezone(PDT).strftime('%m/%d/%Y %H:%M:%S')
        clear_details = ""
        if item.get("cleared_time",""):
            temp_clr_time = datetime.datetime.utcfromtimestamp(item["cleared_time"]/1000.)
            temp_clr_time = pytz.UTC.localize(temp_clr_time).astimezone(PDT).strftime('%m/%d/%Y %H:%M:%S') + ' PDT'
            clear_details = "\nCleared By: " + str(item.get("cleared_by"," ")) + "\nCleared Time: " + str(temp_clr_time)
        elif item.get("cleared_events",""):
            clear_details = "\nOrginal alarm: " + str(item.get("cleared_events"))

        tr = [ temp_time,item['rule_name_display'], item["active"], item["acknowledged"],item["severity"],
               "UUID: " + item["uuid"] + "\nValues:\n" + json.dumps(item["values"] , sort_keys=True, indent=4)
               + clear_details ]
        details = ("The device with IP " + json.dumps(item["values"][0]['system-ip'])+" had an alarm of "+alarm_tag)
        print("The device with IP " + json.dumps(item["values"][0]['system-ip'])+" had an alarm of "+alarm_tag)
        table.append(tr)

        
    try:
        print(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
        return details
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt="grid"))
        return details


# ServiceNow API calls

def get_user_sys_id(snow_user):

    # find the ServiceNow user_id for the specified user

    url = snow_url + '/table/sys_user?sysparm_limit=1'
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    response = requests.get(url, auth=(snow_user, snow_pass), headers=headers)
    user_json = response.json()
    return user_json['result'][0]['sys_id']


def create_incident(description, comment, snow_user, severity):

    # This function will create a new incident with the {description}, {comments}, severity for the {user}

    caller_sys_id = get_user_sys_id(snow_user)
    print ('The ServiceNow userid is '+caller_sys_id)
    url = snow_url + '/table/incident'
    payload = {'short_description': description,
               'comments': (comment + ', \nIncident created using APIs by caller by PUT_YOUR_NAME_HERE'),
               'caller_id': caller_sys_id,
               'urgency': severity
               }
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    response = requests.post(url, auth=(snow_user, snow_pass), data=json.dumps(payload), headers=headers)
    #print(response)
    incident_json = response.json()
    print('An incident with the number '+incident_json['result']['number']+' has been created by the user with ID '+caller_sys_id)
    return incident_json['result']['number']


if __name__ == "__main__":
    print ("Connection to vManage successful")
    list_alarms_tags()
    input("Press Enter to view the alarms that are Critical and caused by a System Reboot in the last 24 hours: ")
    details=list_alarms('System_Reboot_Issued')
    print('-'*80)
    title = 'The vEdge router for PodXX has been rebooted!'
    comments = 'There has been a user initiated reboot detected on : PodXX'
    create_incident('Pod21 Reboot', comments, snow_user,3)
    print('-'*80)
    print ('Posting to RoomID '+WEBEX_TEAMS_SPACE_NAME)
    print ('using token '+ WEBEX_TEAMS_AUTH)
    message = api.messages.create(WEBEX_TEAMS_SPACE_NAME,text=details)
    print('-'*80)
    print('End of Script')