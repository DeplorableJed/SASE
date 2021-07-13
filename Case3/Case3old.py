#! /usr/bin/env python

import os
import tabulate
import requests
import click
import json
import sys
import yaml
import pprint
import time
import webex_teams_apis
import config
import pprint

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

vmanage_host = config.vmanage_host
vmanage_port = config.vmanage_port
vmanage_username = config.vmanage_username
vmanage_password = config.vmanage_password

WEBEX_TEAMS_URL = config.WEBEX_TEAMS_URL
WEBEX_TEAMS_AUTH = config.WEBEX_TEAMS_AUTH
WEBEX_TEAMS_SPACE_NAME = config.WEBEX_TEAMS_SPACE_NAME
WEBEX_MESSAGE = 'Message from Pod1'

if vmanage_host is None or vmanage_port is None or vmanage_username is None or vmanage_password is None:
    print("Check the config.py file and ensure your credentials are set correctly")
    exit()

class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            click.echo("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None


def get_device_ids(jsessionid,token,template_id):

    if token is not None:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid}

    base_url = "https://{vmanage_host}:{vmanage_port}/dataservice"

    api_url = '/template/device/config/attached/' + template_id

    url = base_url + api_url

    response = requests.get(url=url, headers=headers,verify=False)

    if response.status_code == 200:
        device_ids = []
        for device in response.json()['data']:
            device_ids.append(device['uuid'])
        return device_ids

    else:
        click.echo("Failed to get device ids " + str(response.text))
        exit()

def get_device_inputs(jsessionid,token,template_id, device_ids):

    if token is not None:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
    else:
        headers = {'Content-Type': "application/json",'Cookie': jsessionid}

    payload = {
        'templateId': template_id,
        'deviceIds': device_ids,
        'isEdited': True,
        'isMasterEdited': False
    }

    base_url = "https://{vmanage_host}:{vmanage_port}/dataservice"

    api_url = '/template/device/config/input'

    url = base_url + api_url    

    response = requests.post(url=url, headers=headers, data=json.dumps(payload), verify=False)

    if response.status_code == 200:

        device_inputs = response.json()['data']

        for input in device_inputs:
            input['csv-templateId'] = template_id
    
    else:
        click.echo("Failed to get device config input " + str(response.text))
        exit()

    return device_inputs

Auth = Authentication()
jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

if token is not None:
    header = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
else:
    header = {'Content-Type': "application/json",'Cookie': jsessionid}

base_url = "https://%s:%s/dataservice"%(vmanage_host, vmanage_port)

@click.group()
def cli():
    """Command line tool for vManage Templates and Policy Configuration APIs.
    """
    pass

@click.command()
def template_list():
    """ Retrieve and return templates list.                      
        \nExample command: ./vmanage_config_apis.py template-list
    """
    click.secho("Retrieving the templates available.")

    url = base_url + "/template/device"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']

    else:
        print("Failed to get list of templates")
        exit()

    headers = ["Template Name", "Device Type", "Template ID", "Attached devices"]
    table = list()

    for item in items:
        tr = [item['templateName'], item['deviceType'], item['templateId'], item['devicesAttached']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()
def feature_list():
    """ Retrieve and return feature templates list.                      
        \nExample command: ./vmanage_config_apis.py feature-list
    """
    click.secho("Retrieving the non defaults feature templates that have been configured.")

    url = base_url + "/template/feature"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of feature templates")
        exit()

    headers = ["Template Name", "Device Type", "Template ID", "Template Type"]
    table = list()

    for item in items:
        if item['createdBy']=='admin':
            pprint.pprint(item)
            print ("*"*80)
            tr = [item['templateName'], item['deviceType'], item['templateId'], item['templateType']]
            table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()

def policy_list():
    """ Retrieve and return centralized policies list.                              
        \nExample command: ./vmanage_config_apis.py policy-list
    """
    click.secho("Retrieving the Centralized Policies available.")

    url = base_url + "/template/policy/vsmart"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of policies")
        exit()

    headers = ["Policy Name", "Policy Type", "Policy ID", "Active/Inactive"]
    table = list()

    for item in items:
        tr = [item['policyName'], item['policyType'], item['policyId'], item['isPolicyActivated']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()
@click.option("--name", help="Name of the policy")
def activate_policy(name):
    """   Activate centralized policy.                              
        \nExample command: ./vmanage_config_apis.py activate-policy --name MultiTopologyPlusAppRoute
    """

    policy_uuid = ""
    url = base_url + "/template/policy/vsmart"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
        for item in items:
            if item["policyName"] == name:
                policy_uuid = item['policyId']
                click.echo("Policy UUID for %s is %s"%(name,policy_uuid))
                break
    else:
        click.echo("Failed to get list of policies")
        exit()

    if policy_uuid == "":
        click.echo("Failed to find Policy UUID for %s, Please check if policy exists on vManage"%name)
        exit()

    url = base_url + "/template/policy/vsmart/activate/%s?confirm=true"%policy_uuid

    payload = {}

    response = requests.post(url=url, headers=header, data=json.dumps(payload),verify=False)
    if response.status_code == 200:
        process_id = response.json()['id']
        url = base_url + "/device/action/status/" + process_id
        while(1):
            policy_status_res = requests.get(url,headers=header,verify=False)
            if policy_status_res.status_code == 200:
                policy_push_status = policy_status_res.json()
                if policy_push_status['summary']['status'] == "done":
                    if 'Success' in policy_push_status['summary']['count']:
                        click.echo("\nSuccessfully activated vSmart Policy %s"%name)
                    elif 'Failure' in policy_push_status['summary']['count']:
                        click.echo("\nFailed to activate vSmart Policy %s"%name)
                    break
    else:
        click.echo("\nFailed to activate vSmart Policy %s"%name)

@click.command()
@click.option("--name", help="Name of the policy")
def deactivate_policy(name):
    """   Deactivate centralized policy.                              
        \nExample command: ./vmanage_config_apis.py deactivate-policy --name MultiTopologyPlusAppRoute
    """

    policy_uuid = ""
    url = base_url + "/template/policy/vsmart"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
        for item in items:
            if item["policyName"] == name:
                policy_uuid = item['policyId']
                click.echo("Policy UUID for %s is %s"%(name,policy_uuid))
                break
    else:
        click.echo("Failed to get list of policies")
        exit()

    if policy_uuid == "":
        click.echo("Failed to find Policy UUID for %s, Please check if policy exists on vManage"%name)
        exit()

    url = base_url + "/template/policy/vsmart/deactivate/%s?confirm=true"%policy_uuid

    payload = {}

    response = requests.post(url=url, headers=header, data=json.dumps(payload),verify=False)
    if response.status_code == 200:
        process_id = response.json()['id']
        url = base_url + "/device/action/status/" + process_id
        while(1):
            policy_status_res = requests.get(url,headers=header,verify=False)
            if policy_status_res.status_code == 200:
                policy_push_status = policy_status_res.json()
                if policy_push_status['summary']['status'] == "done":
                    if 'Success' in policy_push_status['summary']['count']:
                        click.echo("\nSuccessfully deactivated vSmart Policy %s"%name)
                    elif 'Failure' in policy_push_status['summary']['count']:
                        click.echo("\nFailed to deactivate vSmart Policy %s"%name)
                    break
    else:
        click.echo("\nFailed to deactivate vSmart Policy %s"%name)

@click.command()
@click.option("--name", help="Application Aware Routing Policy Name")
@click.option("--seq_name", help="Sequence name for which Preferred color should be changed")
@click.option("--pref_color", help="New Preferred color")
def approute_modify_color(name,seq_name,pref_color):
    """ Modify the Preferred Color in existing App Aware Route policy.                                  
        \nExample command: ./vmanage_config_apis.py approute-modify-color --name AppRoutePolicyVPN10 --seq_name DSCP46 --pref_color public-internet
    """
    try:
        
        new_path = pref_color
        app_route_policy_name = name

        if seq_name is None or pref_color is None or name is None :
            click.echo("\nInput parameters App route policy name or Sequence name or Preferred color is missing")  
            exit()   

        # Get app aware route policies 

        api_url = "/template/policy/definition/approute"        

        url = base_url + api_url
        
        response = requests.get(url=url, headers=header, verify=False)

        if response.status_code == 200:
            app_aware_policy = response.json()["data"]
            for item in app_aware_policy:
                if item["name"] == app_route_policy_name:
                    app_aware_policy_id = item["definitionId"]
                    break     
        else:
            click.echo("\nFailed to get app route policies list\n")
            exit()  

        # Get app aware route policy sequences definition 

        api_url = "/template/policy/definition/approute/%s"%app_aware_policy_id

        url = base_url + api_url
        
        response = requests.get(url=url, headers=header, verify=False)

        if response.status_code == 200:
            temp = response.json()
            for item1 in temp["sequences"]:
                if item1["sequenceName"] == seq_name:
                    for item2 in item1["actions"]:
                        if item2['type'] == 'slaClass':
                            for item3 in item2['parameter']:
                                if item3["field"] == 'preferredColor':
                                    item3["value"] = new_path

            app_policy_def = temp
            click.echo("\nRetrieved app aware route policy definition for %s"%app_route_policy_name)
        else:
            click.echo("\nFailed to get app route policy sequences\n")
            exit() 

        # Update policy app route policy 

        payload = {
                    "name": app_policy_def["name"] ,
                    "type": app_policy_def["type"],
                    "description": app_policy_def["description"] ,
                    "sequences": app_policy_def["sequences"]
                  }

        response = requests.put(url=url, headers=header, data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            master_templates_affected = response.json()['masterTemplatesAffected']
            if master_templates_affected:
                click.echo("\nMaster templates affected: %s"%master_templates_affected)
            else:
                click.echo("\nSuccessfully updated Preferred Color to %s in sequence %s of policy %s"%(pref_color,seq_name,name))
                exit()
        else:
            click.echo("\nFailed to edit app route policy " + str(response.text))
            exit()

        # Get device uuid and csv variables for each template id which is affected by prefix list edit operation

        inputs = []

        for template_id in master_templates_affected:
            device_ids = get_device_ids(jsessionid,token,template_id)
            device_inputs = get_device_inputs(jsessionid,token,template_id,device_ids)
            inputs.append((template_id, device_inputs))


        device_template_list = []
        
        for (template_id, device_input) in inputs:
            device_template_list.append({
                'templateId': template_id,
                'isEdited': True,
                'device': device_input
            })


        #api_url for CLI template 'template/device/config/attachcli'

        api_url = '/template/device/config/attachfeature'

        url = base_url + api_url

        payload = { 'deviceTemplateList': device_template_list }

        response = requests.post(url=url, headers=header,  data=json.dumps(payload), verify=False)

        if response.status_code == 200:
            process_id = response.json()["id"]
        else:
            click.echo("Template attach process failed " + str(response.text))     

        api_url = '/device/action/status/' + process_id  

        url = base_url + api_url

        while(1):
            policy_status_res = requests.get(url,headers=header,verify=False)
            if policy_status_res.status_code == 200:
                policy_push_status = policy_status_res.json()
                if policy_push_status['summary']['status'] == "done":
                    if 'Success' in policy_push_status['summary']['count']:
                        click.echo("\nSuccessfully updated Preferred Color to %s in sequence %s of policy %s"%(pref_color,seq_name,name))
                    elif 'Failure' in policy_push_status['summary']['count']:
                        click.echo("\nFailed to update Preferred Color to %s in sequence %s of policy %s"%(pref_color,seq_name,name))
                    break

    except Exception as e:
        print('Exception line number: {}'.format(sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            
def create_feature_template():
    """create template with Cisco SDWAN.
        Provide all template parameters and their values as arguments.
        Example command:
          ./vmanage_apis.py create-template --input_yaml=banner.yaml
    """
    click.secho("Creating feature template based on config details")
    api_url = "/template/feature"        
    url = base_url + api_url
    #payload = {"templateName":"vedge_cloud_lab","templateMinVersion":"15.0.0","templateDescription":"vedge_cloud_test","templateType":"banner","templateDefinition":{"login":{"vipObjectType":"object","vipType":"constant","vipValue":"test_banner","vipVariableName":"banner_login"},"motd":{"vipObjectType":"object","vipType":"constant","vipValue":"test_banner","vipVariableName":"banner_motd"}},"deviceType":["vedge-cloud"],"deviceModels":[{"name":"vedge-cloud","displayName":"vEdge Cloud","deviceType":"vedge","isCliSupported":True,"isCiscoDeviceModel":False}],"factoryDefault":False}

    payload = {
    "templateName": "test",
    "templateMinVersion": "15.0.0",
    "templateDescription": "test",
    "templateType": "banner",
    "templateDefinition": {
        "login": {
            "vipObjectType": "object",
            "vipType": "constant",
            "vipValue": "Hello World",
            "vipVariableName": "banner_login"
        },
        "motd": {
            "vipObjectType": "object",
            "vipType": "constant",
            "vipValue": "Have a good day",
            "vipVariableName": "banner_motd"
        }
    },
    "deviceType": [
        "vedge-CSR-1000v"
    ],
    "deviceModels": [
        {
            "name": "vedge-cloud",
            "displayName": "vEdge Cloud",
            "deviceType": "vedge",
            "isCliSupported": True,
            "isCiscoDeviceModel": False
        }
    ],
    "factoryDefault": False
    }
    print("Load payload data")
    payload = json.dumps(payload)
    print(url)
    pprint.pprint(payload)
    print(type(payload))
    headers={'Content-type': 'application/json', 'Accept': 'application/json'}
    response = requests.post(url=url, data=payload, headers=headers, verify=False)
    print(headers)
    
    if response.status_code == 200:
        print("\nCreated banner template ID: ", response.json())
    else:
        print("\nFailed creating banner template, error: ",response.text)

def create_device_template():
    api_url = "/template/device/feature"        
    url = base_url + api_url

    payload = {'configType': 'template',
     'deviceType': 'vedge-CSR-1000v',
     'factoryDefault': 'false',
     'featureTemplateUidRange': [],
     'generalTemplates': [{'templateId': '02e3cf1e-d826-4152-afc6-f681f1026247',
                           'templateType': 'cedge_aaa'},
                          {'templateId': 'c4b60893-91ee-4341-807e-9889114edeb0',
                           'templateType': 'cisco_system'},
                          {'templateId': '9f516c0a-ecc8-45ac-8f6c-1b7349112229',
                           'templateType': 'cisco_omp'},
                          {'subTemplates': [{'templateId': '1ec6dc94-b46d-466f-aa42-c224e06fe112',
                                             'templateType': 'cisco_vpn_interface'},
                                            {'templateId': 'a84fc720-d9f8-4746-8226-0fbce526ae69',
                                             'templateType': 'cisco_vpn_interface'}],
                           'templateId': 'cf144d5e-0829-4cab-a5b2-097ade0ba363',
                           'templateType': 'cisco_vpn'},
                          {'subTemplates': [{'templateId': 'd3de90df-3005-4a8e-ac90-8927a6c1c3ef',
                                             'templateType': 'cisco_vpn_interface'}],
                           'templateId': '8535dd50-9b77-4b2d-8b36-435127f43a19',
                           'templateType': 'cisco_vpn'},
                          {'subTemplates': [{'templateId': 'ed600ed2-3a92-4804-bb00-67ae21c3aa07',
                                             'templateType': 'cisco_ospf'},
                                            {'templateId': '831c9cb1-62d6-4e26-b537-e99355f24fed',
                                             'templateType': 'cisco_vpn_interface'},
                                            {'templateId': 'fb6f0489-87e3-4eef-8297-d577a7a3c1d5',
                                             'templateType': 'cisco_vpn_interface'}],
                           'templateId': 'e4b1b450-4999-4405-b2d1-9b149cb9441b',
                           'templateType': 'cisco_vpn'},
                          {'templateId': 'a120167b-c700-405e-8c15-8b75b31d57c4',
                           'templateType': 'cisco_sig_credentials'},
                          {'templateId': 'adc59c4b-441b-4839-9f9c-1cab21cf0907',
                           'templateType': 'cisco_banner'}],
     'policyId': '',
     'templateDescription': 'Device Template PodXX',
     'templateName': 'PodXX_Device_Template'}
    print("Load payload data")
    payload = json.dumps(payload)
    print(url)
    pprint.pprint(payload)
    #headers={'Content-type': 'application/json', 'Accept': 'application/json'}
    response = requests.post(url=url, data=payload, headers=header, verify=False)
    print(header)
    
    if response.status_code == 200:
        print("\nCreated banner template ID: ", response.json())
    else:
        print("\nFailed creating banner template, error: ",response.text)




if __name__ == "__main__":
    #cli()
    print()
    print("*"*80)
    create_device_template()
    #feature_list()
    #WEBEX_MESSAGE = 'The Device Template is as follows'
    #webex_teams_apis.post_space_message(WEBEX_TEAMS_SPACE_NAME, WEBEX_MESSAGE)
