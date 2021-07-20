import requests
import sys
import json
import os
import tabulate
import click
import pprint
import time
import yaml
import config
from requests.packages.urllib3.exceptions import InsecureRequestWarning

vmanage_host = config.vmanage_host
vmanage_port = config.vmanage_port
vmanage_username = config.vmanage_username
vmanage_password = config.vmanage_password

WEBEX_TEAMS_URL = config.WEBEX_TEAMS_URL
WEBEX_TEAMS_AUTH = config.WEBEX_TEAMS_AUTH
WEBEX_TEAMS_SPACE_NAME = config.WEBEX_TEAMS_SPACE_NAME
WEBEX_MESSAGE = 'CUSTOMIZE ME'

#YAML_FILE = config.YAML_FILE



requests.packages.urllib3.disable_warnings()

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
jsessionid = vmanage_session.login(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
print('The session id is '+jsessionid)
token = vmanage_session.get_token(vmanage_host,vmanage_port,jsessionid)
print('The token is '+token)
print('*'*100)
print()

if token is not None:
    headers = {'Content-Type': 'application/json','Cookie': jsessionid, 'X-XSRF-TOKEN': token}
else:
    headers = {'Content-Type': 'application/json','Cookie': jsessionid}

def list_devices():

    # Retrieve and return information about network devices in SD-WAN fabric.

    print('Retrieving the device list')

    response = vmanage_session.get_request('device').json()

    items = response['data']

    print('\nDevice details retrieved for one network device') 
       
    #pprint.pprint(items[1])

    print('\nlist of all devices retrieved')

    headers = ['Host-Name', 'Device Type', 'Latitude', 'Longitude', 'Certificate\nValidity', 'Version', 'Device Model', 'System IP']
    table = list()

    for item in items:
        if item['reachability'] == 'reachable':
            tr = [item['host-name'], item['device-type'], item['latitude'], item['longitude'], item['certificate-validity'], item['version'], item['device-model'], item['system-ip']]
            table.append(tr)
    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))

def system_status(system_ip):
    # Retrieve and return information about system status of network device in SD-WAN fabric

    print('Retrieving the System Status')

    url = 'device/system/status?deviceId={0}'.format(system_ip)

    response = vmanage_session.get_request(url).json()

    items = response['data']

    print('\nSystem status for Device = ',system_ip)

    headers = ['Host name', 'Up time', 'Version', 'Memory Used', 'CPU system']
    table = list()

    for item in items:
        tr = [item['vdevice-host-name'], item['uptime'], item['version'], item['mem_used'], item['cpu_system']]
        table.append(tr)

    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))


def interface_status(system_ip):
    # Retrieve and return information about Interface status of network device in SD-WAN fabric

    print('Retrieving the interface Status')

    url = 'device/interface/synced?deviceId={0}'.format(system_ip)

    response = vmanage_session.get_request(url).json()

    items = response['data']

    print('\nInterfaces status for Device = ',system_ip)

    headers = ['Interface Name', 'Operational status']
    table = list()

    for item in items:
        tr = [item['ifname'], item['if-oper-status']]
        table.append(tr)

    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))



def control_status(system_ip):
    # Retrieve and return information about Control status of network device in SD-WAN fabric


    print('Retrieving the Control Status')

    url = 'device/control/synced/connections?deviceId={0}'.format(system_ip)

    response = vmanage_session.get_request(url).json()

    items = response['data']

    print('\nControl Connection status for Device = ',system_ip)

    headers = ['Peer Type', 'Peer System IP', 'state', 'Last Updated']
    table = list()

    for item in items:
        tr = [item['peer-type'], item['system-ip'], item['state'], time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(item['lastupdated']/1000.))]
        table.append(tr)

    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))



def device_counters(system_ip):
    # Retrieve and return information about Device Counters of network device in SD-WAN fabric

    print('Retrieving the Device Counters')

    url = 'device/counters?deviceId={0}'.format(system_ip)

    response = vmanage_session.get_request(url).json()

    items = response['data']

    print('\nDevice Counters for Device = ',system_ip)


    headers = ['OMP Peers Up', 'OMP Peers Down', 'Vsmart connections', 'BFD Sessions Up', 'BFD Sessions Down']
    table = list()

    for item in items:
        try:
            tr = [item['ompPeersUp'], item['ompPeersDown'], item['number-vsmart-control-connections'], item['bfdSessionsUp'], item['bfdSessionsDown']]
            table.append(tr)
        except KeyError:
            pass

    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))



def list_device_template():
    # Retrieve and return device templates list.

    print('Retrieving the templates available.')

    response = vmanage_session.get_request('template/device').json()

    items = response['data']

    headers = ['Template Name', 'Device Type', 'Template ID', 'Attached devices', 'Template version']
    table = list()

    for item in items:
        tr = [item['templateName'], item['deviceType'], item['templateId'], item['devicesAttached'], item['templateAttached']]
        table.append(tr)
    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))




def create_banner_template():
    #create banner template with Cisco SDWAN.

    #print('Loading Feature Template Details from YAML File')
    with open('banner_config.yaml') as f:
        #print(f)
        config = yaml.safe_load(f.read())

    payload = {
        'templateName': config['template_name'],
        'templateMinVersion': '15.0.0',
        'templateDescription': config['template_description'],
        'templateType': 'cisco_banner',
        'templateDefinition': {
            'login': {
                'vipObjectType': 'object',
                'vipType': 'constant',
                'vipValue': config['login_banner'],  # using the values defined for login banner in yaml file
                'vipVariableName': 'banner_login'
            },
            'motd': {
                'vipObjectType': 'object',
                'vipType': 'constant',
                'vipValue': config['motd_banner'],  # using the values defined for motd banner in yaml file
                'vipVariableName': 'banner_motd'
            }
        },
         'deviceType': [
            config['device_type']
        ],
        'deviceModels': [
             {
                'name': 'vedge-CSR-1000v',
                'displayName': 'vEdge CSR 1000v',
                'deviceType': 'vedge-CSR-1000v',
                'isCliSupported': True,
                'isCiscoDeviceModel': False
             }
         ],
         'factoryDefault': False
         }

    #pprint.pprint(payload)
    response = vmanage_session.post_request('template/feature/', payload)
    req=response.json()

    if response.status_code == 200:
        d=dict(response.json())
        print('Created banner feature template with the ID: '+d['templateId'])
        return d['templateId']

    else:
        print('Failed creating banner template, error: ',response.text)
        exit

def create_SIG_cred_template():
    # create SIG Credential template with Cisco SDWAN.
 

    #print('Loading Feature Template Details from YAML File')
    with open('SIG_cred_config.yaml') as f:
        #print(f)
        config = yaml.safe_load(f.read())

    payload = {
	'templateName':config['template_name'],
		'templateDescription':config['template_description'],
		'templateType':'cisco_sig_credentials',
		'deviceType':[
			config['device_type']
		],
		'templateMinVersion':'15.0.0',
		'templateDefinition':{
			'umbrella':{
				'api-key':{
					'vipObjectType':'object',
					'vipType':'constant',
					'vipValue':'a27322d2918a4aba9f5afa811110ff41',
					'vipVariableName':'system_api_key'
				},
				'api-secret':{
					'vipObjectType':'object',
					'vipType':'constant',
					'vipValue':'2176b00b1e074d93be82f3d5fe287353',
					'vipVariableName':'system_api_secret',
					'vipNeedsEncryption':'true'
				},
				'org-id':{
					'vipObjectType':'object',
					'vipType':'constant',
					'vipValue':'5326453',
					'vipVariableName':'system_org_id'
				}
			}
	    },
        'factoryDefault':'false'
	}


    #pprint.pprint(payload)
    response = vmanage_session.post_request('template/feature/', payload)
    req=response.json()
    #print(req)

    if response.status_code == 200:
        d=dict(response.json())
        print('Created SIG Credentials feature template with the ID: '+d['templateId'])
        return d['templateId']

    else:
        print('Failed creating SIG Credentials template, error: ',response.text)
        exit

def create_SIG_tunnel_template():
    # create SIG Tunnel template with Cisco SDWAN


    #print('Loading Feature Template Details from YAML File')
    with open('tunnel_config.yaml') as f:
        config = yaml.safe_load(f.read())

    payload = {
		'templateName':config['template_name'],
		'templateDescription':config['template_description'],
		'templateType':'cisco_secure_internet_gateway',
		'deviceType':[
			config['device_type']
		],
		'templateMinVersion':'15.0.0',
		'templateDefinition':{
			'vpn-id':{
				'vipObjectType':'object',
				'vipType':'constant',
				'vipValue':0
			},
			'interface':{
				'vipType':'constant',
				'vipValue':[
					{
						'if-name':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'ipsec1',
							'vipVariableName':'tunnel_if_name'
						},
						'auto':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'true'
						},
						'shutdown':{
							'vipObjectType':'object',
							'vipType':'notIgnore',
							'vipValue':'false',
							'vipVariableName':'tunnel_shutdown'
						},
						'description':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'SIG Tunnel',
							'vipVariableName':'tunnel_description'
						},
						'ip':{
							'unnumbered':{
								'vipObjectType':'node-only',
								'vipType':'constant',
								'vipValue':'true'
							}
						},
						'tunnel-source-interface':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':config['source_interface'],
							'vipVariableName':'tunnel_tunnel_source_interface'
						},
						'tunnel-destination':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'dynamic'
						},
						'application':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'sig'
						},
						'tunnel-set':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'secure-internet-gateway-umbrella'
						},
						'tunnel-dc-preference':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'primary-dc'
						},
						'tcp-mss-adjust':{
							'vipObjectType':'object',
							'vipType':'ignore',
							'vipValue':1300,
							'vipVariableName':'tunnel_tcp_mss_adjust_'
						},
						'mtu':{
							'vipObjectType':'object',
							'vipType':'notIgnore',
							'vipValue':1400,
							'vipVariableName':'tunnel_mtu_'
						},
						'dead-peer-detection':{
							'dpd-interval':{
								'vipObjectType':'object',
								'vipType':'constant',
								'vipValue':10,
								'vipVariableName':'tunnel_dpd_interval'
							},
							'dpd-retries':{
								'vipObjectType':'object',
								'vipType':'constant',
								'vipValue':3,
								'vipVariableName':'tunnel_dpd_retries'
							}
						},
						'ike':{
							'ike-version':{
								'vipObjectType':'object',
								'vipType':'constant',
								'vipValue':2
							},
							'authentication-type':{
								'pre-shared-key-dynamic':{
									'vipObjectType':'node-only',
									'vipType':'constant',
									'vipValue':'true'
								}
							},
							'ike-rekey-interval':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':14400,
								'vipVariableName':'tunnel_ike_rekey_interval_'
							},
							'ike-ciphersuite':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':'aes256-cbc-sha1',
								'vipVariableName':'tunnel_ike_ciphersuite'
							},
							'ike-group':{
								'vipObjectType':'object',
								'vipType':'notIgnore',
								'vipValue':'14',
								'vipVariableName':'tunnel_ike_group'
							}
						},
						'ipsec':{
							'ipsec-rekey-interval':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':3600,
								'vipVariableName':'tunnel_ipsec_rekey_interval'
							},
							'ipsec-replay-window':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':512,
								'vipVariableName':'tunnel_ipsec_replay_window'
							},
							'ipsec-ciphersuite':{
								'vipObjectType':'object',
								'vipType':'notIgnore',
								'vipValue':'aes256-gcm',
								'vipVariableName':'tunnel_ipsec_ciphersuite'
							},
							'perfect-forward-secrecy':{
								'vipObjectType':'object',
								'vipType':'notIgnore',
								'vipValue':'none',
								'vipVariableName':'tunnel_perfect_forward_secrecy'
							}
						}
					}
				],
				'vipObjectType':'tree',
				'vipPrimaryKey':[
					'if-name'
				]
			},
			'service':{
				'vipType':'constant',
				'vipValue':[
					{
						'svc-type':{
							'vipObjectType':'object',
							'vipType':'constant',
							'vipValue':'sig'
						},
						'ha-pairs':{
							'interface-pair':{
								'vipType':'constant',
								'vipObjectType':'tree',
								'vipPrimaryKey':[
									'active-interface',
									'backup-interface'
								],
								'vipValue':[
									{
										'active-interface':{
											'vipObjectType':'object',
											'vipType':'constant',
											'vipValue':'ipsec1'
										},
										'backup-interface':{
											'vipObjectType':'object',
											'vipType':'constant',
											'vipValue':'None'
										},
										'active-interface-weight':{
											'vipObjectType':'object',
											'vipType':'constant',
											'vipValue':1
										},
										'backup-interface-weight':{
											'vipObjectType':'object',
											'vipType':'constant',
											'vipValue':1
										},
										'priority-order':[
											'active-interface',
											'backup-interface',
											'active-interface-weight',
											'backup-interface-weight'
										]
									}
								]
							}
						},
						'umbrella-data-center':{
							'data-center-primary':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':'',
								'vipVariableName':'vpn_umbprimarydc'
							},
							'data-center-secondary':{
								'vipObjectType':'object',
								'vipType':'ignore',
								'vipValue':'',
								'vipVariableName':'vpn_umbsecondarydc'
							}
						}
					}
				],
				'vipObjectType':'tree',
				'vipPrimaryKey':[
					'svc-type'
				]
			}
		},
		'factoryDefault':'false'
	}


    #pprint.pprint(payload)
    response = vmanage_session.post_request('template/feature/', payload)
    req=response.json()

    if response.status_code == 200:
        d=dict(response.json())
        print('Created SIG Credentials feature template with the ID: '+d['templateId'])
        return d['templateId']

    else:
        print('Failed creating banner template, error: ',response.text)
        exit
		
def list_device_template():
    #Retrieve and return device templates list

    print('Retrieving the templates available.')

    response = vmanage_session.get_request('template/device').json()

    items = response['data']

    headers = ['Template Name', 'Device Type', 'Template ID', 'Attached devices', 'Template version']
    table = list()

    for item in items:
        if item['lastUpdatedBy']=='admin':
            tr = [item['templateName'], item['deviceType'], item['templateId'], item['devicesAttached'], item['templateAttached']]
            table.append(tr)
    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))




def create_device_template():
    #create device template with Cisco SDWAN
    print('Creating device template based on yaml file details')
    with open('device_template_config.yaml') as f:
        #print(f)
        config = yaml.safe_load(f.read())
        #print(config)

    payload = {
      'templateName': config['template_name'],
      'templateDescription': config['template_description'],
      'deviceType': config['device_type'],
      'configType': 'template',
      'policyId': '',
      'factoryDefault': 'false',
      'featureTemplateUidRange': [],
      'generalTemplates': [
        {
          'templateId': '02e3cf1e-d826-4152-afc6-f681f1026247',
          'templateType': 'cedge_aaa'
        },
            {
          'templateId': 'c4b60893-91ee-4341-807e-9889114edeb0',
          'templateType': 'cisco_system'
        },
            {
          'templateId': '9f516c0a-ecc8-45ac-8f6c-1b7349112229',
          'templateType': 'cisco_omp'
        },
            {
          'templateId': 'cf144d5e-0829-4cab-a5b2-097ade0ba363',
          'templateType': 'cisco_vpn',
          'subTemplates': [
            {
              'templateId': config['sig_tunnel_id'],
              'templateType': 'cisco_vpn_interface'
            },
            {
              'templateId': 'a84fc720-d9f8-4746-8226-0fbce526ae69',
              'templateType': 'cisco_vpn_interface'
            }
          ]
        },
            {
              'templateId': '8535dd50-9b77-4b2d-8b36-435127f43a19',
          'templateType': 'cisco_vpn',
          'subTemplates': [
            {
              'templateId': 'd3de90df-3005-4a8e-ac90-8927a6c1c3ef',
              'templateType': 'cisco_vpn_interface'
            }
          ]
        },
             {
          'templateId': 'e4b1b450-4999-4405-b2d1-9b149cb9441b',
          'templateType': 'cisco_vpn',
          'subTemplates': [
            {
              'templateId': '88c1d524-8dcf-412e-899b-28a204e962d3',
              'templateType': 'cisco_ospf'
            },
            {
              'templateId': '831c9cb1-62d6-4e26-b537-e99355f24fed',
              'templateType': 'cisco_vpn_interface'
            },
            {
              'templateId': 'fb6f0489-87e3-4eef-8297-d577a7a3c1d5',
              'templateType': 'cisco_vpn_interface'
            }
          ]
        },   
            {
          'templateId': config['sig_cred_id'],
          'templateType': 'cisco_sig_credentials'
        },
                {
          'templateId': config['banner_id'],
          'templateType': 'cisco_banner'
        },
            {
          'templateId': 'ed600ed2-3a92-4804-bb00-67ae21c3aa07',
          'templateType': 'cisco_smnp'
        },
            {
          'templateId': 'dbe0d474-81fe-4791-8667-affc33d90289',
          'templateType': 'cisco_logging'
        },
            {
          'templateId': '178199ac-3e3c-4734-b81c-0af67cfdde25',
          'templateType': 'cisco_bfd'
        },
            {
          'templateId': '53a0e87f-a276-438b-8966-787ccf434233',
          'templateType': 'cisco_security'
        },
            {
          'templateId': '1948df12-dc42-4342-a2d1-f4200a6fdf45',
          'templateType': 'cedge_global'
        }
        ]
    }
    #pprint.pprint(payload)
    response = vmanage_session.post_request('template/device/feature/', payload)
    req=response.json()

    if response.status_code == 200:
        d=dict(response.json())
        #print(d)
        print('Created Device template with ID: '+d['templateId'])
        return d['templateId']

    else:
        print('Failed creating banner template, error: ',response.text)
        exit
 

def list_feature():
    #Retrieve and return the NON default feature template
    
    print('Retrieving the templates available.')

    response = vmanage_session.get_request('template/feature').json()

    items = response['data']

    headers = ['Template Name', 'Model', 'Template Type', 'Template ID']
    table = list()
    
    for item in items:
        if item['createdBy']=='admin':
            tr = [item['templateName'], item['deviceType'], item['templateType'], item['templateId']]
            table.append(tr)
    try:
        print(tabulate.tabulate(table, headers, tablefmt='fancy_grid'))
    except UnicodeEncodeError:
        print(tabulate.tabulate(table, headers, tablefmt='grid'))

def attach(template, variables):
    """Attach a template with Cisco SDWAN.
        Provide all template parameters and their values as arguments.
        Example command:
          ./sdwan.py attach --template template-id --variables Site-3-vEdge-Variables.yaml
    
    print("Attempting to attach template.")
    
    with open('attach_config.yaml) as f:
        config = yaml.safe_load(f.read())

    system_ip = config.get("system_ip")
    host_name = config.get("host_name")
    template_id = template

    template_variables = {
                            "csv-status":"complete",
                            "csv-deviceId": config.get("device_id"),
                            "csv-deviceIP": system_ip,
                            "csv-host-name": host_name,
                            "//system/host-name": config.get("system_host_name"),
                            "//system/system-ip": config.get("system_system_ip"),
                            "//system/site-id": config.get("site_id"),
                            "/1/vpn_1_if_name/interface/ip/address": config.get("vpn_1_if_ipv4_address"),
                            
                            "/512/vpn_512_if_name/interface/ip/address": config.get("vpn_512_if_ipv4_address"),
                            "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/mpls_next_hop/address": config.get("mpls_next_hop"),
                            "/0/vpn-instance/ip/route/0.0.0.0/0/next-hop/public_internet_next_hop/address": config.get("public_internet_next_hop"),
                            "/0/vpn_public_internet_interface/interface/if-name": config.get("vpn_public_internet_interface"),
                            "/0/vpn_public_internet_interface/interface/ip/address": config.get("vpn_public_internet_interface"),
                            "/0/vpn_mpls_interface/interface/if-name": config.get("vpn_mpls_interface"),
                            "/0/vpn_mpls_interface/interface/ip/address": config.get("vpn_mpls_if_ipv4_address"),
                         }


    payload = {
        "deviceTemplateList":[
        {
            "templateId":template_id,       
            "device":[ template_variables ],
            "isEdited":"false", 
            "isMasterEdited":"false" 
        }
        ]
    }

    url = base_url + "/template/device/config/attachfeature"

    response = requests.post(url=url, data=json.dumps(payload), headers=header, verify=False)
    if response.status_code == 200:
        attach_template_pushid = response.json()['id']
        url = base_url + "/device/action/status/%s"%attach_template_pushid
        while(1):
            template_status_res = requests.get(url,headers=header,verify=False)
            if template_status_res.status_code == 200:
                template_push_status = template_status_res.json()
                if template_push_status['summary']['status'] == "done":
                    if 'Success' in template_push_status['summary']['count']:
                        print("Attached Site 3 vEdge Template")
                    elif 'Failure' in template_push_status['summary']['count']:
                        print("Failed to attach Site 3 vEdge Template")
                        exit()
                    break
            else:             
                print("\nFetching template push status failed")
                exit()

    else:
        print("Failed to attach Site 3 vEdge Template")
        exit()
    """


if __name__ == '__main__':

    # List starting feature templates
    list_feature()
    print('*'*80)
    
	# Collect Banner info, read YAML as Dict, add input to Dict, and write to YAML files
    input('Press Enter to create a new banner template using the API: ')
    tname = input('Enter your template name with no spaces (Example PodXX_Banner_FT): ')
    tdesc = input('Enter your template description (Example PodXX Banner Feature Template): ')
    tlogin = input('Enter your login banner text: ')
    tmotd = input('Enter your motd banner text: ')
    with open('banner_config.yaml','r') as f:
        data_list = yaml.safe_load(f)
        data_list.update({'template_name': tname,'template_description': tdesc,'login_banner': tlogin, 'motd_banner': tmotd})
    with open('banner_config.yaml', 'w') as f:
        yaml.dump(data_list, f)
    bannerID = create_banner_template()
    #print('A banner template has been created with an id of: '+bannerID)
    print('*'*80)

	# Collect SIG Cred info, read YAML as Dict, add input to Dict, and write to YAML files
    input("Press Enter to create a SIG Credential Feature Template: ")	
    tname = input('Enter your template name with no spaces (Example PodXX_SIG_Cred_FT): ')
    tdesc = input('Enter your template description (Example PodXX SIG Credentials Feature Template): ')
    with open('SIG_cred_config.yaml','r') as f:
        data_list = yaml.safe_load(f)
        data_list.update({'template_name': tname,'template_description': tdesc})
    with open('SIG_cred_config.yaml', 'w') as f:
        yaml.dump(data_list, f)
    sigCredID = create_SIG_cred_template()
    #print('A SIG Credential template has been created with an id of: '+sigCredID)
    print('*'*80)
    
    # Collect SIG Tunnel info, read YAML as Dict, add input to Dict, and write to YAML files
    input("Press Enter to create a SIG Tunnel Feature Template: ")
    tname = input('Enter your template name with no spaces (Example PodXX_SIG_Tunnel_FT): ')
    tdesc = input('Enter your template description (Example PodXX SIG Tunnel Feature Template): ')
    with open('tunnel_config.yaml','r') as f:
        data_list = yaml.safe_load(f)
        data_list.update({'template_name': tname,'template_description': tdesc})
    with open('tunnel_config.yaml', 'w') as f:
        yaml.dump(data_list, f)
    sigTunnelID = create_SIG_tunnel_template()
    #print('A SIG Tunnel template has been created with an id of: '+sigTunnelID)    
    print('*'*80)

    # List all non default feature templates
    input('Press Enter to see the 3 new templates have been added: ')
    list_feature()
    print('*'*80)

    # List all non default device templates	
    input('Press Enter to view the starting device templates')
    list_device_template()
    print('*'*80)

    #Collect Device Template info, read YAML as Dict, add input to Dict, and write to YAML files	
    input('Press Enter to create a new devices template: ')
    dtname = input('Enter your device template name with no spaces (Example PodXX_Device_Template): ')
    dtdesc = input('Enter your device template description (Example PodXX Device Template): ')
    with open('device_template_config.yaml','r') as f:
        data_list = yaml.safe_load(f)
        data_list.update({'template_name': dtname,'template_description': dtdesc, 'banner_id': bannerID, 'sig_cred_id': sigCredID, 'sig_tunnel_id': sigTunnelID})
    with open('device_template_config.yaml', 'w') as f:
        yaml.dump(data_list, f)
    create_device_template()
    print('*'*80)

    # List all non default device template
    list_device_template()
    print('*'*80)

    # List Devices in the Lab	
    input('Press Enter to view devices: ')
    list_devices()
    print('*'*80)
	
    print('End of Script')
    print('*'*80)
