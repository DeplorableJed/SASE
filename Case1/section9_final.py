import json, base64, email, hmac, hashlib, urllib3, urllib
import requests
import pprint
import config
import sys
import webex_teams_apis
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings

# Webex API Credentials
WEBEX_TEAMS_URL = config.WEBEX_TEAMS_URL
WEBEX_TEAMS_AUTH = config.WEBEX_TEAMS_AUTH
WEBEX_TEAMS_SPACE_NAME = config.WEBEX_TEAMS_SPACE_NAME
WEBEX_MESSAGE = ''

# DUO API configuration variables
API_HOSTNAME = config.DUO_API_HOSTNAME
S_KEY = config.DUO_API_SECRET_KEY
I_KEY = config.DUO_API_INTEGRATION_KEY

DUO_USER_GUIDE = config.DUO_USER_GUIDE
METHOD = 'POST'
API_PATH = '/admin/v1/users'


API_PATH_USER = '/admin/v1/users'
USERNAME = config.USERNAME
FIRSTNAME = config.FIRSTNAME
LASTNAME = config.LASTNAME
REALNAME = FIRSTNAME + " " + LASTNAME
EMAIL = config.EMAIL
PARAMS_USER = {
          'email': EMAIL,
          'firstname': FIRSTNAME,
          'lastname': LASTNAME,
          'realname': REALNAME,
          'username': USERNAME
          }


API_PATH_PHONE = '/admin/v1/phones'
NUMBER = config.PHONE_NUMBER
PHONE_NAME = config.PHONE_NAME
TYPE = 'mobile'
PLATFORM = config.PHONE_PLATFORM
PARAMS_PHONE = {
          'name': PHONE_NAME,
          'number': NUMBER,
          'platform': PLATFORM,
          'type': TYPE
          }


USER_ID = ''
API_PATH_ASSOCIATE = f'/admin/v1/users/{USER_ID}/phones'
PHONE_ID = ''  #phone_id
PARAMS_ASSOCIATE = {
          'phone_id': PHONE_ID
          }


# Script specific Umbrella variables
U_FIRSTNAME = config.UFIRSTNAME
U_LASTNAME = config.ULASTNAME
U_EMAIL = config.UEMAIL
U_ROLE_ID = config.UROLEID
U_TIMEZONE = config.UTIMEZONE
U_PASSWORD = config.UPASSWORD
U_ORG_ID = config.UMBRELLA_ORG_ID
U_API_HOSTNAME = config.UAPIHOST
U_API_KEY = config.UMBRELLA_MGMT_API_KEY
U_API_SECRET = config.UMBRELLA_MGMT_API_SECRET
U_USER_GUIDE = config.UUSERGUIDE

PARAMS_U_USER = {
        "firstname":U_FIRSTNAME,
         "lastname":U_LASTNAME,
         "email":U_EMAIL,
         "roleId":U_ROLE_ID,
         "timezone":U_TIMEZONE,
         "password":U_PASSWORD
          }

U_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
        }

def sign(method=METHOD,
         host=API_HOSTNAME,
         path=API_PATH_USER,
         params=PARAMS_USER,
         skey=S_KEY,
         ikey=I_KEY):

    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    """

    # create canonical string
    now = email.utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, str):
            val = val.encode("utf-8")
        args.append(
            '%s=%s' % (urllib.parse.quote(key, '~'), urllib.parse.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)
    #print(canon)

    # sign canonical string
    sig = hmac.new(skey.encode('utf-8'), canon.encode('utf-8'), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    #print(auth)
    encoded_auth = base64.b64encode(auth.encode('utf-8'))

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % str(encoded_auth, 'UTF-8')}

def createDuoUser():
    # Create the User and set the USER_ID which will be used in the Associate section
    url = f'https://{API_HOSTNAME}{API_PATH}'
    payload = PARAMS_USER
    request_headers = sign()
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    users = requests.request(METHOD, url, data=payload, headers=request_headers, verify=False)
    if (users.status_code != 200):
        print(f'An error has ocurred creating the User with the following code {users.status_code}!' )
        sys.exit(0)
    output = json.loads(users.content)
    #pprint.pprint(output)
    USER_ID = output['response']['user_id']
    USERNAME = output['response']['username']
    #print(USER_ID)
    print()
    print()
    print('-'*80)
    print(f'User ID created is = {USER_ID} with a username of {USERNAME}')
    print('-'*80)

    return USER_ID, USERNAME


def createDuoPhone ():
    # Create the Phone and set the PHONE_ID which will be used in the Associate section
    url = f'https://{API_HOSTNAME}{API_PATH_PHONE}'
    payload = PARAMS_PHONE
    #pprint.pprint(payload)
    request_headers = sign(METHOD,API_HOSTNAME,API_PATH_PHONE,PARAMS_PHONE,S_KEY,I_KEY)
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    #print(request_headers)
    phone = requests.request(METHOD, url, data=payload, headers=request_headers, verify=False)
    if (phone.status_code != 200):
        print(f'An error has ocurred creating the Phone with the following code {phone.status_code}!')
        sys.exit(0)
    output = json.loads(phone.content)
    #pprint.pprint(output)
    PHONE_ID = output['response']['phone_id']
    PHONE_NUMBER = output['response']['number']
    print('-'*80)
    print(f'Phone number {PHONE_NUMBER} ID is = {PHONE_ID}')
    print('-'*80)

    return PHONE_ID, PHONE_NUMBER

def associateUserToPhone():
    # Take the USER_ID and the PHONE_ID and Associate them
    PARAMS_ASSOCIATE = {
          'phone_id': PHONE_INFO[0]
          }
    API_PATH = f'/admin/v1/users/{USER_INFO[0]}/phones'
    #print(API_PATH)
    url = f'https://{API_HOSTNAME}{API_PATH}'
    payload = PARAMS_ASSOCIATE
    request_headers = sign(METHOD,API_HOSTNAME,API_PATH,PARAMS_ASSOCIATE,S_KEY,I_KEY)
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    association = requests.request(METHOD, url, data=payload, headers=request_headers, verify=False)
    if (association.status_code != 200):
        print(f'An error has ocurred associating the User with the Phone the following code {association.status_code}!' )
        sys.exit(0)
    output = json.loads(association.content)
    #pprint.pprint(output)
    print('-'*80)
    print(f'The Phone {PHONE_INFO[1]} is associated with the User {USER_INFO[1]}')
    print('-'*80)

def createUmbrellaUser():
    # Create a New Device in Umbrella for the new user

    url = f'{U_API_HOSTNAME}{U_ORG_ID}/users'
    #print(url)
    payload = PARAMS_U_USER
    u_user = requests.post(url, data=payload,  auth = (U_API_KEY, U_API_SECRET))
    if (u_user.status_code != 200):
        print(f'An error has ocurred associating the User with the Phone the following code {u_user.status_code}!' )
        sys.exit(0)
    output = json.loads(u_user.content)
    U_USER_ID = output['email']
    U_USER_ROLE = output['role']
    #pprint.pprint(output)
    print('*'*90)
    print(f'The Device with ID {U_USER_ID} has been added to Umbrella with {U_USER_ROLE} Access')
    print('*'*90)
    return U_USER_ID, U_USER_ROLE

if __name__ == "__main__":
    #USER_INFO=createDuoUser()
    #PHONE_INFO=createDuoPhone()
    #associateUserToPhone()
    U_USER_INFO=createUmbrellaUser()
