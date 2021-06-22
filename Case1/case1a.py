import json, base64, email, hmac, hashlib, urllib3, urllib
import requests
import pprint
import config
import sys


urllib3.disable_warnings()

# Imported API configuration variables
API_HOSTNAME = config.DUO_API_HOSTNAME
S_KEY = config.DUO_API_SECRET_KEY
I_KEY = config.DUO_API_INTEGRATION_KEY

# Script specific Cisco Secure variables
METHOD = 'POST'
API_PATH = '/admin/v1/users'

METHOD_POST = 'POST'
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

          

METHOD_POST = 'POST'
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



METHOD_POST = 'POST'
USER_ID = ''  # user_id from get_user_by_username.py output
API_PATH_ASSOCIATE = '/admin/v1/users/{}/phones'.format(USER_ID)
PHONE_ID = ''  #phone_id from get_phone_by_number.py output
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
    print(canon)

    # sign canonical string
    sig = hmac.new(skey.encode('utf-8'), canon.encode('utf-8'), hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())
    #print(auth)
    encoded_auth = base64.b64encode(auth.encode('utf-8'))

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % str(encoded_auth, 'UTF-8')}
    
def createDuoUser():
    # Create the User and set the USER_ID which will be used in the Associate section
    url_USER = "https://{}{}".format(API_HOSTNAME, API_PATH)
    payload = PARAMS_USER
    request_headers = sign()
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    users = requests.request(METHOD, url_USER, data=payload, headers=request_headers, verify=False)    
    if (users.status_code != 200):
        print(f'An error has ocurred creating the User with the following code {users.status_code}!' )
        sys.exit(0)
    output = json.loads(users.content)
    pprint.pprint(output)
    USER_ID = output['response']['user_id']
    print(USER_ID)
    print('-'*80)
    print('User ID created is = '+USER_ID)
    print('-'*80)
    
    return USER_ID

def createDuoPhone ():
    # Create the Phone and set the PHONE_ID which will be used in the Associate section
    url_PHONE = "https://{}{}".format(API_HOSTNAME, API_PATH_PHONE)
    payload = PARAMS_PHONE
    pprint.pprint(payload)
    request_headers = sign(METHOD_POST,API_HOSTNAME,API_PATH_PHONE,PARAMS_PHONE,S_KEY,I_KEY)
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    print(request_headers)
    phone = requests.request(METHOD, url_PHONE, data=payload, headers=request_headers, verify=False)
    if (phone.status_code != 200):
        print(f'An error has ocurred creating the Phone with the following code {phone.status_code}!')
        sys.exit(0)
    output = json.loads(phone.content)
    pprint.pprint(output)
    PHONE_ID = output['response']['phone_id']
    print('-'*80)
    print('Phone ID is = '+PHONE_ID)
    print('-'*80)
    
    return PHONE_ID


def associateUserToPhone():    
    # Take the USER_ID and the PHONE_ID and Associate them
    PARAMS_ASSOCIATE = {
          'phone_id': PHONE_ID
          }
    API_PATH_ASSOCIATE = '/admin/v1/users/{}/phones'.format(USER_ID)
    print(API_PATH_ASSOCIATE)
    url_ASSOCIATE = "https://{}{}".format(API_HOSTNAME, API_PATH_ASSOCIATE)
    payload = PARAMS_ASSOCIATE
    request_headers = sign(METHOD_POST,API_HOSTNAME,API_PATH_ASSOCIATE,PARAMS_ASSOCIATE,S_KEY,I_KEY)
    request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
    association = requests.request(METHOD, url_ASSOCIATE, data=payload, headers=request_headers, verify=False)
    if (association.status_code != 200):
        print(f'An error has ocurred associating the User with the Phone the following code {association.status_code}!' )
        sys.exit(0)
    output = json.loads(association.content)
    pprint.pprint(output)
    print('-'*80)
    print(f'The Phone {PHONE_ID} is associated with the User{USER_ID}')
    print('-'*80)
   
def createUmbrellaUser():
    # Create a New Device in Umbrella for the new user

    API_PATH_U_USER = '{}/users'.format(U_ORG_ID)
    url_U_USER = '{}{}'.format(U_API_HOSTNAME, API_PATH_U_USER)
    print(url_U_USER)
    payload = PARAMS_U_USER
    u_user = requests.post(url_U_USER, data=payload,  auth = (U_API_KEY, U_API_SECRET))
    if (u_user.status_code != 200):
        print(f'An error has ocurred associating the User with the Phone the following code {u_user.status_code}!' )
        sys.exit(0)
    output = json.loads(u_user.content)
    U_USER_ID = output['id']
    pprint.pprint(output)
    print('*'*80)
    print(f'The Device with ID {U_USER_ID} has been added to Umbrella with Read Access')
    print('*'*80)

if __name__ == "__main__":
    
    USER_ID = createDuoUser()
    print()
    print()
    PHONE_ID = createDuoPhone()
    print()
    print()
    associateUserToPhone()
    print()
    print()
    createUmbrellaUser()
    

    


