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
