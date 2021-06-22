import requests

amp_client_id = 'c1347986e0c179dced14'

amp_api_key = '59275b5b-29ce-42ef-9d34-f41b6e3708b7'

# EXAMPLE:
# computer_guid = 'd7fbcdb6-0a14-4e39-867e-02f5e1649497'
computer_guid = '6f71f950-ea26-413f-a629-1ddb1c0833ed'

url = 'https://api.amp.cisco.com/v1/computers/{}/isolation'.format(computer_guid)

response = requests.get(url, auth=(amp_client_id, amp_api_key))

print(response.json())