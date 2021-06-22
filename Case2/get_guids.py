import requests

client_id = 'c1347986e0c179dced14'

api_key = '59275b5b-29ce-42ef-9d34-f41b6e3708b7'

url = 'https://api.amp.cisco.com/v1/computers'

response = requests.get(url, auth=(client_id, api_key))

response_json = response.json()
print(response_json)

for computer in response_json['data']:
    connector_guid = computer['connector_guid']
    print(connector_guid)