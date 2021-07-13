import requests
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
url = "https://172.16.62.102:8443/dataservice/template/device/feature"

payload = json.dumps({
  "templateName": "Test_Template",
  "templateDescription": "Test Template",
  "deviceType": "vedge-CSR-1000v",
  "configType": "template",
  "factoryDefault": "false",
  "policyId": "",
  "featureTemplateUidRange": [],
  "generalTemplates": [
    {
      "templateId": "02e3cf1e-d826-4152-afc6-f681f1026247",
      "templateType": "cedge_aaa"
    },
    {
      "templateId": "c4b60893-91ee-4341-807e-9889114edeb0",
      "templateType": "cisco_system"
    },
    {
      "templateId": "9f516c0a-ecc8-45ac-8f6c-1b7349112229",
      "templateType": "cisco_omp"
    },
    {
      "templateId": "cf144d5e-0829-4cab-a5b2-097ade0ba363",
      "templateType": "cisco_vpn",
      "subTemplates": [
        {
          "templateId": "1ec6dc94-b46d-466f-aa42-c224e06fe112",
          "templateType": "cisco_vpn_interface"
        },
        {
          "templateId": "a84fc720-d9f8-4746-8226-0fbce526ae69",
          "templateType": "cisco_vpn_interface"
        }
      ]
    },
    {
      "templateId": "8535dd50-9b77-4b2d-8b36-435127f43a19",
      "templateType": "cisco_vpn",
      "subTemplates": [
        {
          "templateId": "d3de90df-3005-4a8e-ac90-8927a6c1c3ef",
          "templateType": "cisco_vpn_interface"
        }
      ]
    },
    {
      "templateId": "e4b1b450-4999-4405-b2d1-9b149cb9441b",
      "templateType": "cisco_vpn",
      "subTemplates": [
        {
          "templateId": "ed600ed2-3a92-4804-bb00-67ae21c3aa07",
          "templateType": "cisco_ospf"
        },
        {
          "templateId": "831c9cb1-62d6-4e26-b537-e99355f24fed",
          "templateType": "cisco_vpn_interface"
        },
        {
          "templateId": "fb6f0489-87e3-4eef-8297-d577a7a3c1d5",
          "templateType": "cisco_vpn_interface"
        }
      ]
    },
    {
      "templateId": "a120167b-c700-405e-8c15-8b75b31d57c4",
      "templateType": "cisco_sig_credentials"
    },
    {
      "templateId": "356babbf-9574-4236-8112-b7f937dd7184",
      "templateType": "cisco_banner"
    }
  ]
})
headers = {
  'X-XSRF-TOKEN': 'C39E7B505A33A8A7585A99B81F7CB4D23A423363727B45874D548E406B4C82376519569953F6E7455AB20700295913E3C238',
  'Content-Type': 'application/json',
  'Cookie': 'JSESSIONID=ypJCPYdTtbV6spZ_b-o_rIicj4fFmULkLuQzxZYB.2e8de25e-f269-4976-b792-65b2ccbc2ce9'
}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
