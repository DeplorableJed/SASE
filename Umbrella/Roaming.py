import requests

url = "https://management.api.umbrella.com/v1/5326453/organizationId/roamingcomputers"

headers = {
    "Accept": "application/json",
    "Authorization": "Basic YTI3MzIyZDI5MThhNGFiYTlmNWFmYTgxMTExMGZmNDE6MjE3NmIwMGIxZTA3NGQ5M2JlODJmM2Q1ZmUyODczNTM="
}

response = requests.request("GET", url, headers=headers)

print(response.text)