vmanage_host = "172.16.62.102"
vmanage_port = "8443"
vmanage_username = "admin"
vmanage_password = "Cisco123!"

WEBEX_TEAMS_URL = 'https://webexapis.com/v1'
WEBEX_TEAMS_AUTH = 'Bearer ' + 'OTM3ZTMxZjItZGM4ZC00ODA5LWI1ZTYtMDAyMmUzOTNhOTNjMjQxM2IxOWYtYjk5_PF84_e17d4b4d-d1d4-4ebd-8b20-7735538ecf7b' # Enter your token good for 12 hours here
WEBEX_TEAMS_SPACE_NAME = 'Jed SASE Test' # Get the exact name from Webex


template_name = 'PodXX_banner_cEdge_1k'
template_description = 'Banner for PodXX'
login_banner = 'Hello PodXX'
motd_banner = 'Have a good day PodXX'
device_type = 'vedge-CSR-1000v'

YAML_FILE = """
template_name: 'PodXX_banner_cEdge_1k'
template_description: 'Banner for PodXX'
login_banner: 'Hello PodXX'
motd_banner: 'Have a good day PodXX'
device_type: 'vedge-CSR-1000v
"""