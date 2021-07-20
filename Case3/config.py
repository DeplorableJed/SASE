vmanage_host = "172.16.62.102"
vmanage_port = "8443"
vmanage_username = "admin"
vmanage_password = "Cisco123!"

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
