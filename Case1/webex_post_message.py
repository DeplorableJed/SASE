#!/usr/bin/env python3


# developed by Gabi Zapodeanu, TSA, GPO, Cisco Systems


# import Python packages


import urllib3
import requests
import json
import sys
#sys.path.append('..')

# import functions modules

import webex_teams_apis


from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth


from config import WEBEX_TEAMS_URL, WEBEX_TEAMS_AUTH

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings


def main():

    # post message to the new space
    webex_teams_apis.post_space_message('Class Space SRW', 'test message')
    input('Check the space for the new message posted, hit any key to continue ')


if __name__ == '__main__':
    main()
