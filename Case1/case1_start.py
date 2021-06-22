import json, base64, email, hmac, hashlib, urllib3, urllib
import requests
import pprint
import config
import sys
import webex_teams_apis
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth
from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
