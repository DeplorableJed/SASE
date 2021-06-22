import sys
import requests
import json
from datetime import datetime
import config

API_KEY = config.UMBRELLA_REPORT_API_KEY
API_SECRET = config.UMBRELLA_REPORT_API_SECRET
ORG_ID = config.UMBRELLA_ORG_ID

def getMostRecentRequests():
	url = 'https://reports.api.umbrella.com/v1/organizations/'+ ORG_ID + '/destinations/internetbadguys.com/activity'
	
	# do GET request for the domain status and category
	req = requests.get(url, auth = (API_KEY, API_SECRET))
	
	# error handling if true then the request was HTTP 200, so successful
	if (req.status_code != 200):
		print('An error has occured with the following code %s' % req.status_code)
		sys.exit(0)
	
	output = req.json()
	print (output)
	

	print('{:^30}{:^20}{:^15}{:^20}{:^25}{:^10}'.format(
		'Date Time',
		'Origin Type',
		'Origin Label',
		'External IP',
		'Destination',
		'Action'
	))
	
	
	for item in output['requests']:
		origin_type = item['originType']
		external_ip = item['externalIp']
		destination = item['destination']
		origin_label = item['originLabel']
		action_taken = item['actionTaken']
		datetime = item['datetime']
		
		print('{:^30}{:^20}{:^15}{:^20}{:^25}{:^10}'.format(
			datetime,
			origin_type,
			origin_label,
			external_ip,
			destination,
			action_taken
		))
		
def main():
	# print the menu
	print('''
				Umbrella - Retrieve Destinations: Most recent requests report
							SRW Blitz Lab
				''')
				
	getMostRecentRequests()
	
if __name__ == '__main__':
	main()