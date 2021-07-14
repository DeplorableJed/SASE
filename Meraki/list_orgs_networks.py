import csv
from datetime import datetime
import os
from pprint import pprint
import tabulate
import meraki
import json

# Either input your API key below by uncommenting line 10 and changing line 16 to api_key=API_KEY,
# or set an environment variable (preferred) to define your API key. The former is insecure and not recommended.
# For example, in Linux/macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
#API_KEY = 'd0e472060dd5e6049567d94b042d7aba77be7db3'


def main():
    # Instantiate a Meraki dashboard API session
    dashboard = meraki.DashboardAPI(
        api_key='d0e472060dd5e6049567d94b042d7aba77be7db3',
        base_url='https://api.meraki.com/api/v1/',
        output_log=True,
        log_file_prefix=os.path.basename(__file__)[:-3],
        log_path='',
        print_console=False
    )

    # Get list of organizations to which API key has access
    organizations = dashboard.organizations.getOrganizations()

    # Iterate through list of orgs
    for org in organizations:
        print()
        print('#'*80)
        print(f'\nAnalyzing the organization with a name {org["name"]}:')
        print()
        print('#'*80)
        org_id = org['id']
        print('*'*80)
        print("Found an organization with an id of :"+org_id+" with the following networks")
        print()
        print('*'*80)

        # Get list of networks in organization
        try:
            networks = dashboard.organizations.getOrganizationNetworks(org_id)
            headers = ["Network Name", "ID", "Tags"]
            table = list()

            for net in networks:
                tr = [net.get('name'), net.get('organizationId'), net.get('tags')]
                table.append(tr)
            try:
                
                print(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
            except UnicodeEncodeError:
                print(tabulate.tabulate(table, headers, tablefmt="grid"))

        except meraki.APIError as e:
            print(f'Meraki API error: {e}')
            print(f'status code = {e.status}')
            print(f'reason = {e.reason}')
            print(f'error = {e.message}')
            continue
        except Exception as e:
            print(f'some other error: {e}')
            continue
        
  


if __name__ == '__main__':
    start_time = datetime.now()
    main()
    end_time = datetime.now()
    print(f'\nScript complete, total runtime {end_time - start_time}')
