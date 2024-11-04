register_module_line('pfSense_Firewall', 'start', __line__())

import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PfSense:
    def __init__(self, host, username, password, port):
        self.host = host
        self.username = username
        self.password = password
        self.port = port 
        self.session = requests.Session()
        self.session.verify = False

    def http_request(self, method, path, data=None, params=None):
        url = f"https://{self.host}:{self.port}{path}"
        response = self.session.request(method=method, url=url, json=data, params=params, auth=(self.username, self.password))
        return response if response.status_code == 200 else None

    def login(self):
        return "Success" if self.http_request('GET', '/index.php') else "Failed"

    def read_rules(self):
        response = self.http_request('GET', '/api/v2/firewall/rules')
        return response.json() if response else None

    def create_rule(self, data):
        response = self.http_request('POST', '/api/v2/firewall/rule', data=data)
        return response.json() if response else None

    def update_rule(self, data):
        return bool(self.http_request('PATCH', '/api/v2/firewall/rule', data=data))

    def delete_rule(self, rule_id):
        return bool(self.http_request('DELETE', f'/api/v2/firewall/rule/', params={'id': rule_id}))

    def replace_rules(self, data):
        return bool(self.http_request('PUT', '/api/v2/firewall/rules', data=data))

    # Define input data
    def input_data(self, args):
        # Xử lý các trường string
        data_input = {k: args.get(k) for k in [
            "id", "type", "ipprotocol", "protocol", "source", "source_port",
            "destination", "destination_port", "descr", "statetype", "direction"
        ]}
        # Xử lý các trường array
        for field in ["interface", "icmptype", "tcp_flags_out_of", "tcp_flags_set"]:
            data_input[field] = [args.get(field)]
        return data_input

def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    rule_id = args.get('rule_id')
    host = params.get('host')
    username = params.get('username')
    password = params.get('password')
    port = params.get('port')

    pfsense = PfSense(host, username, password, port)

    try:
        if command == 'test-module':
            result = pfsense.login()
            if result == "Success":
                return_results('ok')
        elif command == 'read-rules':
            return_results(pfsense.read_rules())
        elif command == 'create-rule':
            data = pfsense.input_data(args)
            return_results(pfsense.create_rule(data))
        elif command == 'update-rule':
            data = pfsense.input_data(args)
            return_results(pfsense.update_rule(data))
        elif command == 'delete-rule':
            return_results(pfsense.delete_rule(rule_id))
        elif command == 'replace-rules':
            data = [pfsense.input_data(args)]
            return_results(pfsense.replace_rules(data))
    except Exception as e:
        raise Exception(f'Error connecting to pfSense: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('pfSense_Firewall ', 'end', __line__())
