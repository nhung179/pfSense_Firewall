register_module_line('pfSense_Firewall', 'start', __line__())

import requests
import json
from functools import wraps
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def handle_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            demisto.error(f"Error in {func.__name__}: {e}")
            return None
    return wrapper

class PfSense:
    def __init__(self, host, username, password, port):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.session = requests.Session()
        self.session.verify = False

    def http_request(self, method, path, data=None):
        url = f"https://{self.host}:{self.port}{path}"
        response = self.session.request(method=method, url=url, json=data, auth=(self.username, self.password))
        return response if response.status_code == 200 else None

    @handle_errors
    def login(self):
        return "Success" if self.http_request('GET', '/index.php') else "Failed"

    @handle_errors
    def get_rules(self, rule_id):
        path = f"/api/v2/firewall/rule/?id={rule_id}" if alias_id else "/api/v2/firewall/rules"
        response = self.http_request('GET', path)
        return response.json() if response else None

    @handle_errors
    def create_rule(self, data_rule):
        response = self.http_request('POST', '/api/v2/firewall/rule', data=data_rule)
        return response.json() if response else None

    @handle_errors
    def update_rule(self, data_rule):
        return bool(self.http_request('PATCH', '/api/v2/firewall/rule', data=data_rule))

    @handle_errors
    def delete_rules(self, rule_id):
        path = f"/api/v2/firewall/rule/?id={rule_id}" if rule_id else "/api/v2/firewall/rules"
        return bool(self.http_request('DELETE', path))

    @handle_errors
    def replace_rules(self, data_rule):
        return bool(self.http_request('PUT', '/api/v2/firewall/rules', data=data_rule))

    @handle_errors
    def get_aliases(self, alias_id):
        path = f"/api/v2/firewall/alias/?id={alias_id}" if alias_id else "/api/v2/firewall/aliases"
        response = self.http_request('GET', path)
        return response.json() if response else None

    @handle_errors
    def create_alias(self, data_alias):
        response = self.http_request('POST', '/api/v2/firewall/alias', data=data_alias)
        return response.json() if response else None

    @handle_errors
    def update_alias(self, data_alias):
        return bool(self.http_request('PATCH', '/api/v2/firewall/alias', data=data_alias))

    @handle_errors
    def delete_aliases(self, alias_id):
        path = f"/api/v2/firewall/alias/?id={alias_id}" if alias_id else "/api/v2/firewall/aliases"
        return bool(self.http_request('DELETE', path))

    @handle_errors
    def replace_aliases(self, data_alias):
        return bool(self.http_request('PUT', '/api/v2/firewall/aliases', data=data_alias))

    @handle_errors
    def get_apply(self):
        response = self.http_request('GET', "/api/v2/firewall/apply")
        return response.json() if response else None

    @handle_errors
    def create_apply(self):
        data_apply = {}
        response = self.http_request('POST', '/api/v2/firewall/apply', data=data_apply)
        return response.json() if response else None

    def input_data(self, args, is_rule=True):
        if is_rule:
            fields = ["id", "type", "ipprotocol", "protocol", "source", "source_port", "destination", "destination_port", "descr", "statetype", "direction"]
            list_fields = ["interface", "icmptype", "tcp_flags_out_of", "tcp_flags_set"]
        else:
            fields = ["id", "name", "type"]
            list_fields = ["address", "detail"]

        data = {field: args.get(field) for field in fields}
        data.update({field: [args.get(field)] for field in list_fields})
        return data

def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    rule_id = args.get('rule_id')
    alias_id = args.get('alias_id')
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
        elif command == 'pfsense-get-rules':
            return_results(pfsense.get_rules(rule_id))
        elif command == 'pfsense-create-rule':
            data_rule = pfsense.input_data(args, is_rule=True)
            return_results(pfsense.create_rule(data_rule))
        elif command == 'pfsense-update-rule':
            data_rule = pfsense.input_data(args, is_rule=True)
            return_results(pfsense.update_rule(data_rule))
        elif command == 'pfsense-delete-rules':
            return_results(pfsense.delete_rules(rule_id))
        elif command == 'pfsense-replace-rules':
            data_rule = pfsense.input_data(args, is_rule=True)
            return_results(pfsense.replace_rules(data_rule))
        elif command == 'pfsense-get-aliases':
            return_results(pfsense.get_aliases(alias_id))
        elif command == 'pfsense-create-alias':
            data_alias = pfsense.input_data(args, is_rule=False)
            return_results(pfsense.create_alias(data_alias))
        elif command == 'pfsense-update-alias':
            data_alias = pfsense.input_data(args, is_rule=False)
            return_results(pfsense.update_alias(data_alias))
        elif command == 'pfsense-delete-aliases':
            return_results(pfsense.delete_aliases(alias_id))
        elif command == 'pfsense-replace-aliases':
            data_alias = pfsense.input_data(args, is_rule=False)
            return_results(pfsense.replace_aliases(data_alias))
        elif command == 'pfsense-get-apply':
            return_results(pfsense.get_apply())
        elif command == 'pfsense-create-apply':
            return_results(pfsense.create_apply())


    except Exception as e:
        raise Exception(f'Error connecting to pfSense: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('pfSense_Firewall ', 'end', __line__())
