#check pull request
#Code Chưa Tối Ưu => Code Đã Tối Ưu Ở Bên Dưới 

register_module_line('pfSense_Firewall', 'start', __line__())

import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PfSense:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False

    def login(self):
        url = f"https://{self.host}:9080/index.php"
        response = self.session.request(method='GET', url=url, auth=(self.username, self.password))
        if response.status_code == 200:
            return "Success"
        else:
            return "Failed"

    def read_rules(self):
        url = f"https://{self.host}:9080/api/v2/firewall/rules"
        response = self.session.request(method='GET', url=url, auth=(self.username, self.password))
        print(response)
        if response.status_code == 200:
            rules = response.json()
            return rules
        else:
            return None

    def create_rule(self, data):
        url = f"https://{self.host}:9080/api/v2/firewall/rule"
        response = self.session.request(method='POST', url=url, json=data, auth=(self.username, self.password))
        print(response.status_code)
        print(response.text)
        if response.status_code == 200:
            rules = response.json()
            return rules
        else:
            return None

    def update_rule(self, data):
        url = f"https://{self.host}:9080/api/v2/firewall/rule"
        response = self.session.request(method='PATCH', url=url, json=data, auth=(self.username, self.password))
        print(response.status_code)
        if response.status_code == 200:
            return True
        else:
            return False

    def delete_rule(self, rule_id):
        url = f"https://{self.host}:9080/api/v2/firewall/rule/?id={rule_id}"
        response = self.session.request(method='DELETE', url=url, auth=(self.username, self.password))
        print(response)
        if response.status_code == 200:
            return True
        else:
            print(f"Failed to delete rule with ID {rule_id}. Error code: {response.status_code}")
            return False

    def replace_rules(self, data):
        url = f"https://{self.host}:9080/api/v2/firewall/rules"
        response = self.session.request(method='PUT', url=url, json=data, auth=(self.username, self.password))
        print(response.status_code)
        print(response.text)
        if response.status_code == 200:
            return True
        else:
            return False


    # Define input data
    def input_data(self, args):
        id_input = args.get("id")
        type_input = args.get("type")
        ipprotocol_input = args.get("ipprotocol")
        protocol_input = args.get("protocol")
        source_input = args.get("source")
        source_port_input = args.get("source_port")
        destination_input = args.get("destination")
        destination_port_input = args.get("destination_port")
        descr_input = args.get("descr")
        statetype_input = args.get("statetype")
        direction_input = args.get("direction")

        interface_input=[]
        interface_input.append(args.get("interface"))
        icmptype_input = []
        icmptype_input.append(args.get("icmptype"))
        tcp_flags_out_of_input=[]
        tcp_flags_out_of_input.append(args.get("tcp_flags_out_of"))
        tcp_flags_set_input=[]
        tcp_flags_set_input.append(args.get("tcp_flags_set"))

        data_input = {
            "id": id_input,
            "type": type_input,
            "interface": interface_input,
            "ipprotocol": ipprotocol_input,
            "protocol": protocol_input,
            "icmptype": icmptype_input,
            "source": source_input,
            "source_port": source_port_input,
            "destination": destination_input,
            "destination_port": destination_port_input,
            "descr":  descr_input,
            "statetype": statetype_input,
            "tcp_flags_out_of": tcp_flags_out_of_input,
            "tcp_flags_set": tcp_flags_set_input,
            "direction": direction_input
        }
        return data_input

def main():
    args = demisto.args()
    params = demisto.params()
    command = demisto.command()

    host = params.get('host')
    username = params.get('username')
    password = params.get('password')
    rule_id = args.get('rule_id')

    try:
        pfsense = PfSense(host, username, password)
        if command == 'test-module':
            result = pfsense.login()
            if result == "Success":
                return_results('ok')
        elif command == 'read-rules':
            result = pfsense.read_rules()
            return_results(result)
        elif command == 'create-rule':
            data = pfsense.input_data(args)
            result = pfsense.create_rule(data)
            return_results(result)
        elif command == 'update-rule':
            data = pfsense.input_data(args)
            result = pfsense.update_rule(data)
            return_results(result)
        elif command == 'delete-rule':
            result = pfsense.delete_rule(rule_id)
            return_results(result)
        elif command == 'replace-rules':
            data = [pfsense.input_data(args)]
            result = pfsense.replace_rules(data)
            return_results(result)
    except Exception as e:
        raise Exception(f'Error connecting to pfSense: {str(e)}')

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('pfSense_Firewall ', 'end', __line__())

------------------
#Code Tối Ưu hơn 

register_module_line('pfSense_Firewall', 'start', __line__())

import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PfSense:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False

    def http_request(self, method, endpoint, data=None, params=None):
        url = f"https://{self.host}:9080{endpoint}"
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
    pfsense = PfSense(params.get('host'), params.get('username'), params.get('password'))

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
