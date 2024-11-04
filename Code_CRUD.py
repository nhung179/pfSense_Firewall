import requests
import json

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class pfSense:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = False

    def login(self):
        login_url = f"https://{self.host}/index.php"
        response = self.session.get(login_url, auth=(self.username, self.password))
        print(response.status_code)
        if response.status_code == 200:
            return True
        else:
            return False

    def get_rules(self):
        get_url = f"https://{self.host}/api/v2/firewall/rules" 
        response = self.session.get(get_url, auth=(self.username, self.password))

        if response.status_code == 200:
            rules = response.json()
            return rules
        else:
            return None
    
    def post_rule(self):
        post_url = f"https://{self.host}/api/v2/firewall/rule"
        rule_data = {
            "id": "",
            "type": "pass",
            "interface": ["lan"],
            "ipprotocol": "inet",
            "protocol": "tcp",
            "icmptype": ["any"],
            "source": "any",
            "source_port": "80",
            "destination": "any",
            "destination_port": "80",
            "descr": "Default allow LAN3 to any rule",
            "disabled": False,
            "log": False,
            "statetype": "keep state",
            "tcp_flags_any": False,
            "tcp_flags_out_of": ["fin"],
            "tcp_flags_set": ["fin"],
            "gateway": None,
            "sched": None,
            "dnpipe": None,
            "pdnpipe": None,
            "defaultqueue": None,
            "ackqueue": None,
            "floating": None,
            "quick": None,
            "direction": "any"
        }
        response = self.session.post(post_url, json=rule_data, auth=(self.username, self.password))
        print(response.status_code)
        print(response.text)

        return response.status_code == 200
           
    def delete_rule(self, rule_id):
        delete_url = f"https://{self.host}/api/v2/firewall/rule/?id={rule_id}"
        response = self.session.delete(delete_url, auth=(self.username, self.password))
        print(response.status_code)
        print(response.text)

        if response.status_code == 200:
            return True
        else:
            print(f"Failed to delete rule with ID {rule_id}. Error code: {response.status_code}")
            print(response.text)
            return False
        
    def patch_rule(self):
        patch_url = f"https://{self.host}/api/v2/firewall/rule"
        rule_data = {
            "id": "4",
            "type": "pass",
            "interface": ["lan"],
            "ipprotocol": "inet",
            "protocol": "tcp",
            "icmptype": ["any"],
            "source": "any",
            "source_port": "443",
            "destination": "any",
            "destination_port": "443",
            "descr": "Updated port ",
            "disabled": False,
            "log": False,
            "statetype": "keep state",
            "tcp_flags_any": False,
            "tcp_flags_out_of": ["fin"],
            "tcp_flags_set": ["fin"],
            "gateway": None,
            "sched": None,
            "dnpipe": None,
            "pdnpipe": None,
            "defaultqueue": None,
            "ackqueue": None,
            "quick": None,
            "direction": "any"
        }
        response = self.session.patch(patch_url, json=rule_data, auth=(self.username, self.password))
        print(response.status_code)
        print(response.text)
        return response.status_code == 200
    
if __name__ == "__main__":
    HOST = "192.168.2.2"
    USERNAME = "admin"
    PASSWORD = "lenhung"

    pfsense = pfSense(HOST, USERNAME, PASSWORD)

    if pfsense.login():
        print("Login successful")
        rules = pfsense.get_rules()
        if rules:
            print(json.dumps(rules, indent=4))

        if pfsense.post_rule():
            print("Rule created successfully.")
        else:
            print("Failed to create rule")
        
        rule_id = input("Enter the rule ID to delete: ")
        if pfsense.delete_rule(rule_id):
            print(f"Rule with ID {rule_id} deleted successfully.")
        else:
            print(f"Failed to delete rule with ID {rule_id}.")

        if pfsense.patch_rule():
            print("Rule updated successfully.")
        else:
            print("Failed to update rule")

    else:
        print("Failed login")

    