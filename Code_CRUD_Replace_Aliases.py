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
        login_url = f"https://{self.host}/index.php"
        response = self.session.get(login_url, auth=(self.username, self.password))
        if response.status_code == 200:
            return True
        else:
            return False
        
    def get_aliases(self, alias_id):
        if alias_id:
            url = f"https://{self.host}/api/v2/firewall/alias/?id={alias_id}"
        else:
            url = f"https://{self.host}/api/v2/firewall/aliases" 
        response = self.session.get(url, auth=(self.username, self.password))
        if response.status_code == 200:
            aliases = response.json()
            return aliases
        else:
            return None
    
    def create_alias(self):
        url = f"https://{self.host}/api/v2/firewall/alias"
        data = {
            "name": "Demo1",
            "descr": "test test",
            "type": "host",
            "address": [
                "1.1.1.1"
            ],
            "detail": [
                "trytest"
            ]
        }
        response = self.session.post(url, json=data, auth=(self.username, self.password))
        return response.status_code == 200

    def update_alias(self):
        url = f"https://{self.host}/api/v2/firewall/alias"
        data = {
            "id": "1",
            "name": "test",
            "descr": "oke",
            "type": "port",
            "address": [
                "4466"
            ],
            "detail": [
                "trytestport"
            ]
        }
        response = self.session.patch(url, json=data, auth=(self.username, self.password))
        return response.status_code == 200

    def delete_alias(self, alias_id):
        if alias_id:
            url = f"https://{self.host}/api/v2/firewall/alias/?id={alias_id}"
        else: 
            #WARNING: This will delete all objects that match the query, use with caution.
            url = f"https://{self.host}/api/v2/firewall/aliases"
        response = self.session.delete(url, auth=(self.username, self.password))
        return response.status_code == 200
    
    def replace_aliases(self):
        url = f"https://{self.host}/api/v2/firewall/aliases"
        print("1", url)
        data = [{
            "id": "1",
            "name": "test",
            "descr": "oke",
            "type": "port",
            "address": [
                "4466"
            ],
            "detail": [
                "trytestport"
            ]
        }]
        response = self.session.put(url, json=data, auth=(self.username, self.password))
        return response.status_code == 200

if __name__ == "__main__":
    HOST = ""
    USERNAME = ""
    PASSWORD = ""
    pfsense = PfSense(HOST, USERNAME, PASSWORD)

    if pfsense.login():
        print("Login successful")
        alias_id = input("Enter the alias ID to read: ")
        aliases = pfsense.get_aliases(alias_id)
        if aliases:
            print(json.dumps(aliases, indent=4))
        else:
            print(f"Failed to read alias with ID {alias_id}.")
        if pfsense.create_alias():
            print("alias created successfully.")
        else:
            print("Failed to create alias")
        if pfsense.update_alias():
            print(f"Alias updated successfully.")
        else:
            print(f"Failed to update alias.")
        alias_id = input("Enter the alias ID to delete: ")
        if pfsense.delete_alias(alias_id):
            print(f"Rule with ID {alias_id} deleted successfully.")
        else:
            print(f"Failed to delete rule with ID {alias_id}.")
        if pfsense.replace_aliases():
            print("aliases replaced successfully.")
        else:
            print("Failed to replace alias")
    else:
        print("Failed login")
