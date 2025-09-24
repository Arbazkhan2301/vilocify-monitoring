import requests
import pandas as pd
import json
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

API_BASE_URL = "https://svm.cert.siemens.com/portal/api/v1/"
CLIENT_CERT = "C:/Users/z0051rra/OneDrive - Innomotics/OpenSSL-Win64/bin/certificate.pem"
CLIENT_KEY = "C:/Users/z0051rra/OneDrive - Innomotics/OpenSSL-Win64/bin/pri-key.pem"
CLIENT_KEY_PASSPHRASE = "arbazkhan123456789$@"
CA_BUNDLE = "C:/Users/z0051rra/OneDrive - Innomotics/OpenSSL-Win64/bin/ca-bundle.pem"

# === SSL Adapter with passphrase ===
class SSLAdapterWithPassphrase(HTTPAdapter):
    def __init__(self, certfile, keyfile, password, ca_bundle, **kwargs):
        self.certfile = certfile
        self.keyfile = keyfile
        self.password = password
        self.ca_bundle = ca_bundle
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile, password=self.password)
        context.load_verify_locations(self.ca_bundle)
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# === Create session ===
session = requests.Session()
adapter = SSLAdapterWithPassphrase(
    certfile=CLIENT_CERT,
    keyfile=CLIENT_KEY,
    password=CLIENT_KEY_PASSPHRASE,
    ca_bundle=CA_BUNDLE
)
session.mount('https://', adapter)

# === Functions ===

def get_monitoring_list_ids():
    url = urljoin(API_BASE_URL, "common/monitoring_lists")
    response = session.get(url)
    response.raise_for_status()
    return response.json()

def get_monitoring_list_details(list_id):
    url = urljoin(API_BASE_URL, f"common/monitoring_lists/{list_id}")
    response = session.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Warning: Could not fetch details for ID {list_id}")
        return None

def export_to_excel(data, filename="monitoring_lists.xlsx"):
    df = pd.DataFrame(data)
    df.to_excel(filename, index=False)
    print(f"Exported {len(data)} records to {filename}")

def export_to_json(data, filename="monitoring_lists.json"):
    with open(filename, 'w', encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"Exported {len(data)} records to {filename}")

def main():
    ids = get_monitoring_list_ids()
    all_details = []
    for list_id in ids:
        details = get_monitoring_list_details(list_id)
        if details:
            if 'id' not in details:
                details['id'] = list_id
            all_details.append(details)

    if all_details:
        export_to_excel(all_details)
        export_to_json(all_details)
    else:
        print("No data to export.")

if __name__ == "__main__":
    main()

