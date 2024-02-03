import requests
import logging
import ipaddress
import json

virustotal_api_key = 'eef0acf1ca2d3afc9c2f520799de25b3304f6dc5fb5d013bcfdd775b0666f60f'

def query_virustotal_ip(query_value, virustotal_api_key):
    url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': virustotal_api_key, 'ip': query_value}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        result = response.json()
        return {'ip_results': result}

    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal API for IP: {e}")
        return {'error': True, 'message': f'Error querying VirusTotal API for IP: {e}', 'response': response.text}


def query_virustotal_hash(query_value, virustotal_api_key):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': virustotal_api_key, 'resource': query_value}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        result = response.json()
        return {'hash_results': result}

    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal API for Hash: {e}")
        return {'error': True, 'message': f'Error querying VirusTotal API for Hash: {e}', 'response': response.text}



def query_virustotal(query_value=None, query_type=None, virustotal_api_key=None):
    if query_type == 'ip':
        return query_virustotal_ip(query_value, virustotal_api_key)
    elif query_type == 'hash':
        return query_virustotal_hash(query_value, virustotal_api_key)
    else:
        logging.warning("Invalid query type. Please provide either 'ip' or 'hash'.")
        return {'error': True, 'message': 'Invalid query type'}

def generate_incident_report(ip_results, hash_results, affectedusername, affected_host_ip, threat_actor_ip, hash_value):
    report = "\nIR REPORT\n\n"

    # Affected Host
    report += f"Affected IP: {affected_host_ip}\n"
    report += f"Affected User Name: {affectedusername}\n\n"

    # Threat IP (Sanitize here)
    sanitized_threat_actor_ip = ".".join(threat_actor_ip.split(".")[:-1]) + "[.]" + threat_actor_ip.split(".")[-1]
    report += f"Threat Actor IP: {sanitized_threat_actor_ip}\n"
    report += f"Threat Actor IP Location: {ip_results.get('ip_results', {}).get('country', 'Unknown')}\n\n"

    # Malicious File
    report += f"Malicious File Name: [prompt for file name after hash, if left blank, don't put it on the report]\n"
    report += f"Malicious File Hash: {hash_value}\n\n"

    # Handle IP Results
    ip_results_data = ip_results.get('ip_results', {})

    # Print Detected URLs
    detected_urls = ip_results_data.get('detected_urls', [])
    if detected_urls:
        report += "Detected URLs:\n"
        for url_info in detected_urls:
            report += f"URL: {url_info['url']}\n"
            report += f"Scan Date: {url_info['scan_date']}\n"
            report += f"Positives: {url_info['positives']}\n"
            report += f"Total Scans: {url_info['total']}\n\n"
    else:
        report += "No detected URLs.\n"

    # Print other IP Results
    report += f"Country: {ip_results_data.get('country', 'Unknown')}\n"
    report += f"AS Owner: {ip_results_data.get('as_owner', 'Unknown')}\n"
    report += f"Verbose Message: {ip_results_data.get('verbose_msg', 'Unknown')}\n\n"

    # Handle Hash Results
    if 'hash_results' in hash_results:
        hash_results_data = hash_results['hash_results']

        # Print Hash Results
        report += "Hash Results:\n"
        for key, value in hash_results_data.items():
            report += f"{key}: {value}\n"

        positives = hash_results_data.get('positives', 0)
        report += f"The file associated with this incident is flagged as malicious by {positives} security vendors.\n\n"
    else:
        report += "No results for Malicious File.\n"

    report += f"We recommend that IP {sanitized_threat_actor_ip} is blocked from communicating with your environment. "
    report += f"Furthermore, we recommend that the affected host is quarantined from the network, and deploy an anti-virus to remove the file. (add relevant recommendations)\n"

    return report


def incident_response_workflow():
    affectedusername = input("Affected User Name: ")
    affected_host_ip = input("Affected Host IP: ")
    threat_actor_ip = input("Threat Actor IP: ")
    hash_value = input("Hash Value: ")

    # Query VirusTotal for IP and hash if provided
    ip_results = query_virustotal_ip(threat_actor_ip, virustotal_api_key) if threat_actor_ip else {}
    hash_results = query_virustotal_hash(hash_value, virustotal_api_key) if hash_value else {}

    # Customize the incident report based on your needs
    incident_report = generate_incident_report(
        ip_results.get('ip_results', {}),
        hash_results.get('hash_results', {}),
        affectedusername, affected_host_ip, threat_actor_ip, hash_value
    )

    print(incident_report)

    # Convert results to JSON format
    ip_results_json = json.dumps(ip_results, indent=2)
    hash_results_json = json.dumps(hash_results, indent=2)

    # You can print or store these JSON strings as needed
    print("IP Results (JSON format):\n", ip_results_json)
    print("\nHash Results (JSON format):\n", hash_results_json)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Set the desired logging level
    incident_response_workflow()