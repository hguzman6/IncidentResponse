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

    # Extract Threat IP Location
    country = ip_results.get('data', {}).get('attributes', {}).get('country', 'Unknown')
    city = ip_results.get('data', {}).get('attributes', {}).get('city', 'Unknown')
    report += f"Threat Actor IP Location: {country}, {city}\n\n"

    # Detected URLs
    detected_urls = ip_results.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
    if detected_urls:
        report += "Detected URLs:\n"
        for url, info in detected_urls.items():
            report += f"  URL: {url}\n"
            report += f"  Scan Date: {info.get('last_analysis_date')}\n"
            report += f"  Positives: {info.get('malicious')}\n"
            report += f"  Total Scans: {info.get('total')}\n\n"
    else:
        report += "No detected URLs.\n"

    # Other Threat IP Details
    report += f"AS Owner: {ip_results.get('data', {}).get('attributes', {}).get('as_owner', 'Unknown')}\n"
    report += f"ASN: {ip_results.get('data', {}).get('attributes', {}).get('asn', 'Unknown')}\n"
    report += f"Verbose Message: {ip_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('verbose_msg', 'Unknown')}\n\n"

    # Malicious File Name and Hash
    malicious_file_name = input('Malicious File Name (press Enter to skip): ')
    report += f"Malicious File Name: {malicious_file_name or 'Not provided'}\n"
    report += f"Malicious File Hash: {hash_value}\n\n"

    # Hash Results
    positives = hash_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    report += f"The file associated with this incident is flagged as malicious by {positives} security vendors.\n\n"

    return report


def incident_response_workflow():
    affectedusername = input("Affected User Name: ")
    affected_host_ip = input("Affected Host IP: ")
    threat_actor_ip = input("Threat Actor IP: ")
    hash_value = input("Hash Value (provide a valid hash for testing, or press Enter to skip): ")

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

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Set the desired logging level
    incident_response_workflow()