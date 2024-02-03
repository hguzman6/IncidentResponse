import requests
import logging
import ipaddress
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve VirusTotal API key from environment variables
virustotal_api_key = os.getenv("virustotal_api_key")

if not virustotal_api_key:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable not set.")


# Function to query VirusTotal for IP information
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

# Function to query VirusTotal for file hash information
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

# Function to choose the appropriate query function based on the type (IP or hash)
def query_virustotal(query_value=None, query_type=None, virustotal_api_key=None):
    if query_type == 'ip':
        return query_virustotal_ip(query_value, virustotal_api_key)
    elif query_type == 'hash':
        return query_virustotal_hash(query_value, virustotal_api_key)
    else:
        logging.warning("Invalid query type. Please provide either 'ip' or 'hash'.")
        return {'error': True, 'message': 'Invalid query type'}

# Function to generate an incident response report
def generate_incident_report(affected_user, affected_host_ip, sanitized_threat_actor_ip, hash_value, vt_ip_results, vt_hash_results, affected_hostname):
    
# Extract relevant IP information
    ip_location = vt_ip_results.get('ip_results', {}).get('country', 'Unknown')
    associated_owner = vt_ip_results.get('ip_results', {}).get('as_owner', 'Unknown')
    positive_ip_hits = vt_ip_results.get('ip_results', {}).get('detected_urls', [{}])[0].get('positives', 0)
    total_ip_hits = vt_ip_results.get('ip_results', {}).get('detected_urls', [{}])[0].get('total', 0)
    asn = vt_ip_results.get('ip_results', {}).get('asn', 'Unknown')
    detected_urls = vt_ip_results.get('ip_results', {}).get('detected_urls', [])
    verbose_message = vt_ip_results.get('ip_results', {}).get('verbose_msg', 'Unknown')

# Sanitize the URLs for display
    sanitized_urls = [url.get('url', 'Unknown').rsplit('.', 1)[0] + '[.]' + url.get('url', 'Unknown').rsplit('.', 1)[1] if '.' in url.get('url', 'Unknown') else url.get('url', 'Unknown') for url in detected_urls]

# Extract relevant file hash information
    
    file_name = vt_hash_results.get('hash_results', {}).get('file_name', 'Not provided')
    detection_date = vt_hash_results.get('hash_results', {}).get('scan_date', 'Unknown')
    positive_hash_hits = vt_hash_results.get('hash_results', {}).get('positives', 0)
    total_hash_hits = vt_hash_results.get('hash_results', {}).get ('total', 0)

    report = "\nIncident Response (IR) Report\n\n"
    
    # Affected User
    report += f"    Victim Information:\n"
    report += f"        User Name: {affected_user}\n"
    report += f"        User IP: {affected_host_ip}\n"
    report += f"        Host Name: {affected_hostname}\n\n"

    # Threat Actor Details
    report += "     Security Incident Details\n"
    report += f"        Threat Actor Details:\n"
    report += f"            Malicious IP: {sanitized_threat_actor_ip}\n"    
    report += f"            Malicious IP Location: {ip_location}\n"
    report += f"            Associated Owner: {associated_owner}\n"
    report += f"            ASN (Autonomous System Number): {asn}\n"
    report += f"            Detected/Associated URLs: {', '.join(sanitized_urls)}\n\n"

    report += f"        Threat credibility:\n"
    report += f"            The OSINT investigation found that {positive_ip_hits} out of {total_ip_hits}\n"
    report += f"            security vendors flag this IP/URL as malicious.\n"
    report += f"            VirusTotal Message: {verbose_message}\n\n"

    # Malicious File Details
    report += f"        Malicious File Details:\n"
    report += f"            Malicious File Hash: {hash_value}\n"
    report += f"            Malicious File Name: {file_name}\n"
    report += f"            Malicious File Detection Date: {detection_date}\n"
    report += f"            Total Positive Malicious Hits: {positive_hash_hits} out of {total_hash_hits}\n\n"
    

    # Remediation Actions
    report += "     Remediation Actions:\n"
    report += f"        Isolate the following affected system\n"
    report += f"            User Name:{affected_user}\n"
    report += f"            Host IP:{affected_host_ip}\n"
    report += f"            Host Name:{affected_hostname}\n\n"
  

    report += f"        Block traffic to/from:\n"
    report += f"            Malicious IP:{sanitized_threat_actor_ip}\n\n"

    report += f"        Conduct a thorough investigation to identify and remove any traces of the malicious file.\n\n"

    report += f"        Strengthen overall security measures, including endpoint protection and network monitoring.\n\n"

    report += f"        Regularly update antivirus signatures and security patches.\n\n"


    ### full JSON IP REPORT: 
    ### report += f"    Full IP Results JSON: {vt_ip_results}\n"
    ### report += f"    Full IP Results JSON: {vt_hash_results}\n"


    return report

# Function to guide the incident response workflow

def incident_response_workflow():
    affected_user = input("Affected User Name: ")
    affected_hostname = input("Affected Hostname: ")
    affected_host_ip = input("Affected Host IP: ")
    threat_actor_ip = input("Threat Actor IP: ")
    hash_value = input("Hash Value (provide a valid hash for testing, or press Enter to skip): ")

    # Query VirusTotal for IP and hash if provided
    ip_results = query_virustotal_ip(threat_actor_ip, virustotal_api_key) if threat_actor_ip else {}
    hash_results = query_virustotal_hash(hash_value, virustotal_api_key) if hash_value else {}

    sanitized_threat_actor_ip = ".".join(threat_actor_ip.split(".")[:-1]) + "[.]" + threat_actor_ip.split(".")[-1]
    
    # Generate incident report
    incident_report = generate_incident_report(
        affected_user, affected_host_ip, sanitized_threat_actor_ip, hash_value, ip_results, hash_results, affected_hostname, 
    )

    print(incident_report)

if __name__ == "__main__":
    ### EXPOSES API KEY - USE FOR DEBUGGING/TESTING ONLY ###
            # logging.basicConfig(level=logging.DEBUG)  
    incident_response_workflow()