import requests
import json
import logging

VIRUSTOTAL_API_KEY = 'eef0acf1ca2d3afc9c2f520799de25b3304f6dc5fb5d013bcfdd775b0666f60f'  # Replace with your VirusTotal API key

def sanitize_ip(ip):
    if ip:
        return ip.replace('.', '[.]')
    return None

def query_virustotal(hash_value, threat_actor_ip):
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report' if threat_actor_ip else 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY}

    if threat_actor_ip:
        params['ip'] = threat_actor_ip
    elif hash_value:
        params['resource'] = hash_value
    else:
        logging.warning("Invalid query. Please provide either a threat_actor_ip or a hash_value.")
        return {'error': True, 'message': 'Invalid query'}

    try:
        response = requests.get(url, params=params)

        if response.status_code == 200:
            result = response.json()

            if 'response_code' in result and result['response_code'] == 1:
                return result
            else:
                logging.warning(f"VirusTotal API query failed. Response: {result.get('verbose_msg', 'Unknown error')}")
                return {'error': True, 'message': result.get('verbose_msg', 'Unknown error')}
        else:
            logging.warning(f"VirusTotal API query failed. HTTP Status Code: {response.status_code}")
            return {'error': True, 'message': f"HTTP Status Code: {response.status_code}"}

    except Exception as e:
        logging.error(f"Error querying VirusTotal API: {e}")
        return {'error': True, 'message': 'Error querying VirusTotal API'}

def generate_incident_report(results):
    # Customize the incident report format based on your needs
    report = f"\nIncident Report:\n\n"

    # Sanitize IP for printing
    sanitized_ip = sanitize_ip(results.get('ip', ''))
    
    # Print threat actor information if available
    if sanitized_ip:
        report += f"Threat IP: {sanitized_ip}\n"
        report += f"Description: The IP address associated with this incident is flagged as malicious by {results.get('positives', 0)} security vendors.\n"

    # Print hash value information if available
    if 'resource' in results:
        report += f"Malicious File: {results['resource']}\n"
        report += f"Description: The file associated with this incident is flagged as malicious by {results.get('positives', 0)} security vendors.\n"

    print(report)

if __name__ == "__main__":
    threat_actor_ip = input("Threat Actor IP: ")
    hash_value = input("Hash Value: ")

    # Query VirusTotal for IP if provided
    if threat_actor_ip:
        virustotal_ip_result = query_virustotal(None, threat_actor_ip)
        generate_incident_report(virustotal_ip_result)

    # Query VirusTotal for hash value if provided
    if hash_value:
        virustotal_hash_result = query_virustotal(hash_value, None)
        generate_incident_report(virustotal_hash_result)
