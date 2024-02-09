import requests
import os
import json
import ipaddress
import logging
from colorama import Fore, Style, init
from dotenv import load_dotenv

# Initialize colorama
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

# Retrieve VirusTotal API key from environment variables
virustotal_api_key = os.getenv("virustotal_api_key")

if not virustotal_api_key:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable not set.")

# Function to validate an IPv4 address
def validate_ip(ip):
    try:
        # Use ipaddress.IPv4Address() to validate the IP address
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

# Welcome banner
def display_welcome_banner():
    print("""
**********************************************
*         Incident Response App              *
*                                            *
*   Welcome to the first iteration!          *
*   Your go-to tool for streamlined incident *
*   response investigations and reporting.   *
*                                            *
*   Explore powerful features, efficiently   *
*   manage incidents, and elevate your       *
*   cybersecurity efforts with confidence.   *
*                                            *
*         Ready to respond effectively?      *
*                                            *
*         Created by: Hugo Guzman            *
*         Powered by: VirusTotal API         *
*         Assisted by: ChatGPT               *
**********************************************
""")
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
    
    report = "\nIncident Response (IR) Report\n\n"

    # Affected User
    report += f"    Victim Information:\n"
    report += f"        User Name: {affected_user}\n"
    report += f"        Host Name: {affected_hostname}\n"
    report += f"        Host IP: {affected_host_ip}\n\n"
    

    report += "     Security Incident Details\n\n"
    
    # Initialize to 0 in the event no IP address value is place or results are actually 0
    positive_ip_hits = 0
    total_ip_hits = 0

    if vt_ip_results:
        ip_location = vt_ip_results.get('ip_results', {}).get('country', 'Unknown')
        associated_owner = vt_ip_results.get('ip_results', {}).get('as_owner', 'Unknown')
        positive_ip_hits = vt_ip_results.get('ip_results', {}).get('detected_urls', [{}])[0].get('positives', 0)
        total_ip_hits = vt_ip_results.get('ip_results', {}).get('detected_urls', [{}])[0].get('total', 0)
        asn = vt_ip_results.get('ip_results', {}).get('asn', 'Unknown')
        detected_urls = vt_ip_results.get('ip_results', {}).get('detected_urls', [])
        verbose_message = vt_ip_results.get('ip_results', {}).get('verbose_msg', 'Unknown')
        
        #Sanitizes URLS with a parenthesis in the last period [ex. www.google(.)com]
        sanitized_urls = [url.get('url', 'Unknown').rsplit('.', 1)[0] + '[.]' + url.get('url', 'Unknown').rsplit('.', 1)[1] if '.' in url.get('url', 'Unknown') else url.get('url', 'Unknown') for url in detected_urls]

        report += f"        IP Address Threat Details\n"
        report += f"            Malicious IP: {sanitized_threat_actor_ip}\n"
        report += f"            Malicious IP Location: {ip_location}\n"
        report += f"            Associated Owner: {associated_owner}\n"
        report += f"            ASN (Autonomous System Number): {asn}\n"
        report += f"            Detected/Associated URLs: {', '.join(sanitized_urls)}\n\n"

        report += f"        Threat credibility:\n"
    if positive_ip_hits > 0:
        report += f"            The OSINT investigation found that {Fore.RED}{positive_ip_hits}{Style.RESET_ALL} out of {total_ip_hits}\n"
        report += f"            security vendors flag this IP address as malicious.\n"
        report += f"            VirusTotal Message: {verbose_message}\n\n"
    else:
        report += f"            Suspicious IP Address: {hash_value}\n"
        report += f"            The OSINT investigation found {Fore.YELLOW}no{Style.RESET_ALL} malicious reputation for the IP address provided.\n\n"
        
    
    # File Details (if hash is provided)
    # Initialize to 0 in the event no hash value is place or results are actually 0
    positive_hash_hits = 0  
    total_hash_hits = 0
    
    if vt_hash_results:
        file_name = vt_hash_results.get('hash_results', {}).get('file_name', 'Not provided')
        detection_date = vt_hash_results.get('hash_results', {}).get('scan_date', 'Unknown')
        positive_hash_hits = vt_hash_results.get('hash_results', {}).get('positives', 0)
        total_hash_hits = vt_hash_results.get('hash_results', {}).get ('total', 0)

        report += f"        Suspicious File Details:\n"
        report += f"            File Hash: {hash_value}\n"
        report += f"            File Name: {file_name}\n"
        report += f"            File Detection Date: {detection_date}\n\n"
        
        report += f"        Threat credibility\n" 
    if positive_hash_hits > 0:
        report += f"            The OSINT investigation found that {Fore.RED}{positive_hash_hits}{Style.RESET_ALL} out of {total_hash_hits}\n"
        report += f"            security vendors flag this file hash as malicious.\n\n"
    else:
        report += f"            Suspicious File Hash:\n"
        report += f"            The OSINT investigation found {Fore.YELLOW}no{Style.RESET_ALL} malicious reputation for the hash value provided.\n\n"



    # Remediation Actions
    report += "     Remediation Actions\n\n"
    report += f"         Isolate the following affected system:\n"
    report += f"             User Name: {affected_user}\n"
    report += f"             Host Name: {affected_hostname}\n"
    report += f"             Host IP: {affected_host_ip}\n\n"
    
    if positive_ip_hits > 0:
        report += f"         Block traffic to and from the following malicious IP address: {Fore.RED}{sanitized_threat_actor_ip}{Style.RESET_ALL}\n\n"
    else: 
        report += f""
    report += f"         Conduct a thorough investigation to identify and remove any traces of the malicious file.\n\n"

    report += f"         Strengthen overall security measures, including endpoint protection and network monitoring.\n\n"

    report += f"         Regularly update antivirus signatures and security patches.\n\n"

    ### full JSON IP REPORT: 
    ### report += f"    Full IP Results JSON: {vt_ip_results}\n"
    ### report += f"    Full IP Results JSON: {vt_hash_results}\n"

    return report
   


# Function to guide the incident response workflow
def incident_response_workflow():
    while True:
        print("Let's generate our incident response report. Please gather and input the following information")
        affected_user = input("Affected User Name: ")
        affected_hostname = input("Affected Host Name: ")

        # Validate and prompt until a valid IP is provided
        while True:
            affected_host_ip = input("Affected Host IP: ")
            if validate_ip(affected_host_ip):
                break
            else:
                print("Invalid IP address. Please enter a valid IPv4 address.")

        # Validate and prompt until a valid IP is provided
        while True:
            threat_actor_ip = input(f"{Fore.YELLOW}Suspicious IP Address{Style.RESET_ALL}: ")
            if not threat_actor_ip or validate_ip(threat_actor_ip):
                break
            else:
                print("Invalid IP address. Please enter a valid IPv4 address.")

        hash_value = input(f"{Fore.YELLOW}Suspicious File Hash{Style.RESET_ALL}: ")

            # Check if Threat Actor IP is provided by the user
        if not threat_actor_ip.strip():  # Check if the input is an empty string after stripping whitespace
            print("No Threat Actor IP provided. Skipping IP query.")
            ip_results = {}
        else:
            # Query VirusTotal for IP information
            ip_results = query_virustotal_ip(threat_actor_ip, virustotal_api_key)
            positive_ip_hits = ip_results.get('positives', 0)  # Initialize to 0 if 'positives' key is not present


# Check if Hash Value is provided by the user
        if not hash_value.strip():  # Check if the input is an empty string after stripping whitespace
            print("No File Hash Value provided. Skipping Hash query.")
            hash_results = {}
        else:
            # Query VirusTotal for hash information
            hash_results = query_virustotal_hash(hash_value, virustotal_api_key)

        sanitized_threat_actor_ip = (
            ".".join(threat_actor_ip.split(".")[:-1]) + "[.]" + threat_actor_ip.split(".")[-1]
        )

        # Generate incident report
        incident_report = generate_incident_report(affected_user, affected_host_ip, sanitized_threat_actor_ip, hash_value, ip_results, hash_results, affected_hostname)

        print(incident_report)

        if input("Do you want to run another query? (y/n): ").lower() != "y":
            break



def main():
    # Check if it's the first launch
    first_launch = True

    if first_launch:
        # If it's the first launch, display the welcome banner
        display_welcome_banner()
        first_launch = False

    # Run the incident response workflow
    incident_response_workflow()

if __name__ == "__main__":
    ### EXPOSES API KEY - USE FOR DEBUGGING/TESTING ONLY ###
    # logging.basicConfig(level=logging.DEBUG)  
    main()