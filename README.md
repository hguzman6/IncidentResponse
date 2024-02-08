# Incident Response Reporting Application #
The application queries VirusTotal (VT) via an API and returns useful information on IP addresses and/or file hash values. Essentially, it checks the reputation of the IP address and/or hash value, and provides an actionable intelligence report. The report includes victim information, security incident information, and recommended remediation steps. 
The application is designed to optimize investigations and automate reporting. The goal is to develop a dynamic application that leverages open-source intelligence databases to conduct investigations and provide valuable and actionable reports. 

## Prerequisites
- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`)
- `requirements.txt` is located in the `Config` directory
- `.env` file containing your VT API key

## Usage
1. Navigate to the `Production` directory.
2. Set up a virtual environment (recommended).
3. Install the required dependencies:
   * `pip install -r requirements.txt`
   * `requirements.txt` is located in the Config folder. 
7. Ensure the `.env` file is configured with the necessary API keys.
8. Run the script: `python Incident-Response-Report-Tool.py`.
9. Input the following data:
    * `Affected User Name`
    * `Affected Host Name`
    * `Affected Host IP`
    * `Suspicious IP Address`
    * `Suspicious File Hash Value`
   
## Options and Parameters
The application is designed to query suspicious IP addresses and/or file hash values. At this time, only one (1) IP address and one (1) file hash value can be queried at a time. The application is capable of querying an IP address and file hash value for the same report. If you choose to input only one query, IP address or file hash value, simply press `enter`, leaving the field blank. 

## Configuration
The application requires a VT API key. Make sure you keep this key secure, as it is tied to your VT account. By using a `.env` file, we are able to keep the key seperate from the application.
The application is already designed to retrieve the key from the `.env` file. Make sure you save it in the same directory as the `Incident-Response-Report-Tool`.

Create a VT account and retrieve your API key:
   * https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key
        
### Environment Variables
Ensure that the following environment variables is set in the .`env` file:
`VIRUSTOTAL_API_KEY`: [Your VirusTotal API key]

## Example

    Incident Response App
    Welcome to the first iteration
    Your go-to tool for streamlined incident 
    response investigations and reporting. 
    Explore powerful features, efficiently 
    manage incidents, and elevate your 
    cybersecurity efforts with confidence. 
    
    Ready to respond effectively?
    
    Created by: Hugo Guzman 
    Powered by: VirusTotal API 
    Assisted by: ChatGPT               


    Let's generate our incident response report. Please gather and input the following information  
    Affected User Name: [user input]
    Affected Host Name: [user input]
    Affected Host IP: [user input]  
    Suspicious IP Address: [user input] 
    Suspicious File Hash: [user input] 
    
    Incident Response (IR) Report
    Victim Information:
    User Name: hugo_guzman
    Host Name: windows1337
    Host IP: 127.0.0.1

     Security Incident Details

        IP Address Threat Details
            Malicious IP: 121.229.31[.]33
            Malicious IP Location: CN
            Associated Owner: Chinanet
            ASN (Autonomous System Number): 4134
            Detected/Associated URLs: https://121.229.31[.]33/, http://121.229.31[.]33/

        Threat credibility:
            The OSINT investigation found that 15 out of 91
            security vendors flag this IP address as malicious.
            VirusTotal Message: IP address in dataset

        Suspicious File Details:
            File Hash: c0202cf6aeab8437c638533d14563d35
            File Name: Not provided
            File Detection Date: 2024-02-08 02:32:42

        Threat credibility
            The OSINT investigation found that 58 out of 72
            security vendors flag this file hash as malicious.

     Remediation Actions

         Isolate the following affected system:
             User Name: hugo_guzman
             Host Name: windows1337
             Host IP: 127.0.0.1

         Block traffic to and from the following malicious IP address: 121.229.31[.]33

         Conduct a thorough investigation to identify and remove any traces of the malicious file.

         Strengthen overall security measures, including endpoint protection and network monitoring.

         Regularly update antivirus signatures and security patches.

Do you want to run another query? (y/n):`


## Troubleshooting
To troubleshoot connection to VT API:
          Scroll to the bottom of the scipt, find the function `if __name__ == "__main__":` and remove the `#` from  `logging.basicConfig(level=logging.DEBUG)`
          Note: this will expose your API key via the URL it prints out. 
          
          example:
                `...
                Let's generate our incident response report. Please gather and input the following information
                Affected User Name: check
                Affected Host Name: check
                Affected Host IP: 127.0.0.1
                Suspicious IP Address: 121.229.31.33
                Suspicious File Hash:
                DEBUG:urllib3.connectionpool:Starting new HTTPS connection (1): www.virustotal.com:443
                DEBUG:urllib3.connectionpool:https://www.virustotal.com:443 "GET /vtapi/v2/ip-address/report?apikey=<REDACTED>&ip=121.229.31.33 HTTP/1.1" 200 None
                No File Hash Value provided. Skipping Hash query.
                ...`
                
## Contributing
Feel free to contribute by opening issues or submitting pull requests, or email me @ hugo.guzman92@gmail.com 

## Acknowledgments
- Jesus Christ, our Lord and Savior
- VirusTotal API Documentation
- OpenAI ChatGPT 

## License
This project is licensed under the [MIT License], located in the main directory. 
