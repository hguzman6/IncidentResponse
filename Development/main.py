import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve VirusTotal API key from environment variables
virustotal_api_key = os.getenv("virustotal_api_key")

# Print the loaded API key
print("VirusTotal API Key:", virustotal_api_key)