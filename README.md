# Incident Response Project

This project is designed to provide incident response reports using data from VirusTotal. It has two versions: Dev and Prodocution.

## Usage

### Dev Version

The development version of the Incident Response Report Tool is located in the `Dev` directory.

#### Prerequisites

- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`)

### Production Version

The production version of the Incident Response Report Tool is located in the `Production` directory.

#### Usage

1. Navigate to the `Production` directory.
2. Set up a virtual environment (recommended).
3. Install the required dependencies: `pip install -r requirements.txt`.
4. Ensure the `.env` file is configured with the necessary API keys.
5. Run the script: `python Incident-Response-Report-Tool.py`.

## Configuration

### Environment Variables

Ensure that the following environment variables are set:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key.

## Contributing

Feel free to contribute by opening issues or submitting pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
