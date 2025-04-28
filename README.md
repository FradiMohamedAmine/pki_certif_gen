# Certificate Generator

A web-based tool for generating X.509 certificates with a user-friendly interface. This tool allows users to generate certificates with custom parameters and download them in various formats.

## Features

- Generate X.509 certificates with custom parameters
- Support for multiple certificate formats (PEM, P12)
- User-friendly web interface
- Input validation and error handling
- Secure certificate generation
- Download certificates in various formats

## Prerequisites

- PHP 7.4 or higher
- OpenSSL extension for PHP
- Web server (Apache/Nginx) or PHP built-in server
- Write permissions for the certificates directory

## Installation

1. Clone or download this repository to your web server directory:
```bash
git clone <repository-url>
cd certifcate_gen
```

2. Create a `config.ini` file in the project root with the following content:
```ini
[constants]
PATH_TO_CA_CERTIFICATE = "/path/to/your/ca.crt"
PATH_TO_CA_KEY = "/path/to/your/ca.key"
CA_PASSPHRASE = "your_ca_passphrase"
CERTIFICATE_OUTPUT_DIR = "/path/to/certificates/directory"
KEY_SIZE = 2048
DIGEST_ALGO = "sha256"
```

3. Set proper permissions for the certificates directory:
```bash
chmod 750 certificates
```

## Usage

1. Start the PHP development server:
```bash
php -S localhost:8000
```

2. Open your web browser and navigate to:
```
http://localhost:8000
```

3. Fill out the certificate generation form:
   - Full Name: Your full name
   - Organization: Your organization name (e.g., FSB)
   - Organizational Unit: Your department or unit (e.g., DEPARTEMENT INFO)
   - Email Address: Your email address
   - P12 File Password: Password for the P12 file
   - Certificate Validity: Number of days (1-3650)
   - Country Code: Two-letter country code (e.g., TN)

4. Click "Generate Certificate" to create your certificate

5. Download the generated certificate files:
   - CRT: The certificate file
   - PRIVATE KEY: Your private key
   - PUBLIC KEY: Your public key
   - CSR: Certificate Signing Request
   - P12: PKCS#12 archive containing certificate and private key

## Security Considerations

- Keep your CA private key secure
- Use strong passwords for P12 files
- Regularly backup your certificates
- Monitor certificate expiration dates
- Implement proper access controls for the certificates directory

## Directory Structure

```
certifcate_gen/
├── certificates/         # Generated certificates storage
├── config.ini           # Configuration file
├── generate_cert.php    # Certificate generation script
├── index.html          # Web interface
└── README.md           # This file
```

## Error Handling

The application includes comprehensive error handling for:
- Missing or invalid configuration
- Input validation
- Certificate generation failures
- File system operations
- OpenSSL operations

## Troubleshooting

Common issues and solutions:

1. **"config.ini not found" error**
   - Ensure the config.ini file exists in the correct location
   - Check file permissions

2. **Certificate generation fails**
   - Verify OpenSSL is properly installed
   - Check CA certificate and key paths
   - Ensure proper permissions on the certificates directory

3. **Download links not working**
   - Verify the certificates directory is accessible
   - Check web server configuration
   - Ensure proper file permissions
