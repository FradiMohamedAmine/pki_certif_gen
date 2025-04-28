<?php
/**
 * Certificate Generation Script
 * This script generates X.509 certificates using OpenSSL
 */

// Load configuration
$configFile = __DIR__ . '/config.ini';
if (!file_exists($configFile)) {
    die("Error: config.ini not found");
}

$config = parse_ini_file($configFile, true);
if ($config === false) {
    die("Error: Invalid config.ini format");
}

// Constants
define('CIPHER_ALGO', OPENSSL_KEYTYPE_RSA);
define('DIGEST_ALGO', $config['constants']['DIGEST_ALGO']);
define('KEY_SIZE', $config['constants']['KEY_SIZE']);

// Function to validate and sanitize input
function sanitizeInput($input) {
    return filter_var($input, FILTER_SANITIZE_STRING);
}

// Function to generate certificate
function generateCertificate($userData) {
    global $config;
    
    // Validate required fields
    $requiredFields = ['name', 'organization', 'organizational_unit', 'email', 'password', 'validity', 'country', 'serial'];
    foreach ($requiredFields as $field) {
        if (!isset($userData[$field]) || empty($userData[$field])) {
            throw new Exception("Missing required field: $field");
        }
    }
    
    // Sanitize inputs
    $name = sanitizeInput($userData['name']);
    $organization = sanitizeInput($userData['organization']);
    $organizationalUnit = sanitizeInput($userData['organizational_unit']);
    $email = filter_var($userData['email'], FILTER_SANITIZE_EMAIL);
    $country = strtoupper(sanitizeInput($userData['country']));
    
    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        throw new Exception("Invalid email format");
    }
    
    // Validate country code
    if (!preg_match('/^[A-Z]{2}$/', $country)) {
        throw new Exception("Invalid country code");
    }
    
    // Load CA certificate and key
    if (!file_exists($config['constants']['PATH_TO_CA_CERTIFICATE'])) {
        throw new Exception("CA certificate not found");
    }
    
    if (!file_exists($config['constants']['PATH_TO_CA_KEY'])) {
        throw new Exception("CA key not found");
    }
    
    $caCertificate = file_get_contents($config['constants']['PATH_TO_CA_CERTIFICATE']);
    $caKey = file_get_contents($config['constants']['PATH_TO_CA_KEY']);
    
    if ($caCertificate === false || $caKey === false) {
        throw new Exception("Failed to read CA files");
    }
    
    // Generate key pair
    $keyDetails = [
        'digest_alg' => DIGEST_ALGO,
        'private_key_type' => CIPHER_ALGO,
        'private_key_bits' => KEY_SIZE
    ];
    
    $keyPair = openssl_pkey_new($keyDetails);
    if ($keyPair === false) {
        throw new Exception("Failed to generate key pair: " . openssl_error_string());
    }
    
    // Export private key
    $privateKey = '';
    if (!openssl_pkey_export($keyPair, $privateKey, $userData['password'])) {
        throw new Exception("Failed to export private key: " . openssl_error_string());
    }
    
    // Get public key
    $keyDetails = openssl_pkey_get_details($keyPair);
    $publicKey = $keyDetails['key'];
    
    // Create certificate signing request
    $dn = [
        "countryName" => $country,
        "organizationName" => $organization,
        "organizationalUnitName" => $organizationalUnit,
        "commonName" => $name,
        "emailAddress" => $email
    ];
    
    $csr = openssl_csr_new($dn, $keyPair, ['digest_alg' => DIGEST_ALGO]);
    if ($csr === false) {
        throw new Exception("Failed to create CSR: " . openssl_error_string());
    }
    
    // Sign the certificate
    $certificate = openssl_csr_sign(
        $csr,
        $caCertificate,
        [$caKey, $config['constants']['CA_PASSPHRASE']],
        $userData['validity'],
        ['digest_alg' => DIGEST_ALGO],
        $userData['serial']
    );
    
    if ($certificate === false) {
        throw new Exception("Failed to sign certificate: " . openssl_error_string());
    }
    
    // Create output directory
    $outputDir = $config['constants']['CERTIFICATE_OUTPUT_DIR'] . '/' . 
                preg_replace('/[^A-Za-z0-9_-]/', '_', $name);
    
    if (!is_dir($outputDir)) {
        if (!mkdir($outputDir, 0750, true)) {
            throw new Exception("Failed to create output directory");
        }
    }
    
    // Save files
    $baseFilename = $outputDir . '/' . preg_replace('/[^A-Za-z0-9_-]/', '_', $name);
    
    if (!file_put_contents($baseFilename . '_private.key', $privateKey)) {
        throw new Exception("Failed to save private key");
    }
    
    if (!file_put_contents($baseFilename . '_public.key', $publicKey)) {
        throw new Exception("Failed to save public key");
    }
    
    $csrContent = '';
    if (!openssl_csr_export($csr, $csrContent)) {
        throw new Exception("Failed to export CSR");
    }
    
    if (!file_put_contents($baseFilename . '_request.req', $csrContent)) {
        throw new Exception("Failed to save CSR");
    }
    
    $certContent = '';
    if (!openssl_x509_export($certificate, $certContent)) {
        throw new Exception("Failed to export certificate");
    }
    
    if (!file_put_contents($baseFilename . '_certificate.crt', $certContent)) {
        throw new Exception("Failed to save certificate");
    }
    
    // Export PKCS#12
    if (!openssl_pkcs12_export_to_file(
        $certificate,
        $baseFilename . '_pkcs12.p12',
        $keyPair,
        $userData['password'],
        ['extracerts' => $caCertificate, 'friendly_name' => $name]
    )) {
        throw new Exception("Failed to export PKCS#12: " . openssl_error_string());
    }
    
    return [
        'private_key' => $baseFilename . '_private.key',
        'public_key' => $baseFilename . '_public.key',
        'csr' => $baseFilename . '_request.req',
        'certificate' => $baseFilename . '_certificate.crt',
        'pkcs12' => $baseFilename . '_pkcs12.p12'
    ];
}

// Example usage
try {
    $userData = [
        'name' => 'Mohamed Amine FRADI',
        'organization' => 'FSB',
        'organizational_unit' => 'DEPARTEMENT INFO',
        'email' => 'mohamedamine.fradi@fsb.ucar.tn',
        'password' => '123456',
        'validity' => 365,
        'country' => 'TN',
        'serial' => '12345678'
    ];
    
    $result = generateCertificate($userData);
    echo "Certificate generated successfully!\n";
    echo "Files saved in: " . dirname($result['certificate']) . "\n";
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>
