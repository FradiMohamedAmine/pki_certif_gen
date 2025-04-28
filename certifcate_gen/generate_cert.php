<?php
// Show all errors for debugging
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Load config using absolute path
$configFile = '/home/bl4z/pki/certifcate_gen/config.ini';
if (!file_exists($configFile)) {
    http_response_code(500);
    die("config.ini not found at: " . $configFile);
}
$ini = parse_ini_file($configFile, true);
$config = $ini['constants'];

// Ensure OpenSSL is available
if (!function_exists('openssl_pkey_new')) {
    http_response_code(500);
    die("OpenSSL extension not enabled");
}

// Load your CA
$caCert = file_get_contents($config['PATH_TO_CA_CERTIFICATE']) 
    or die("Cannot read CA cert at: " . $config['PATH_TO_CA_CERTIFICATE']);
$caKeyPath = $config['PATH_TO_CA_KEY'];

// Make sure the CA key exists and is readable
if (!file_exists($caKeyPath)) {
    die("🚨 CA key file not found at: $caKeyPath");
}
if (!is_readable($caKeyPath)) {
    die("🚨 CA key file exists but is not readable (check permissions)");
}

// Read the CA private key (encrypted)
$caKey = file_get_contents($caKeyPath);
if (strpos($caKey, 'PRIVATE KEY') === false) {
    die("🚨 CA key file does not contain a PEM private key header.\n" 
        . "Here's the first 100 chars:\n" 
        . substr($caKey, 0, 100));
}

// Set the passphrase for the encrypted key
$caPassphrase = $config['CA_PASSPHRASE'];

// Load the CA private key using the passphrase
$caPriv = openssl_pkey_get_private($caKey, $caPassphrase) 
    or die("Invalid CA private key: " . openssl_error_string());

// Validate and sanitize input
$name = trim($_POST['name'] ?? '');
$organization = trim($_POST['organization'] ?? '');
$organizational_unit = trim($_POST['organizational_unit'] ?? '');
$email = trim($_POST['email'] ?? '');
$country = trim($_POST['country'] ?? '');
$validity = intval($_POST['validity'] ?? 365);
$serial = intval($_POST['serial'] ?? 0);

// Validate required fields
if (empty($name) || empty($organization) || empty($organizational_unit) || empty($email) || empty($country)) {
    http_response_code(400);
    die("All fields are required");
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    die("Invalid email format");
}

// Validate country code
if (!preg_match('/^[A-Za-z]{2}$/', $country)) {
    http_response_code(400);
    die("Country code must be exactly 2 letters");
}

// Validate validity period
if ($validity < 1 || $validity > 3650) {
    http_response_code(400);
    die("Validity period must be between 1 and 3650 days");
}

// Build DN from form
$dn = [
    "countryName"            => strtoupper($country),
    "organizationName"       => $organization,
    "organizationalUnitName" => $organizational_unit,
    "commonName"             => $name,
    "emailAddress"           => $email
];

// Generate user private key & CSR
$privkey = openssl_pkey_new([
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
    "private_key_bits" => $config['KEY_SIZE']
]) or die("Key generation failed: " . openssl_error_string());

$csr = openssl_csr_new($dn, $privkey, ["digest_alg" => $config['DIGEST_ALGO']]) 
    or die("CSR generation failed: " . openssl_error_string() . "\nDN: " . print_r($dn, true));

// Self-sign CSR with your CA
$x509 = openssl_csr_sign(
    $csr,
    $caCert,
    $caPriv,
    $validity,
    ["digest_alg" => $config['DIGEST_ALGO']],
    $serial
) or die("Signing failed: " . openssl_error_string());

// Add custom extensions to the certificate
$cert_extensions = [
    "subjectAltName" => "DNS:ca-lab-fsb.com", // Add custom alt names if needed
    "issuer" => "CA LAB FSB", // Add issuer name (CA)
    "Not After" => "06/02/2035", // Expiry date
    "Identity" => "CA LAB FSB"
];

// Adding extensions to the X.509 certificate
$extension_string = '';
foreach ($cert_extensions as $key => $value) {
    $extension_string .= "$key=$value\n";
}

// Export everything to strings
openssl_pkey_export($privkey,  $keyStr)      or die("Export key failed");
openssl_csr_export($csr,        $csrStr)      or die("Export CSR failed");
openssl_x509_export($x509,      $crtStr)      or die("Export CRT failed");

// Convert CA PEM string into an X.509 resource
$caCertRes = openssl_x509_read($caCert);
if (!$caCertRes) {
    die("Failed to parse CA certificate");
}

// Export P12 with CA in the chain
$p12Options = [
    'friendly_name' => $_POST['name'],
    'extracerts'    => [$caCertRes]
];

if (!openssl_pkcs12_export(
        $x509,
        $p12Str,
        $privkey,
        $_POST['password'],
        $p12Options
    )) {
    die("Export P12 failed: " . openssl_error_string());
}

// Extract the public key
$publicKey = openssl_pkey_get_details($privkey);
$publicKeyStr = $publicKey['key'];

// Create the folder named after the certificate (sanitized)
$folder = preg_replace('/[^A-Za-z0-9_-]/', '_', $_POST['name']);
$path = $config['CERTIFICATE_OUTPUT_DIR'] . '/' . $folder;

// Check if certificate already exists
if (is_dir($path)) {
    http_response_code(400);
    die("A certificate with this name already exists. Please choose a different name.");
}

// Ensure the output directory exists
if (!is_dir($config['CERTIFICATE_OUTPUT_DIR'])) {
    if (!mkdir($config['CERTIFICATE_OUTPUT_DIR'], 0750, true)) {
        http_response_code(500);
        die("Failed to create output directory");
    }
}

// Create the user's certificate directory
if (!mkdir($path, 0750, true)) {
    http_response_code(500);
    die("Failed to create certificate directory");
}

// Save the files to the folder
if (!file_put_contents("$path/$folder.private.key", $keyStr)) {
    http_response_code(500);
    die("Failed to save private key");
}

if (!file_put_contents("$path/$folder.public.key", $publicKeyStr)) {
    http_response_code(500);
    die("Failed to save public key");
}

if (!file_put_contents("$path/$folder.req", $csrStr)) {
    http_response_code(500);
    die("Failed to save CSR");
}

if (!file_put_contents("$path/$folder.crt", $crtStr)) {
    http_response_code(500);
    die("Failed to save certificate");
}

if (!file_put_contents("$path/$folder.p12", $p12Str)) {
    http_response_code(500);
    die("Failed to save P12 file");
}

// Provide the user with download links
echo "✔️ Your certificate files have been generated!<br>";
echo "You can download them from the following links:<br>";

$baseUrl = '/certificates/' . $folder . '/';
echo "<a href='{$baseUrl}{$folder}.crt' download>Download CRT</a><br>";
echo "<a href='{$baseUrl}{$folder}.private.key' download>Download PRIVATE KEY</a><br>";
echo "<a href='{$baseUrl}{$folder}.public.key' download>Download PUBLIC KEY</a><br>";
echo "<a href='{$baseUrl}{$folder}.req' download>Download CSR</a><br>";
echo "<a href='{$baseUrl}{$folder}.p12' download>Download P12</a><br>";
?>

