<?php
include('Crypt/RSA.php');

session_start();

if ( ! isset($_SESSION['authenticating']) ) {
    $_SESSION['authenticating'] = false;
}

// Check if the logged in session variable is set. If it's not initialize with false.
if ( ! isset($_SESSION['logged_in'])) {
    $_SESSION['logged_in'] = false;
}

// TODO: remove
//unset($_SESSION['master_key']);

// This chunk of code creates the padding from binary and converts it to hex
function generate_padding() {
    $pad_1_char = '36';
    $pad_2_char = '5c';
    $pad_1_md5 = "";
    $pad_2_md5 = "";
    $pad_1_sha = "";
    $pad_2_sha = "";
    for ($i = 0; $i < 48; $i++) {
        $pad_1_md5 .= $pad_1_char;
        $pad_2_md5 .= $pad_2_char;
        if ($i == 39) {
            $pad_1_sha = $pad_1_md5;
            $pad_2_sha = $pad_2_md5;
        }
    }
    $pad_1_md5 = $pad_1_md5;
    $pad_2_md5 = $pad_2_md5;

    return array(
        'md5' => array('pad1' => $pad_1_md5, 'pad2' => $pad_2_md5),
        'sha' => array('pad1' => $pad_1_sha, 'pad2' => $pad_2_sha),
    );
}

if ( ! $_SESSION['authenticating']) {
    $_SESSION['authenticating'] = true;

    define('PRE_MASTER_KEY_LENGTH', 48); // in bytes
    define('SERVER_RANDOM_LENGTH', 28);  // in bytes

    $rsa = new Crypt_RSA();

    // First thing to do is grab the username out of the post variables.
    // TODO: change from GET to POST
    $username = $_REQUEST['username'];
    $client_random = $_REQUEST['random'];

    // TODO: Lookup username in database and get the public key
    $public_key = <<<EOF
-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCkHxbir3wJ5yWAtp2b1hubl55s
xqi1O+oTIhVrYNrDrt7Ru8Dpv0EUuVmJ9TehbtGFhzcTQWXzkR3O345ZtkRSByxK
kYmx+pgcxu7ASioPXuefiZh4QuFNSNb6ztiz29W8EmWZbvSQ1pg+QwDb1OA/qfCn
T0geNpMflU4JIDrHDwIBAw==
-----END PUBLIC KEY-----
EOF;
    $_SESSION['public_key'] = $public_key;

    // Generate the random value to use as the pre_master_key
    // TODO: alert about not cryptographically strong value
    $pre_master_key = bin2hex(openssl_random_pseudo_bytes(PRE_MASTER_KEY_LENGTH));

    // Generate the server's random value
    $current_time = new Math_BigInteger(microtime(true) * 10000, '10');
    $server_random = bin2hex($current_time->toBytes()) . bin2hex(openssl_random_pseudo_bytes(SERVER_RANDOM_LENGTH));

    // Generate and store the master key using server.random and client.random
    $master_key = md5($pre_master_key . sha1('A' . $pre_master_key . $client_random . $server_random)) .
                  md5($pre_master_key . sha1('BB' . $pre_master_key . $client_random . $server_random)) .
                  md5($pre_master_key . sha1('CCC' . $pre_master_key . $client_random . $server_random));

    $_SESSION['master_key'] = $master_key;
    $_SESSION['transmitted_messages'] = $username . $client_random . $master_key . $server_random;

    // Load the key into the engine
    $rsa->loadKey($public_key);
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);

    // Encrypt the pre_master_key and convert it to hex
    $encrypted_key = bin2hex($rsa->encrypt($pre_master_key));
    $server_random = bin2hex($rsa->encrypt($server_random));

    // Encode the encrypted key as json
    $json_key = json_encode(array('key' => $encrypted_key, 'random' => $server_random));

    // Return the encrypted pre_master_key as json
    echo $json_key;
}
else {
    define('SENDER_CLIENT', '0x434C4E54');

    define('SUCCESS_URL', 'http://127.0.0.1/~dan/success.php');
    define('FAIL_URL', 'http://127.0.0.1/~dan/failure.php');

    $master_key = $_SESSION['master_key'];
    $transmitted_messages = $_SESSION['transmitted_messages'];
    $public_key = $_SESSION['public_key'];

    // returns two arrays, md5 and sha, each with a pad1 and pad2
    extract(generate_padding());

    $rsa = new Crypt_RSA();

    // Load the key into the engine
    $rsa->loadKey($public_key, CRYPT_RSA_PUBLIC_FORMAT_PKCS1);
    $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);

    // Calculate the expected hashes from the client
    $md5_hash =  md5($master_key . $md5['pad2'] .  md5($transmitted_messages . SENDER_CLIENT . $master_key . $md5['pad1']));
    $sha_hash = sha1($master_key . $sha['pad2'] . sha1($transmitted_messages . SENDER_CLIENT . $master_key . $sha['pad1']));

    // TODO: change to $_POST
    $user_md5 = bin2hex($rsa->decrypt(pack('H*', $_REQUEST['md5'])));
    $user_sha = bin2hex($rsa->decrypt(pack('H*', $_REQUEST['sha'])));

    // If the hashes match then set the successful login session key
    if ($md5_hash === $user_md5 && $sha_hash === $user_sha) {
        unset($_SESSION['master_key']);
        unset($_SESSION['transmitted_messages']);
        unset($_SESSION['public_key']);

        $_SESSION['logged_in'] = true;

        echo json_encode(array('redirect_url' => bin2hex($rsa->encrypt(SUCCESS_URL))));
    }
    else {
        echo json_encode(array('redirect_url' => bin2hex($rsa->encrypt(FAIL_URL))));
    }

    $_SESSION['authenticating'] = false;
}

?>
