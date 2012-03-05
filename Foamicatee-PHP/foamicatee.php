<?php
/*
 * This class provides the methods which will allow the server to
 * authenticate with a client user using the Foamicator addon. The usage
 * of this library is fairly simple.
 *
 * Dependencies:
 *
 * This class depends on the Crypt/RSA phpseclib found at
 *     http://phpseclib.sourceforge.net/documentation/index.html
 *
 * There are two main structures used with this API. First is the user
 * array which consists of the following information:
 *      $user = array(
 *          'random'     => // the provided random value
 *          'public_key' => // the public key associated with this user
 *
 *          // The next two are needed only after the challenge is sent
 *          // and are supplied by Foamicator to you
 *          'md5'        => // the md5 hash response to the challenge
 *          'sha'        => // the sha1 hash response to the challenge
 *      );
 *
 * The other main structure is the server information. This is generated
 * for you and returned as part of the array from the get_challenge
 * function. This information will need to be stored to be accessible
 * for the reply request from the addon. The array consists of:
 *      $server = array(
 *          'pre_master_secret' => // the pre_master_secret generated for
 *                                 // this authentication
 *          'random'            => // the random value that was created
 *      );
 *
 * Usage:
 *
 * 1. To get the challenge message to reply to the Foamicator addon with
 *    call the get_challenge function with the user array like so:
 *
 *      $result = Foamicatee::get_challenge(array(
 *          'random'     => $user_random,
 *          'public_key' => $public_key,
 *      ));
 *
 *    The function returns an array of data as follows:
 *
 *      array(
 *          'status' => // true if the function was successful false
 *                      // otherwise
 *          'json'   => // a json encoded string that should be returned
 *                      // to the Foamicator addon
 *          'server' => // the array of information to save for the
 *                      // second function call
 *      );
 *
 * 2. After saving the server array return the json string.
 *
 * 3. When Foamicator replies with the answer to the challenge add the
 *    hashes to the user array should call the authenticate function like
 *    so:
 *
 *    $user['md5'] = $_POST['hashes']['md5'];
 *    $uesr['sha'] = $_POST['hashes']['sha'];
 *    $result = Foamicatee::authenticate($user, $result['server']);
 *
 *    The function returns an array similar to the first:
 *
 *      array(
 *          'status' => // true if the user was authenticated false
 *                      // otherwise
 *          'json'   => // a json encoded string that should be returned
 *                      // to the Foamicator addon
 *      );
 *
 * 4. No matter whether the authentication was successful or not, the
 *    json string should still be returned to the addon. It will tell the
 *    addon if the authentication was successful or not. If it wasn't,
 *    Foamicator alerts the user and she can attempt to login again.
 *
 * NOTE:
 *    If either function did not receive the required parameters they
 *    will return false.
 *
 * SEE ALSO:
 *    For an example implementation see foamicate_auth.php
 *
 *
 *
 *
 * Implementation details
 *
 * There are currently 4 status codes. They are:
 *       'auth'          => 0, // Returned with the challenge to indicate
 *                             // the authentication is in progress.
 *       'auth_fail'     => 1, // Returned when the authentication
 *                             // failed.
 *       'logged_in'     => 2, // Returned if the login was successful.
 *       'stage_fail'    => 3, // Indicates that the server and addon are
 *                             // out of sync in the auth process.
 *
 * The general structure of the json array is as follows:
 *
 *      'json' => array(
 *          'status' => // the status code indicating what kind of
 *                      // message this is
 *
 *          // These are required for _fail messages
 *          'error'  => // the error message to display to the user
 *
 *          // These are included in the auth message
 *          'secret' => // the encrypted pre_master_secret
 *          'random' => // the server's random value
 *
 *          // These are incldued in the logged_in and auth_fail
 *          // messages
 *          'url' => // a url to redirect the user's broswer to
 *      )
 *
 * The json returned with the two fail messages should also include an
 * error key with a string to display to the user indicating the
 * problem.
 */

require_once('Crypt/RSA.php');

class Foamicatee
{
    // These status codes are used to let Foamicator (the addon) know
    // what happened.
    protected static $status = array(
        'auth'          => 0,
        'auth_fail'     => 1,
        'logged_in'     => 2,
        'stage_fail'    => 3,
    );

    const PRE_MASTER_SECRET_LENGTH = 48; // in bytes
    const SERVER_RANDOM_LENGTH     = 28;  // in bytes
    const SENDER_CLIENT            = '0x434C4E54';

    protected static $md5_pad = array(
        'pad1' => '363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636',
        'pad2' => '5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
    );
    protected static $sha_pad = array(
        'pad1' => '36363636363636363636363636363636363636363636363636363636363636363636363636363636',
        'pad2' => '5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c',
    );

    /*
     * This chunk of code creates the padding from binary and converts it to hex.
     *
     * @deprecated
     * @return array of the paddings
     */
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

    /*
     * Returns the message for the client to indicate that it's at the wrong stage
     * of authentication and it should retry.
     *
     * @return array of status, json return message
     */
    public static function wrong_stage() {
        return array(
            'status' => true,
            'json'   => json_encode(array('status' => Foamicatee::$status['stage_fail'], 'error' => 'Wrong stage of logging in.')),
        );
    }

    /*
     * Generates the challenge message for the client addon.
     *
     * @param user the array of user info, public key, random
     * @returns array of status, json return message and the server values
     *     which will be needed later
     */
    public static function get_challenge($user) {
        // Return error if any required parameter is missing
        if ( ! isset($user['random']) || ! isset($user['public_key'])) {
            return false;
        }

        $user['public_key'] = Foamicatee::fix_key($user['public_key']);

        // Load the key into the engine
        $rsa = new Crypt_RSA();
        $rsa->loadKey($user['public_key']);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);

        $pre_master_secret = Foamicatee::get_pre_master_secret();
        $server_random     = Foamicatee::get_server_random();

        // Encrypt the pre_master_secret and convert it to hex
        $encrypted_secret = bin2hex($rsa->encrypt($pre_master_secret));
        $encrypted_random = bin2hex($rsa->encrypt($server_random));

        // Encode the encrypted secret as json
        return array(
            'status' => true,
            'json'   => json_encode(array('secret' => $encrypted_secret, 'random' => $encrypted_random, 'status' => Foamicatee::$status['auth'])),
            'server' => array('random' => $server_random, 'pre_master_secret' => $pre_master_secret),
        );
    }

    /*
     *

    /*
     * Checks to see if the server hash matches the user supplied hash.
     *
     * @param $user array with the md5 hash, the sha hash, the user
     *      random, the public_key
     * @param $server array with the pre_master_secret and the random value
     * @param success_url the url to tell the user to redirect to upon successful authentication
     * @param fail_url the url to tell the user to redirect to upon failed authentication
     * @return array with the status and the json return message
     */
    public static function authenticate($user, $server, $success_url, $fail_url) {
        // Return error if any required parameter is missing
        if ( ! isset($user['random']) || ! isset($user['public_key']) || ! isset($user['md5']) || ! isset($user['sha']) ||
            ! isset($server['pre_master_secret']) || ! isset($server['random'])) {
            return false;
        }

        $user['public_key'] = Foamicatee::fix_key($user['public_key']);

        // Load the key into the engine
        $rsa = new Crypt_RSA();
        $rsa->loadKey($user['public_key']);
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);

        // Decrypt the hashes from the client
        $user_md5 = bin2hex($rsa->decrypt(pack('H*', $user['md5'])));
        $user_sha = bin2hex($rsa->decrypt(pack('H*', $user['sha'])));

        // Generate the master secret
        $master_secret        = Foamicatee::get_master_secret($server['pre_master_secret'], $user['random'], $server['random']);
        $transmitted_messages = Foamicatee::get_transmitted_messages($user['random'], $master_secret, $server['random']);

        // Calculate the expected hashes from the client
        $md5_hash = Foamicatee::get_md5_hash($master_secret, $user['random'], $server['random'], $transmitted_messages);
        $sha_hash = Foamicatee::get_sha_hash($master_secret, $user['random'], $server['random'], $transmitted_messages);

        // If the hashes match then set the successful login session secret
        if ($md5_hash === $user_md5 && $sha_hash === $user_sha) {
            return array(
                'status' => true,
                'json' => json_encode(array('url' => $success_url, 'status' => Foamicatee::$status['logged_in'])),
            );
        }
        else {
            return array(
                'status' => false,
                'json' => json_encode(array('url' => $fail_url, 'status' => Foamicatee::$status['auth_fail'], 'error' => 'Failed to authenticate.')),
            );
        }
    }

    /*
     * Corrects the format of the public key so that Crypt/RSA won't
     * freak out.
     *
     * @param public_key the key
     * @return the fixed key
     */
    public static function fix_key($public_key) {
        $public_key = substr_replace($public_key, '', 0, 26);   // Remove the BEGIN PUBLIC KEY
        $public_key = substr_replace($public_key, '', -24, 24); // Remove the END PUBLIC KEY
        $public_key = str_replace(' ', '', $public_key);        // Remove spaces
        $public_key = str_replace("\r\n", '', $public_key);     // Remove line breaks
        $public_key = chunk_split($public_key, 64, "\r\n");
        return "\r\n-----BEGIN PUBLIC KEY-----\r\n" . $public_key . "-----END PUBLIC KEY-----\r\n";
    }

    /*
     * Calculates the md5 hash to expect from the client.
     *
     * @param client_random the client's random value
     * @param server_random the server's random value
     * @param transmitted_messages the client_random,
     *      master_secret, and server_random concatenated in this order
     * @return the md5 hash
     */
    protected static function get_md5_hash($master_secret, $client_random, $server_random, $transmitted_messages) {
        return md5($master_secret . Foamicatee::$md5_pad['pad2'] .  md5($transmitted_messages . Foamicatee::SENDER_CLIENT . $master_secret . Foamicatee::$md5_pad['pad1']));
    }

    /*
     * Calculates the md5 hash to expect from the client.
     *
     * @param client_random the client's random value
     * @param server_random the server's random value
     * @param transmitted_messages the client_random,
     *      master_secret, and server_random concatenated in this order
     * @return the md5 hash
     */
    protected static function get_sha_hash($master_secret, $client_random, $server_random, $transmitted_messages) {
        return sha1($master_secret . Foamicatee::$sha_pad['pad2'] . sha1($transmitted_messages . Foamicatee::SENDER_CLIENT . $master_secret . Foamicatee::$sha_pad['pad1']));
    }

    /*
     * Calculate the master secret using server.random and client.random.
     *
     * @param pre_master_secret the pre_master_secret to use
     * @param client_random  the random value from the client
     * @param server_random  the random value from the server
     * @return the master secret
     */
    protected static function get_master_secret($pre_master_secret, $client_random, $server_random) {
        return md5($pre_master_secret . sha1('A' . $pre_master_secret . $client_random . $server_random)) .
              md5($pre_master_secret . sha1('BB' . $pre_master_secret . $client_random . $server_random)) .
             md5($pre_master_secret . sha1('CCC' . $pre_master_secret . $client_random . $server_random));
    }

    /*
     * Creates the tranmitted_messages value.
     *
     * @param user_random the random value of the user
     * @param server_random the random value of the server
     * @param master_secret the master secret
     * @return the value for transmitted_message
     */
    protected static function get_transmitted_messages($user_random, $master_secret, $server_random) {
        return $user_random . $master_secret . $server_random;
    }

    /*
     * Generates a pre_master_secret.
     *
     * @return the pre_master_secret
     */
    protected static function get_pre_master_secret() {
        // TODO: alert about not cryptographically strong value
        return bin2hex(openssl_random_pseudo_bytes(Foamicatee::PRE_MASTER_SECRET_LENGTH));
    }

    /*
     * Generates the server's random value. The SERVER_RANDOM_LENGTH
     * controls how long in bytes the random portion of the pre_master_secret
     * is.
     *
     * @return server's random value
     */
    protected static function get_server_random() {
        $current_time = new Math_BigInteger(microtime(true) * 10000, '10');
        return bin2hex($current_time->toBytes()) . bin2hex(openssl_random_pseudo_bytes(Foamicatee::SERVER_RANDOM_LENGTH));
    }
}

?>
