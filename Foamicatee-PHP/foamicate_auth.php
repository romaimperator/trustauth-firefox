<?php
include('foamicatee.php');
include('mysql.php');

session_start();

// Define a few constants
define('SUCCESS_URL', 'http://127.0.0.1/');
define('FAIL_URL', 'http://127.0.0.1/failure.php');

if ( ! isset($_SESSION['authenticating']) ) {
    $_SESSION['authenticating'] = false;
}

// Check if the logged in session variable is set. If it's not initialize with false.
if ( ! isset($_SESSION['logged_in'])) {
    $_SESSION['logged_in'] = false;
}


if ( ! $_SESSION['authenticating']) {
    $_SESSION['authenticating'] = true;

    // First thing to do is grab the username out of the post variables.
    // TODO: change from GET to POST
    //$user = fetch_user_info($username);
    $user = array(
        'public_key' => rawurldecode($_REQUEST['public_key']),
        'random'     => $_REQUEST['random'],
    );

    $result = Foamicatee::get_challenge($user);

    $_SESSION['server'] = $result['server'];
    $_SESSION['user']   = $user;

    echo $result['json'];
}
else {
    $user   = $_SESSION['user'];
    $server = $_SESSION['server'];

    if ( ! isset($_REQUEST['md5']) || ! isset($_REQUEST['sha'])) {
        $result = Foamicatee::wrong_stage();
    }
    else {
        $user['md5'] = $_REQUEST['md5'];
        $user['sha'] = $_REQUEST['sha'];

        $result = Foamicatee::authenticate($user, $server, SUCCESS_URL, FAIL_URL);

        if ($result['status']) {
            $_SESSION['logged_in'] = true;

            if (($db_user = fetch_user_info($user['public_key'])) == true) {
                $_SESSION['user_id'] = $db_user['id'];
            } else {
                $_SESSION['user_id'] = add_user($user['public_key']);
            }
        }
    }
    $_SESSION['authenticating'] = false;
    echo $result['json'];
}

?>
