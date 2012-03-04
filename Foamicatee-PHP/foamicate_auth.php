<?php
include('foamicatee.php');

session_start();

// Define a few constants
define('SUCCESS_URL', 'http://127.0.0.1/~dan/success.php');
define('FAIL_URL', 'http://127.0.0.1/~dan/failure.php');

if ( ! isset($_SESSION['authenticating']) ) {
    $_SESSION['authenticating'] = false;
}

// Check if the logged in session variable is set. If it's not initialize with false.
if ( ! isset($_SESSION['logged_in'])) {
    $_SESSION['logged_in'] = false;
}

function fetch_user_info($username) {
    $mysql_link = mysql_connect(':/var/mysql/mysql.sock', 'root');
    $query = sprintf("SELECT * FROM users WHERE username='%s'", mysql_real_escape_string($username, $mysql_link));

    mysql_select_db('foamicate');

    $result = mysql_query($query, $mysql_link);
    if ($result) {
        $user = mysql_fetch_assoc($result);
    }
    else {
        echo mysql_error();
        return false;
    }

    mysql_close($mysql_link);
    return $user;
}

if ( ! $_SESSION['authenticating']) {
    $_SESSION['authenticating'] = true;

    // First thing to do is grab the username out of the post variables.
    // TODO: change from GET to POST
    $username = $_REQUEST['username'];
    $user = fetch_user_info($username);

    if ( ! $user) {
        $result = Foamicatee::invalid_username();
    }
    else {
        $user['random'] = $_REQUEST['random'];

        $result = Foamicatee::get_challenge($user);

        $_SESSION['server'] = $result['server'];
        $_SESSION['user']   = $user;
    }
    echo $result['json'];
}
else {
    $user   = $_SESSION['user'];
    $server = $_SESSION['server'];

    $user['md5'] = $_POST['md5'];
    $user['sha'] = $_POST['sha'];

    $result = Foamicatee::authenticate($user, $server, SUCCESS_URL, FAIL_URL);

    if ($result['status']) {
        $_SESSION['logged_in'] = true;
    }

    $_SESSION['authenticating'] = false;
    echo $result['json'];
}

?>
