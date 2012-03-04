<?php

function add_user($username, $public_key) {
    if ($username == '' || $public_key == '') {
        echo "Error: missing username or public key";
        return false;
    }

    $mysql_link = mysql_connect(':/var/mysql/mysql.sock', 'root');
    mysql_select_db('foamicate');

    $query = sprintf("SELECT * FROM users WHERE username='%s'", mysql_real_escape_string($username, $mysql_link));

    $result = mysql_query($query, $mysql_link);
    if ($result && mysql_fetch_assoc($result)) {
        echo "Username already exists.";
        return false;
    }
    else {
        $query = sprintf("INSERT INTO users (username, public_key) VALUES ('%s', '%s')", mysql_real_escape_string($username, $mysql_link), mysql_real_escape_string($public_key, $mysql_link));

        $result = mysql_query($query, $mysql_link);
        if ($result) {
            echo "Success!";
            return true;
        }
        else {
            mysql_error();
            return false;
        }
    }

    mysql_close($mysql_link);
    return $user;
}

if (add_user($_POST['username'], $_POST['public_key'])) {
    include('index.php');
}

?>
