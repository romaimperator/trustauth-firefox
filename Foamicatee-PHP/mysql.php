<?php

function connect() {
    $mysql_link = mysql_connect(':/var/mysql/mysql.sock', 'root');
    mysql_select_db('foamicate');
    return $mysql_link;
}

function disconnect($mysql_link) {
    mysql_close($mysql_link);
}

function fetch_user_info($public_key) {
    $mysql_link = connect();

    $query = sprintf("SELECT * FROM users WHERE public_key='%s'", mysql_real_escape_string($public_key, $mysql_link));

    $result = mysql_query($query, $mysql_link);
    if ($result) {
        $user = mysql_fetch_assoc($result);
    }
    else {
        echo mysql_error();
        return false;
    }

    disconnect($mysql_link);
    return $user;
}

function add_user($public_key) {
    $mysql_link = connect();

    $escaped_public_key = mysql_real_escape_string($public_key, $mysql_link);

    $query = sprintf("INSERT INTO users (public_key) VALUES ('%s')", $escaped_public_key);

    $result = mysql_query($query, $mysql_link);
    $id = mysql_insert_id($mysql_link);

    disconnect($mysql_link);
    return $id;
}

function add_note($note, $user_id) {
    $mysql_link = connect();

    $escaped_note = mysql_real_escape_string($note, $mysql_link);

    $query = sprintf("INSERT INTO note (note, user_id) VALUES ('%s', '%d')", $escaped_note, $user_id);

    $result = mysql_query($query, $mysql_link);
    $id = mysql_insert_id($mysql_link);

    disconnect($mysql_link);
    if ($id === 0) {
        return false;
    } else {
        return $id;
    }
}

function get_notes($user_id) {
    $mysql_link = connect();

    $query = sprintf("SELECT * FROM note WHERE user_id='%s'", mysql_real_escape_string($user_id, $mysql_link));

    $result = mysql_query($query, $mysql_link);

    $notes = fetch_all($result);

    disconnect($mysql_link);
    return $notes;
}

function fetch_all($result) {
   while($row=mysql_fetch_array($result)) {
       $return[] = $row;
   }
   return $return;
}
?>
