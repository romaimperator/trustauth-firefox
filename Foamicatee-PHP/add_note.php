<?php
include('mysql.php');
session_start();

if ( ! isset($_POST['note']) || ! isset($_SESSION['user_id'])) {
    die();
} else {
    if (add_note($_POST['note'], $_SESSION['user_id'])) {
        echo 'Successfully created the note.';
    } else {
        echo 'There was a problem creating the note.';
    }
    if ($SERVER['HTTP_REFERER']) {
        header('LOCATION: ' . $SERVER['HTTP_REFERER']);
    } else {
        header('LOCATION: /');
    }
}

?>
