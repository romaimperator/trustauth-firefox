<?php

session_start();

if ($_SESSION['logged_in'] === true) {
  $_SESSION['logged_in'] = false;
  unset($_SESSION['user_id']);
  header('LOCATION: /');
}
?>
