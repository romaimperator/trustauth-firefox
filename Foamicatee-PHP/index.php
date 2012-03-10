<!DOCTYPE HTML>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="css/foamicate.css" rel="stylesheet">
    <link href="css/bootstrap.css" rel="stylesheet">
    <link href="css/bootstrap-responsive.css" rel="stylesheet">
    <link href="css/prettify.css" type="text/css" rel="stylesheet">
  </head>
  <body onload="window.prettyPrint && prettyPrint()">
    <div class="container">
      <input id="foamicate_url" type="hidden" value="http://127.0.0.1/foamicate_auth.php"/>
<?php
  include('mysql.php');
  session_start();

  if ( ! isset($_SESSION['logged_in'])) {
    $_SESSION['logged_in'] = false;
  }

  if ($_SESSION['logged_in']):
?>
        <div class="row">
          <div class="span4">
            <p>Welcome!</p>
          </div>
          <div class="span2">
            <a href="logout.php">Logout</a>
          </div>
        </div>
        <div class="row">
          <div class="span6">
            <form class="well" action="add_note.php" method="post">
              <label>Note Text</label>
              <input class="span5" type="text" name="note" placeholder="Create a note...">
              <button class="btn" type="submit">create note</button>
            </form>
          </div>
        </div>
  <?php $notes = get_notes($_SESSION['user_id']); ?>
        <div class="row">
          <div class="span4">
            <ol>
              <?php foreach ($notes as $note):  ?>
                <li><?php echo $note['note']; ?></li>
              <?php endforeach; ?>
          </ol>
        </div>
      </div>
<?php else: ?>
      <div class="hero-unit">
        <h1>Hello and welcome to the demo site for Foamicate.</h1>
      </div>
      <div class="row">
        <div class="span3">
          <h3>What is Foamicate?</h3>
          <p>Foamicate is a system for authenticating users without using passwords.
          Instead it uses public key cryptography and RSA authentication. These technologies
          allow users to be authenticated securely and more easily than with
          traditional passwords.</p>
        </div>
        <div class="span4">
          <h3>How does Foamicate work?</h3>
          <p>The server authenticates the client and uses the public key to associate
          the client with an account. The addon then redirects to a url based on success or failure.</p>
          <p><a class="btn" href="#technical">See Details</a></p>
        </div>
        <div class="span5">
          <h3>How can I get Foamicate?</h3>
          <div class="row">
            <div class="span3">
              <h5>For website owners:</h5>
              <p>Allow users to authenticate using Foamicate with just a few simple steps.</p>
              <p><a class="btn" href="#server">See Details</a></p>
            </div>
            <div class="span2">
              <h5>For end users:</h5>
              <p>To use Foamicate all you need to do is install the Foamicator addon.</p>
              <p><a class="btn" href="files/foamicator.xpi">Get the addon!</a></p>
            </div>
          </div>
        </div>
      </div>
      <section id="technical">
<?php include('technical_details.php'); ?>
      </section>
      <section id="server">
<?php include('server_details.php'); ?>
      </section>
<?php endif; ?>
      <hr>
      <footer class="footer">
        <p>Dan Fox</p>
      </footer>
    </div>
    <script src="js/jquery-1.7.1.min.js"></script>
    <script type="text/javascript" src="js/prettify.js"></script>
    <script src="js/bootstrap.js"></script>
  </body>
</html>
