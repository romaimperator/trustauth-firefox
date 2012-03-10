<div class="row">
  <header class="jumbotron subhead">
    <h1>Server Setup Details</h1>
  </header>
  <div class="span12">
    <h3>To add Foamicate support to your server there's only a few simple steps:</h3>
      <ol class="linenums">
        <li>
          <p>Add a url in a hidden input field to every page you want to allow the user to login on.  This special field just needs to have the id "foamicate_url" and a value of the url that the Foamicator addons can authenticate with. Note: this URL must be absolute not relative.</p>
          <p><code class="prettyprint">&lt;input type="hidden" id="foamicate_url" value="your_authentication_handler_url"&gt;</code></p>
        </li>
        <li>
          <p>Add the public key storage to your database.</p>
        </li>
        <li>
          <p>Add the server side authentication procedure to your website.</p>
          <h5>There will soon be provided solutions for:</h5>
          <ul>
            <li>CakePHP</li>
            <li>Rails</li>
          </ul>
          <p>For now you should be able to get something working using the PHP library that I've written. Here is an example using the authentication code running live on this site:</p>
          <pre class="prettyprint linenums lang-html">
  &lt;?php
  include('foamicatee.php');

  // Start the session
  session_start();

  // Create the key to tell if this is the first part or the second part of authentication
  if ( ! isset($_SESSION['authenticating']) ) {
      $_SESSION['authenticating'] = false;
  }

  // Check if the logged in session variable is set. If it's not initialize with false.
  if ( ! isset($_SESSION['logged_in'])) {
      $_SESSION['logged_in'] = false;
  }

  if ( ! $_SESSION['authenticating']) {
      // This is the initial part of authentication
      $_SESSION['authenticating'] = true;

      // First thing to do is grab the user data out of the post variables.
      // NOTE: rawurldecode() is required because the key is urlencoded.
      $user = array(
          'public_key' => rawurldecode($_POST['public_key']),
          'random'     => $_POST['random'],
      );

      // Get the challenge to transmit to the server
      $result = Foamicatee::get_challenge($user);

      // Store the information required for the next part of authentication
      $_SESSION['server'] = $result['server'];
      $_SESSION['user']   = $user;

      // Return the result to the addon
      echo $result['json'];
  }
  else {
      // This is the second part of authentication

      // Load the stored information
      $user   = $_SESSION['user'];
      $server = $_SESSION['server'];

      // If these keys are not set then the addon and the server are out of sync so tell the addon to start over
      if ( ! isset($_POST['md5']) || ! isset($_POST['sha'])) {
          $result = Foamicatee::wrong_stage();
      }
      else {
          // Add the challenge response to the user information
          $user['md5'] = $_REQUEST['md5'];
          $user['sha'] = $_REQUEST['sha'];

          // Attempt to authenticate the data
          $result = Foamicatee::authenticate($user, $server, SUCCESS_URL, FAIL_URL);

          // $result['status'] is true if the authentication was successful
          if ($result['status']) {
              $_SESSION['logged_in'] = true;

              // Here if the public key is found then load the user_id otherwise create a new account
          }
      }
      // Reset to start authentication from the beginning again
      $_SESSION['authenticating'] = false;

      // Return the status of authentication to the addon
      echo $result['json'];
  }
  ?&gt;
          </pre>
          <a class="btn" href="files/foamicatee.php">Download Now!</a>
        </li>
      </ol>
  </div>
</div>
