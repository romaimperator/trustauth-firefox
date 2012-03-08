<html>
    <head>
        <link href="css/bootstrap-responsive.css" rel="stylesheet">
        <link href="css/bootstrap.css" rel="stylesheet">
        <script src="js/bootstrap.js"></script>
    </head>
    <body>
        <input id="foamicate_url" type="hidden" value="http://127.0.0.1/foamicate_auth.php"/>
<?php
    include('mysql.php');
    session_start();

    if ( ! isset($_SESSION['logged_in'])) {
        $_SESSION['logged_in'] = false;
    }

    if ($_SESSION['logged_in']) {
?>
        <p>Welcome!</p>
        <form action="add_note.php" method="post">
            <input type="text" name="note" value="" />
            <button type="submit">create note</button>
        </form>
        <a href="logout.php">Logout</a>
<?php
        $notes = get_notes($_SESSION['user_id']);

        echo '<ul>';
        foreach ($notes as $note) {
            echo '<li>';
            echo $note['note'];
            echo '</li>';
        }
        echo '</ul>';
    }
    else {
?>
        <p>Hello guest! Welcome to the demo site for Foamicate.</p>
        <p>
            <span class="question">What is Foamicate you ask?</span> Foamicate is a system for authenticating users without using passwords.
            Instead it uses public key cryptography and RSA authentication.
        </p>
        <p>
            <span class="question">How does Foamicate work?</span> For website owners: Allow users to authenticate using foamicate
            you just need to do a few simple steps.
            <ol>
                <li>Add an url in a hidden input field to every page you want to allow the user to login on.
                This special field just needs to have the id "foamicate_url" and a value of the url that the
                Foamicator addons can authenticate with.</li>
                <li>Add the public key storage to your database and user account creation page. Hint: you should
                be able to reuse the password field with a little bit of modification.</li>
                <li>Add the server side authentication procedure to your website. There will soon be provided
                solutions like plugins for CakePHP and Rails but for now you should be able to get something
                working based off the PHP code that I've written.</li>
            </ol>
            For end users:
            <ol><li>To use Foamicate on websites all you need to do is install the Foamicator addon.</li></ol>
        </p>
        <p>Get the Firefox addon and test it out on this site!</p>
<?php
    }
?>
    </body>
</html>
