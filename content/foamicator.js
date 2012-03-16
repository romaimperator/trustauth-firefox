var Foamicator = {
  RANDOM_LENGTH: 28, // in bytes

  SENDER_CLIENT: '0x434C4E54',

  FOAMICATOR_SALT: '2EEC776BE2291D76E7C81706BD0E36C0C10D62A706ADB12D2799CA731503FBBA',

  STATUS: {
      'auth':       0,
      'auth_fail':  1,
      'logged_in':  2,
      'stage_fail': 3,
  },

  /*
   * Runs the ajax requests that authenticate the given key with the server.
   *
   * @param keys a hash of the public and private keys to use for encryption and decryption
   * @return none
   */
  authenticate: function(keys) {
    this.init_doc();

    var foam          = this;
    // Fetch the URL to authenticate with from the page.
    var auth_url      = jQuery('input:hidden#foamicate_url', this.doc).val();
    var client_random = this.get_random();
    foam.log(auth_url);

    // Send the public_key to the the url specified and listen for the encrypted pre_master_key
    jQuery.post(auth_url, { public_key: escape(keys['public_key']), random: client_random },
      function(data) {
          if (data['status'] === foam.STATUS['stage_fail']) {
              // The server says we were in the middle of a previous authentication so try again.
              foam.log(data['error']);
              foam.login(event);
              return;
          } else if (data['status'] === foam.STATUS['auth']) {
              //foam.log('secret: ' + data['secret']);
              // Now that we have received the server response, decrypt the pre_master_key
              var pre_master_secret = foam.decrypt(keys['private_key'], data['secret']);
              //foam.log('pre_master_secret: ' + pre_master_secret);
              var server_random  = foam.decrypt(keys['private_key'], data['random']);
              //foam.log('user random: ' + client_random);
              //foam.log('server random: ' + server_random);

              // Now we need to generate the master secret
              var master_secret = foam.get_master_secret(pre_master_secret, client_random, server_random);
              //foam.log('master_secret: ' + master_secret);

              // Generate the validation hashes to return to the server
              var transmitted_messages = client_random + master_secret + server_random;
              //foam.log('transmitted_messages: ' + transmitted_messages);

              var hashes = foam.get_hashes(master_secret, client_random, server_random, transmitted_messages);
              //foam.log('md5: ' + hashes['md5']);
              //foam.log('sha: ' + hashes['sha']);
              hashes['md5'] = foam.encrypt(keys['private_key'], hashes['md5']);
              hashes['sha'] = foam.encrypt(keys['private_key'], hashes['sha']);
              //foam.log('hashes: ' + JSON.stringify(hashes, null));
              jQuery.post(auth_url, { md5: hashes['md5'], sha: hashes['sha'] },
                function(data) {
                    if (data['status'] === foam.STATUS['auth_fail']) {
                        foam.log(data['error']);
                    } else if (data['status'] === foam.STATUS['logged_in']) {
                        foam.log('login successful');
                    }
                    openUILinkIn(data['url'], 'current');
              }, 'json').fail(foam.output_fail);
          } else {
              foam.log('Status not supported: ' + data['status']);
          }
    }, 'json').fail(foam.output_fail);
  },

  /*
   * Generates the hashes to respond to the server with.
   *
   * @param master_secret the master_secret to use
   * @param client_random the client's random value
   * @param server_random the server's random value
   * @param transmitted_messages the values that have been sent so far
   * @return array with the md5 and sha hashes
   */
  get_hashes: function(master_secret, client_random, server_random, transmitted_messages) {
    var padding = this.generate_padding();
    var md5 = this.md5(master_secret + padding['md5']['pad2'] + this.md5(transmitted_messages + this.SENDER_CLIENT + master_secret + padding['md5']['pad1']));
    var sha = this.sha1(master_secret + padding['sha']['pad2'] + this.sha1(transmitted_messages + this.SENDER_CLIENT + master_secret + padding['sha']['pad1']));
    return { md5: md5, sha: sha };
  },

  /*
   * Returns the master key.
   *
   * @param pre_master_secret the pre_master_secret to use
   * @param client_random the client's random value
   * @param server_random the server's random value
   * @return the master_secret
   */
  get_master_secret: function(pre_master_secret, client_random, server_random) {
    return this.md5(pre_master_secret + this.sha1('A' + pre_master_secret + client_random + server_random)) +
           this.md5(pre_master_secret + this.sha1('BB' + pre_master_secret + client_random + server_random)) +
           this.md5(pre_master_secret + this.sha1('CCC' + pre_master_secret + client_random + server_random));
  },

  /*
   * Decrypts the hex data with the key.
   *
   * @param key the decryption key
   * @param the encrypted data in hex
   * @return the plaintext data
   */
  decrypt: function(key, data) {
    return key.decrypt(forge.util.hexToBytes(data));
  },

  /*
   * Decrypts the hex data using the key and AES.
   *
   * @param key the decryption key
   * @param the data in hex
   * @return the decrypted data
   */
  decrypt_aes: function(key, data) {
    var cipher = forge.aes.startDecrypting(key, this.FOAMICATOR_SALT, null);
    cipher.update(forge.util.hexToBytes(data));
    cipher.finish();
    return cipher.output.toHex();
  },

  /*
   * Encrypts the hex data with the key.
   *
   * @param key the encryption key
   * @param the data in hex
   * @return the encrypted data
   */
  encrypt: function(key, data) {
    return forge.util.bytesToHex(key.encrypt(forge.util.hexToBytes(data)));
  },

  /*
   * Encrypts the hex data using the key and AES.
   *
   * @param key the encryption key
   * @param the data in hex
   * @return the encrypted data
   */
  encrypt_aes: function(key, data) {
    var cipher = forge.aes.startEncrypting(key, this.FOAMICATOR_SALT, null);
    cipher.update(forge.util.hexToBytes(data));
    cipher.finish();
    return cipher.output.toHex();
  },

  /*
   * Generates a public / private key pair.
   */
  generate_keys: function() {
    // Retreive the key length and exponent values
    var key_length = this.get_i_pref("key_length");
    var exponent   = this.get_i_pref("exponent");

    // Generate the key
    var keys = forge.pki.rsa.generateKeyPair(key_length, exponent);

    this.public_key  = keys['publicKey'];
    this.private_key = keys['privateKey'];

    // Store the values generated
    this.set_c_pref("pub_key", forge.pki.publicKeyToPem(this.public_key));
    this.set_c_pref("priv_key", forge.pki.privateKeyToPem(this.private_key));
  },

  /*
   * Generates the padding required for calculating the hashes and is used for authentication.
   *
   * @return array of the 4 padding values
   */
  generate_padding: function() {
    var pad1_md5 = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x36), 48));
    var pad2_md5 = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x5c), 48));
    var pad1_sha = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x36), 40));
    var pad2_sha = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x5c), 40));
    return { md5: { pad1: pad1_md5, pad2: pad2_md5 },
             sha: { pad1: pad1_sha, pad2: pad2_sha }};
  },

  /*
   * Generate random data for the authentication process
   *
   * @return hex string of random data
   */
  get_random: function() {
      var byte_buffer = forge.util.createBuffer();
      byte_buffer.putInt32((new Date()).getTime());
      byte_buffer.putBytes(forge.random.getBytes(this.RANDOM_LENGTH));
      return byte_buffer.toHex();
  },

  /*
   * Checks to see if the variable is set.
   *
   * @param variable the variable to check
   * @return true if it is, false otherwise
   */
  isset: function(variable) {
      return typeof(variable) != "undefined" && variable !== null;
  },

  /*
   * This function loads the keys from the preferences
   */
  load_keys: function() {
    this.private_key = forge.pki.privateKeyFromPem(this.get_c_pref("priv_key"));
    this.public_key  = forge.pki.publicKeyFromPem(this.get_c_pref("pub_key"));
  },

  /*
   * Authenticates this addon with the remote server.
   */
  login: function (event) {
    var domain = this.get_domain();

    this.login_to_domain(domain);
  },

  /*
   * Initializes the addon.
   */
  on_load: function() {
    // initialization code
    this.initialized = true;

    this.init_pref();
    this.init_doc();
    this.init_db();

    // Check if this is the first run and generate keys if it is
    if (this.get_b_pref("first_run") === true) {
      this.set_b_pref("first_run", false);
      this.generate_keys();
    } else {
      // Otherwise load the keys from the preferences
      this.load_keys();
    }

    // Setup the listeners
    this.init_listener();
  },

  /*
   * Checks to see if the domain is in the database on page load and
   * sets the button text accordingly.
   */
  on_page_load: function(event) {
    if (Foamicator.domain_exist(Foamicator.get_domain())) {
      Foamicator.log('domain exists');
      Foamicator.set_button_text('Login');
    } else {
      Foamicator.log("domain doesn't exists");
      Foamicator.set_button_text('Sign Up');
    }
  },

  /*
   * Outputs the error mesasge if the post request failed.
   * TODO: change to not use alerts
   */
  output_fail: function(msg, textStatus, errorThrown) {
    alert(msg.status + ";" + msg.statusText + ";" + msg.responseXML);
  },

  /*
   * Sets the master password / encryption key for the key pairs and
   * stores it in the browser.
   *
   * @param password the password to use
   * @return nothing
   */
  set_master_password: function(password) {
    this.log(password);
    var first_hash = this.sha512(password + this.FOAMICATOR_SALT);
    this.log(first_hash);
    var second_hash = this.sha512(first_hash + this.get_domain());
    this.log(second_hash);

    this.store_encryption_key(second_hash);
    this.log("done");
  },





/******************************/
/* Browser Specific Functions */
/******************************/

  /*
   * This function changes the label of the main button to text.
   *
   * @param text the text to change the button to.
   */
  set_button_text: function(text) {
    document.getElementById('foamicator-login').label = text;
  },

  /*
   * Prompts the user with the password dialog.
   *
   * NOTE: currently not in use.
   */
  show_master_password_dialog: function() {
    var win = window.openDialog("chrome://foamicator/content/password_dialog.xul",
                      "foamicatorPasswordDialog", "chrome,centerscreen");
  },

  /*
   * Initializes the place to store the public and private key pairs.
   */
  init_db: function() {
    Components.utils.import("resource://gre/modules/Services.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");

    // Establish a connection to the database
    var file = FileUtils.getFile("CurProcD", ["foamicate.sqlite"]);
    var file_exists = file.exists();
    this.db  = Services.storage.openDatabase(file);
    //if ( ! file_exists) {
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT)");
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys_sites (key_id NUMERIC, site_id NUMERIC)");
    //}
  },

  /*
   * Returns the domain of the current page.
   * @return the current page's domain
   */
  get_domain: function() {
    this.init_doc();
    return this.doc.domain;
  },

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  store_encryption_key: function(key) {
    var hostname = 'chrome://foamicator';
    var formSubmitURL = null;
    var httprealm = 'master_password';
    var username = this.FOAMICATOR_SALT;
    var password = key;

    this.log("begin");
    var nsLoginInfo = new Components.Constructor("@mozilla.org/login-manager/loginInfo;1",
                                             Components.interfaces.nsILoginInfo,
                                             "init");

    var loginInfo = new nsLoginInfo(hostname, formSubmitURL, httprealm, username, password, "", "");
    this.log("created info");

    // Get Login Manager
    var myLoginManager = Components.classes["@mozilla.org/login-manager;1"].
                           getService(Components.interfaces.nsILoginManager);

    myLoginManager.addLogin(loginInfo);
    this.log("store info");
  },

  /*
   * Retrieves the enryption key that is stored in the password manager
   *
   * @return the key that was stored
   */
  get_encryption_key: function() {
    var hostname = 'chrome://foamicator';
    var formSubmitURL = null;
    var httprealm = 'master_password';
    var username = this.FOAMICATOR_SALT;
    var password;

    try {
      // Get Login Manager
      var myLoginManager = Components.classes["@mozilla.org/login-manager;1"].
                             getService(Components.interfaces.nsILoginManager);

      // Find users for the given parameters
      var logins = myLoginManager.findLogins({}, hostname, formSubmitURL, httprealm);

      // Find user from returned array of nsILoginInfo objects
      for (var i = 0; i < logins.length; i++) {
        if (logins[i].username == username) {
          password = logins[i].password;
          break;
        }
      }
    }
    catch(ex) {
      // This will only happen if there is no nsILoginManager component class
    }

    return password;
  },

  /*
   * A debugging function used to try and dump an object to the log
   *
   * @param obj the object to dump
   */
  dump: function(obj) {
    var out = '';
    for (var i in obj) {
        out += i + ": " + obj[i] + "\n";
    }

    this.log(out);
  },

  /*
   * Checks to see if the given domain has a key in the database
   *
   * @param domain the domain to look for
   * @return true if the domain is in the database false otherwise
   */
  domain_exist: function(domain) {
    var foam = this;

    // Create the statement to fetch the most recently created key for this domain
    this.log("connection ready: " + this.db.connectionReady);
    try {
      var statement = this.db.createStatement("SELECT domain FROM keys, sites, keys_sites WHERE keys.id=keys_sites.key_id AND sites.id=keys_sites.site_id AND sites.domain=:domain ORDER BY keys.created DESC");
    } catch (e) {
      this.log(this.db.lastErrorString);
      return;
    }

    this.log('created statement');
    // Bind the parameter
    try {
      statement.params.domain = domain;

      // Execute the query synchronously
      statement.executeStep();
      this.log('executed statement');
      var fetched_domain = statement.row;

      this.log(fetched_domain.domain);
      if (domain === fetched_domain.domain) {
        domain_exists = true;
      }
    } catch (ex) {
      this.dump(ex);
      domain_exists = false;
    }
    statement.finalize();
    return domain_exists;
  },

  /*
   * The main function used to login to the website. It fetches the encryption key,
   * the most recently created key from the database, decrypts the keys, and then
   * uses them to login to the website.
   *
   * The database query and the login are handled asynchronously.
   *
   * @param domain the domain of the page to login to
   */
  login_to_domain: function(domain) {
    var foam = this;

    // Create the statement to fetch the most recently created key for this domain
    var statement = this.db.createStatement("SELECT k.public_key, k.private_key FROM keys as k, sites as s, keys_sites as ks WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=':domain' ORDER BY k.created DESC");
    // Bind the parameter
    statement.params.domain = domain;

    // Execute the query asynchronously
    statement.executeAsync({
      handleResult: function(resultSet) {
        var row = resultSet.getNextRow();

        var encrypted_keys = {
          'public_key': row.getResultByName("k.public_key"),
          'private_key': row.getResultByName("k.private_key"),
        };

        var master_key = foam.get_encryption_key();

        var decrypted_keys = {
          'public_key': foam.decrypt_rsa(master_key, encrypted_keys['public_key']),
          'private_key': foam.decrypt_rsa(master_key, encrypted_keys['private_key']),
        };

        authenticate(decrypted_keys);
      },

      handleError: function(error) {
        foam.log("Database Error: " + error.message);
      },

      handleCompletion: function(reason) {
        if (reason != Components.interfaces.mozIStorageStatementCallback.REASON_FINISHED)
          foam.log("Query canceled or aborted!");
      },
    });
  },

  /*
   * Initializes the javascript listeners for the buttons on the preference page.
   */
  init_listener: function() {
    gBrowser.addEventListener("DOMContentLoaded", this.on_page_load, false);

    var observer = {
      observe: function(aSubject, aTopic, aData) {
        // If this addon's option page is displayed
        if (aTopic == "addon-options-displayed" && aData == "foamicate@github.com") {
          var doc = aSubject;

          // Listener for the generate keys button
          var control = doc.getElementById("genbutton");
          control.addEventListener("click", function(e) { Foamicator.generate_keys(); }, false);

          // Listener for the set master password button
          var control = doc.getElementById("mpbutton");
          control.addEventListener("click", function(e) { Foamicator.prompt_password(); }, false);
        }
      }
    };

    // Add the listener
    Services.obs.addObserver(observer, "addon-options-displayed", false);
  },

  /*
   * Prompts the user to enter a new master password.
   */
  prompt_password: function() {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                  .getService(Components.interfaces.nsIPromptService);
    var password = {value: null};
    var checked = {value: null};
    prompts.promptPassword(null, "Set Master Password", null, password, null, checked);
    if (password.value !== null) {
      this.set_master_password(password.value);
    }
  },

  /*
   * Initializes the doc attribute with the document of the current page.
   */
  init_doc: function() {
    this.doc = content.document;
  },

  // Fetch the preferences for the addon
  init_pref: function() {
    this.prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.foamicator.");
  },

  get_b_pref: function(preference) {
      return this.prefs.getBoolPref(preference);
  },

  set_b_pref: function(preference, value) {
      this.prefs.setBoolPref(preference, value);
  },

  get_c_pref: function(preference) {
      return this.prefs.getCharPref(preference);
  },

  set_c_pref: function(preference, value) {
      this.prefs.setCharPref(preference, value);
  },

  get_i_pref: function(preference) {
      return this.prefs.getIntPref(preference);
  },

  set_i_pref: function(preference, value) {
      this.prefs.setIntPref(preference, value);
  },

  /*
   * Logs a message to the console as a Foamicator message.
   *
   * @param aMessage the message to log
   */
  log: function(aMessage) {
      var console = Components.classes['@mozilla.org/consoleservice;1'].
                getService(Components.interfaces.nsIConsoleService);
      console.logStringMessage('Foamicator: ' + aMessage);
  },

  /*
   * Calculates the md5 hash of the given string
   *
   * @param string the string to hash
   * @return the md5 hash
   */
  md5: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.MD5);
    return this.hash(ch, string);
  },

  /*
   * Calculates the sha-1 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-1 hash
   */
  sha1: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA1);
    return this.hash(ch, string);
  },

  /*
   * Calculates the sha-512 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-512 hash
   */
  sha512: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA512);
    return this.hash(ch, string);
  },

  /*
   * The abstract function to use the firefox object to calculate the hash
   * using the browser function instead of a javascript function.
   *
   * @param ch the crypto hash object initalized to the correct hash function
   * @param string the string to hash
   * @return the calculated hash
   */
  hash: function(ch, string) {
    var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"]
                    .createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
    // Set the UTF-8 encoding
    converter.charset = "ASCII";

    // result is an out parameter,
    // result.value will contain the array length
    var result = {};

    // data is an array of bytes
    var data = converter.convertToByteArray(string, result);

    ch.update(data, data.length);

    var hash = ch.finish(false);

    // return the two-digit hexadecimal code for a byte
    function toHexString(charCode)
    {
      return ("0" + charCode.toString(16)).slice(-2);
    };

    // convert the binary hash data to a hex string.
    return [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
  },
};

// Initialize the Foamicator object
window.addEventListener("load", function(e) { Foamicator.on_load(e); }, false);
