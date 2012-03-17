var Foamicator = {
  RANDOM_LENGTH: 28, // in bytes

  SENDER_CLIENT: '0x434C4E54',

  FOAMICATOR_USERNAME:     'CC101164749B358E3C3C15F11DC6DA10F9551E4C435F15BB23F577B2FBCC3413',
  FOAMICATOR_ENC_KEY_SALT: '2EEC776BE2291D76E7C81706BD0E36C0C10D62A706ADB12D2799CA731503FBBA',
  FOAMICATOR_RET_KEY_SALT: '7CAB8505B677344B34B83C77B6A3EF527DC31FEFDF531B9F5F623DCE040A4351',

  FOAMICATOR_HOSTNAME: 'chrome://foamicator',
  FOAMICATOR_HTTPREALM: 'master_password',

  STATUS: {
      'auth':       0,
      'auth_fail':  1,
      'logged_in':  2,
      'stage_fail': 3,
  },

/*********************/
/* Primary API calls */
/*********************/

  /*
   * Authenticates this addon with the remote server.
   */
  login: function () {
    if ( ! this.is_password_set()) {
      this.prompt_new_password();
    }

    if (this.is_unlocked()) {
      var domain = this.get_domain();

      // Check to see if this domain already has a key
      if (this.domain_exist(domain)) {
        // Login if the user already has a key for this site
        this.login_to_domain(domain);
      } else {
        // Create a new key and store it in the database for this domain
        this.generate_key_pair(domain);
        // Then login with the new pair
        this.login_to_domain(domain);
      }
    } else {
      this.prompt_password();
    }
  },

/*****************************/
/* Pure Javascript functions */
/*****************************/

  /*
   * Runs the ajax requests that authenticate the given key with the server.
   *
   * @param keys a hash of the public and private keys to use for encryption and decryption
   * @return none
   */
  authenticate: function(keys) {
    var foam          = this;
    // Fetch the URL to authenticate with from the page.
    var auth_url      = jQuery('input:hidden#foamicate_url', this.get_doc()).val();
    var client_random = this.get_random();
    foam.log(auth_url);

    var key_objects = {
      'public_key': forge.pki.publicKeyFromPem(keys['public_key']),
      'private_key': forge.pki.privateKeyFromPem(keys['private_key']),
    };

    // Send the public_key to the the url specified and listen for the encrypted pre_master_key
    jQuery.post(auth_url, { public_key: escape(keys['public_key']), random: client_random },
      function(data) {
          if (data['status'] === foam.STATUS['stage_fail']) {
              // The server says we were in the middle of a previous authentication so try again.
              foam.log(data['error']);
              foam.authenticate(keys);
              return;
          } else if (data['status'] === foam.STATUS['auth']) {
              //foam.log('secret: ' + data['secret']);
              // Now that we have received the server response, decrypt the pre_master_key
              var pre_master_secret = foam.decrypt(key_objects['private_key'], data['secret']);
              //foam.log('pre_master_secret: ' + pre_master_secret);
              var server_random  = foam.decrypt(key_objects['private_key'], data['random']);
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
              hashes['md5'] = foam.encrypt(key_objects['private_key'], hashes['md5']);
              hashes['sha'] = foam.encrypt(key_objects['private_key'], hashes['sha']);
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
   * Calculates the encryption key for the key pairs
   *
   * @param password the password to use
   * @return the encryption key
   */
  calculate_encryption_key: function(domain, password) {
    var first_hash = this.sha256(password + this.FOAMICATOR_ENC_KEY_SALT);
    return second_hash = this.sha256(first_hash + domain);
  },

  /*
   * Calculates the retrieval key
   *
   * @param password the password to use
   * @return the retrieval key
   */
  calculate_retrieval_key: function(password) {
    return this.sha256(password + this.FOAMICATOR_RET_KEY_SALT);
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
   * @param key the decryption key as forge key object
   * @param the encrypted data in hex
   * @return the plaintext data
   */
  decrypt: function(key, data) {
    return key.decrypt(forge.util.hexToBytes(data));
  },

  /*
   * Decrypts the hex data using the key and AES.
   *
   * @param key the decryption key as a hex string
   * @param the data in hex
   * @return the decrypted data
   */
  decrypt_aes: function(key, data) {
    var cipher = forge.aes.startDecrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(this.FOAMICATOR_SALT), null);
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(data)));
    cipher.finish();
    return this.decode_hex(cipher.output.toHex());
  },

  /*
   * Encrypts the hex data with the key.
   *
   * @param key the encryption key as forge key object
   * @param the data in hex
   * @return the encrypted data
   */
  encrypt: function(key, data) {
    return forge.util.bytesToHex(key.encrypt(forge.util.hexToBytes(data)));
  },

  /*
   * Encrypts the hex data using the key and AES.
   *
   * @param key the encryption key as a hex string
   * @param the data in hex
   * @return the encrypted data
   */
  encrypt_aes: function(key, data) {
    var cipher = forge.aes.startEncrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(this.FOAMICATOR_SALT), null);
    cipher.update(forge.util.createBuffer(this.encode_bytes(data)));
    cipher.finish();
    return cipher.output.toHex();
  },

  /*
   * Generates a public / private key pair and stores it in the database for
   * the domain
   *
   * @param domain the domain this key pair is for
   */
  generate_key_pair: function(domain) {
    // Retreive the key length and exponent values
    var key_length = this.get_i_pref("key_length");
    var exponent   = this.get_i_pref("exponent");

    var keys = forge.pki.rsa.generateKeyPair(key_length, exponent);

    var encryption_key = this.get_encryption_key();
    var encrypted_keys = {
      'publicKey': this.encrypt_aes(encryption_key, forge.pki.publicKeyToPem(keys['publicKey'])),
      'privateKey': this.encrypt_aes(encryption_key, forge.pki.privateKeyToPem(keys['privateKey'])),
    };

    this.store_key_pair(domain, encrypted_keys['publicKey'], encrypted_keys['privateKey']);
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
   * Returns true if the master password has been set before.
   *
   * @return boolean
   */
  is_password_set: function() {
    return this.get_encryption_key() !== null;
  },

  /*
   * Returns true if the master password has been entered to unlock the addon
   *
   * @return boolean
   */
  is_unlocked: function() {
    return this.retrieval_key !== null;
  },

  /*
   * The main function used to login to the website. It fetches the key pair and
   * uses them to login to the website.
   *
   * The login is handled asynchronously.
   *
   * @param domain the domain of the page to login to
   */
  login_to_domain: function(domain) {
    var foam = this;

    var decrypted_keys = this.fetch_key_pair(domain)
    if (decrypted_keys !== null) {
      this.authenticate(decrypted_keys);
    } else {
      this.log('error fetching keys');
    }
  },

  /*
   * Initializes the addon.
   */
  on_load: function() {
    // initialization code
    this.initialized = true;
    this.retrieval_key = null;

    this.init_pref();
    this.init_db();
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
   * Sets the retrieval key check if it's the right master password
   *
   * @param password the master password
   */
  unlock: function(password) {
    this.retrieval_key = this.calculate_retrieval_key(password);
    encryption_key     = this.calculate_encryption_key(password);

    if (this.get_encryption_key() !== encryption_key) {
      this.log('unlock failed');
      this.retrieval_key = null;
      this.prompt_password("Incorrect master password");
    }
    this.log('unlock passed');
  },

  /*
   * Encodes an ASCII string as hex
   *
   * @param string the string to convert
   * @return the hex encoded string
   */
  encode_hex: function(string) {
    var retval = '';
    var i = 0;
    var tmp = '';

    for(; i < string.length; i++) {
      tmp = string.charCodeAt(i).toString(16);
      if (tmp.length === 1) {
        tmp = '0' + tmp;
      } else if (tmp.length !== 2) {
        this.log('encode of: ' + string + ' produced character length of: ' + tmp.length + ' at character: ' + i);
      }
      retval += tmp;
    }
    return retval;
  },

  /*
   * Encodes a unicode string as hex
   *
   * @param string the string to convert
   * @return the hex encoded string
   */
  encode_bytes: function(string) {
    return forge.util.hexToBytes(this.encode_hex(string));
  },

  /*
   * Decodes an string from hex
   *
   * @param hex the hex string to decode
   * @return the decoded string
   */
  decode_hex: function(hex) {
    var retval = '';
    var i = 0;

    for(; i < hex.length; i+= 2) {
      retval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return retval;
  },

  /*
   * Decodes an string from bytes
   *
   * @param bytes the bytes to decode
   * @return the decoded string
   */
  decode_bytes: function(bytes) {
    return this.decode_hex(forge.util.bytesToHex(bytes));
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
    var file = FileUtils.getFile("ProfD", ["foamicator", "foamicate.sqlite"]);
    var file_exists = file.exists();
    this.db  = Services.storage.openDatabase(file);
    //if ( ! file_exists) {
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)");
      this.db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys_sites (key_id NUMERIC, site_id NUMERIC)");
    //}
  },

  /*
   * Returns the domain of the current page.
   * @return the current page's domain
   */
  get_domain: function() {
    return this.get_doc().domain;
  },

  /*
   * Returns the site_id for the domain or null if the domain wasn't found.
   *
   * @param domain the domain to get the site_id for
   * @return the site_id
   */
  get_site_id: function(domain) {
    try {
      var statement = this.db.createStatement("SELECT id FROM sites WHERE domain=:domain");
      statement.params.domain = domain;
      statement.executeStep();

      var fetched_domain = statement.row;
      if (fetched_domain.id) {
        return fetched_domain.id;
      }
    } catch (ex) {
      this.dump(ex);
      this.log(this.db.lastErrorString);
    }
    return null;
  },

  /*
   * Stores the key pair for the matching domain
   *
   * @param domain the domain associated with this key pair
   * @param public_key the public key of the pair as a forge object
   * @param private_key the private key of the pair as a forge object
   */
  store_key_pair: function(domain, public_key, private_key) {
    // First try to insert the domain if it's not already there.
    var site_id = this.get_site_id(domain);
    this.db.beginTransaction();
    if (site_id === null) {
      try {
        var statement = this.db.createStatement("INSERT OR ABORT INTO sites (domain) VALUES(:domain)");
        statement.params.domain = domain;
        statement.execute();

        site_id = this.db.lastInsertRowID;
      } catch (e) {
        if (this.db.lastErrorString !== "column domain is not unique") {
          this.log(this.db.lastErrorString);
          this.dump(e);
          this.db.rollbackTransaction();
          return;
        }
      } finally {
        statement.finalize();
      }
    }

    // Now that the domain is there, try to insert the new keys
    try {
      var statement = this.db.createStatement("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)");
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = (new Date()).getTime();
      statement.execute();

      var key_id = this.db.lastInsertRowID;
    } catch (e) {
      this.dump(e);
      this.log(this.db.lastErrorString);
      this.db.rollbackTransaction();
      return;
    } finally {
      statement.finalize();
    }

    // Last but not least, if both the domain and the keys were inserted then link them
    if (key_id !== null && site_id !== null) {
      try {
        var statement = this.db.createStatement("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)");
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        statement.execute();
      } catch (e) {
        this.dump(e);
        this.log(this.db.lastErrorString);
        this.db.rollbackTransaction();
        return;
      } finally {
        statement.finalize();
      }
    } else {
      this.db.rollbackTransaction();
      return;
    }

    // If everything was ok then commit the transaction
    this.log('key stored successfully');
    this.db.commitTransaction();

  },

  /*
   * Fetches the most recently created key pair for the given domain, decrypts them
   * using the encryption key and returns the pair as a hash.
   *
   * @param domain the domain to fetch keys for
   * @return hash of the public and private key pair or null if the domain doesn't have a key pair
   */
  fetch_key_pair: function(domain) {
    try {
      var statement = this.db.createstatement("SELECT public_key, private_key, domain FROM keys as k, sites as s, keys_sites as ks WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=':domain' ORDER BY k.created DESC");
    } catch (e) {
      this.log(this.db.lastErrorString);
      return;
    }

    try {
      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      statement.executeStep();
      var fetched_keys = statement.row;
      if (domain === fetched_keys.domain) {
        var encryption_key = this.get_encryption_key();
        key_pair = {
          'public_key': this.decrypt_aes(encryption_key, fetched_keys.public_key),
          'private_key': this.decrypt_aes(encryption_key, fetched_keys.private_key),
        };
      }
    } catch (ex) {
      key_pair = null;
    }
    statement.finalize();
    return key_pair;
  },

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  store_encryption_key: function(key) {
    var hostname = this.FOAMICATOR_HOSTNAME;
    var formSubmitURL = null;
    var httprealm = this.FOAMICATOR_HTTPREALM;
    var username = this.FOAMICATOR_USERNAME;
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
    var hostname = this.FOAMICATOR_HOSTNAME;
    var formSubmitURL = null;
    var httprealm = this.FOAMICATOR_HTTPREALM;
    var username = this.FOAMICATOR_USERNAME;
    var password = null;

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
    } catch(ex) {
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
   * Prompts the user to enter her / his master password.
   *
   * @param message optional message to use
   */
  prompt_password: function(message) {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                  .getService(Components.interfaces.nsIPromptService);
    var password = {value: null};
    var checked = {value: null};
    message = message || "Enter your master password for Foamicator";

    prompts.promptPassword(null, message, null, password, null, checked);
    if (password.value !== null) {
      this.unlock(password.value);
    }
  },

  /*
   * Prompts the user to enter a new master password.
   *
   * @param message optional message to use
   */
  prompt_new_password: function(message) {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                  .getService(Components.interfaces.nsIPromptService);
    var password = {value: null};
    var checked = {value: null};
    message = message || "Enter a master password to use for Foamicator";

    prompts.promptPassword(null, message, null, password, null, checked);
    if (password.value !== null) {
      this.store_encryption_key(this.calculate_encryption_key(password.value));
      this.unlock(password.value);
    }
  },

  /*
   * Initializes the doc attribute with the document of the current page.
   */
  get_doc: function() {
    return content.document;
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
   * Calculates the sha-256 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-256 hash
   */
  sha256: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA256);
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
