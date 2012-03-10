var Foamicator = {
  RANDOM_LENGTH: 28, // in bytes

  SENDER_CLIENT: '0x434C4E54',

  STATUS: {
      'auth':       0,
      'auth_fail':  1,
      'logged_in':  2,
      'stage_fail': 3,
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
   * Decrypts the hex data with the private key.
   */
  decrypt: function(data) {
    return this.private_key.decrypt(forge.util.hexToBytes(data));
  },

  /*
   * Encrypts the hex data with the private key.
   */
  encrypt: function(data) {
    return forge.util.bytesToHex(this.private_key.encrypt(forge.util.hexToBytes(data)));
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
    this.init_doc();
    // Fetch the URL to authenticate with from the page.
    var auth_url      = jQuery('input:hidden#foamicate_url', this.doc).val();
    var public_key    = this.get_c_pref("pub_key");
    var client_random = this.get_random();
    var foam          = this;
    foam.log(auth_url);

    // Send the public_key to the the url specified and listen for the encrypted pre_master_key
    jQuery.post(auth_url, { public_key: escape(public_key), random: client_random },
      function(data) {
          if (data['status'] === foam.STATUS['stage_fail']) {
              // The server says we were in the middle of a previous authentication so try again.
              foam.log(data['error']);
              foam.login(event);
              return;
          } else if (data['status'] === foam.STATUS['auth']) {
              //foam.log('secret: ' + data['secret']);
              // Now that we have received the server response, decrypt the pre_master_key
              var pre_master_secret = foam.decrypt(data['secret']);
              //foam.log('pre_master_secret: ' + pre_master_secret);
              var server_random  = foam.decrypt(data['random']);
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
              hashes['md5'] = foam.encrypt(hashes['md5']);
              hashes['sha'] = foam.encrypt(hashes['sha']);
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
              foam.log('Status not support: ' + data['status']);
          }
    }, 'json').fail(foam.output_fail);
  },

  /*
   * Initializes the addon.
   */
  on_load: function() {
    // initialization code
    this.initialized = true;

    this.init_pref();
    this.init_doc();

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
   * Outputs the error mesasge if the post request failed.
   * TODO: change to not use alerts
   */
  output_fail: function(msg, textStatus, errorThrown) {
    alert(msg.status + ";" + msg.statusText + ";" + msg.responseXML);
  },





/******************************/
/* Browser Specific Functions */
/******************************/

  init_listener: function() {
    var observer = {
      observe: function(aSubject, aTopic, aData) {
        // If this addon's option page is displayed
        if (aTopic == "addon-options-displayed" && aData == "foamicate@github.com") {
          var doc = aSubject;

          // Listener for the generate keys button
          var control = doc.getElementById("genbutton");
          control.addEventListener("click", function(e) { Foamicator.generate_keys(); }, false);
        }
      }
    };

    // Add the listener
    Services.obs.addObserver(observer, "addon-options-displayed", false);
  },

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

  log: function(aMessage) {
      var console = Components.classes['@mozilla.org/consoleservice;1'].
                getService(Components.interfaces.nsIConsoleService);
      console.logStringMessage('Foamicator: ' + aMessage);
  },

  md5: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.MD5);
    return this.hash(ch, string);
  },

  sha1: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA1);
    return this.hash(ch, string);
  },

  sha512: function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA512);
    return this.hash(ch, string);
  },

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

// Setup the initializer
window.addEventListener("load", function(e) { Foamicator.on_load(e); }, false);
