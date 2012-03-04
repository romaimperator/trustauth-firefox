var Foamicator = {
  RANDOM_LENGTH: 28, // in bytes

  SENDER_CLIENT: '0x434C4E54',

  generate_padding: function() {
    var pad1_md5 = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x36), 48));
    var pad2_md5 = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x5c), 48));
    var pad1_sha = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x36), 40));
    var pad2_sha = forge.util.bytesToHex(forge.util.fillString(String.fromCharCode(0x5c), 40));
    //this.log('md5 pad1: ' + pad1_md5 + ' md5 pad2: ' + pad2_md5);
    //this.log('sha pad1: ' + pad1_sha + ' sha pad2: ' + pad2_sha);
    return { md5: { pad1: pad1_md5, pad2: pad2_md5 },
             sha: { pad1: pad1_sha, pad2: pad2_sha }};
  },

  on_load: function() {
    // initialization code
    this.initialized = true;

    // Fetch the preferences for the addon
    this.prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.foamicator.");

    // Check if this is the first run and generate keys if it is
    this.first_run = this.prefs.getBoolPref("first_run");
    if (this.first_run === true) {
      this.prefs.setBoolPref("first_run", false);
      this.generate_keys();
    } else {
      // Otherwise load the keys from the preferences
      this.load_keys();
    }

    // Setup the listeners
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

  submit_public_key: function() {
      jQuery('textarea#foamicate_public_key', content.document).val(this.prefs.getCharPref('pub_key'));
  },

  login: function (event) {
    // Fetch the URL to authenticate with from the page.
    var auth_url = jQuery('form > input:hidden#foamicate_url', content.document).val();

    var username = this.prefs.getCharPref("username");

    // Generate random data
    var byte_buffer = forge.util.createBuffer();
    byte_buffer.putInt32((new Date()).getTime());
    byte_buffer.putBytes(forge.random.getBytes(this.RANDOM_LENGTH));
    var client_random = byte_buffer.toHex();

    var foam = this;

    var transmitted_messages = username + client_random;

    // Send the username to the the url specified and listen for the encrypted pre_master_key
    jQuery.post("http://127.0.0.1/~dan/" + auth_url, { username: username, random: client_random },
      function(data) {
        //foam.log('request returned');
        // Now that we have received the server response, decrypt the pre_master_key
        var pre_master_key = foam.private_key.decrypt(forge.util.hexToBytes(data['key']));
        //foam.log('done with pre_master_key');
        var server_random  = foam.private_key.decrypt(forge.util.hexToBytes(data['random']));
        //foam.log('after decryption');

        // Now we need to generate the master key
        var master_key = foam.calculate_master_key(pre_master_key, client_random, server_random);
        //foam.log('master_key: ' + master_key);

        // Generate the validation hashes to return to the server
        transmitted_messages = transmitted_messages + master_key + server_random;
        var padding = foam.generate_padding();
        //foam.log('first md5: ' + transmitted_messages + foam.SENDER_CLIENT + master_key + padding['md5']['pad1']);
        var hashes = foam.calculate_hashes(master_key, client_random, server_random, transmitted_messages);
        //foam.log('md5: ' + hashes['md5']);
        //foam.log('sha: ' + hashes['sha']);
        hashes['md5'] = forge.util.bytesToHex(foam.private_key.encrypt(forge.util.hexToBytes(hashes['md5'])));
        hashes['sha'] = forge.util.bytesToHex(foam.private_key.encrypt(forge.util.hexToBytes(hashes['sha'])));
        //foam.log('hashes: ' + JSON.stringify(hashes, null));
        jQuery.post("http://127.0.0.1/~dan/" + auth_url, { md5: hashes['md5'], sha: hashes['sha'] },
          function(data) {
            var redirect_url = foam.private_key.decrypt(forge.util.hexToBytes(data['redirect_url']));
            foam.log(redirect_url);
            openUILinkIn(redirect_url, 'current');
        }, 'json').fail(function(msg, textStatus, errorThrown) { alert('second' + msg.status + ";" + msg.statusText + ";" + msg.responseXML); });

    }, 'json').fail(function(msg, textStatus, errorThrown) { alert(msg.status + ";" + msg.statusText + ";" + msg.responseXML); });
  },

  log: function(aMessage) {
      var console = Components.classes['@mozilla.org/consoleservice;1'].
                getService(Components.interfaces.nsIConsoleService);
      console.logStringMessage('Foamicator: ' + aMessage);
  },

  calculate_hashes: function(master_key, client_random, server_random, transmitted_messages) {
    var padding = this.generate_padding();
    var md5 = this.md5(master_key + padding['md5']['pad2'] + this.md5(transmitted_messages + this.SENDER_CLIENT + master_key + padding['md5']['pad1']));
    var sha = this.sha1(master_key + padding['sha']['pad2'] + this.sha1(transmitted_messages + this.SENDER_CLIENT + master_key + padding['sha']['pad1']));
    return { md5: md5, sha: sha };
  },

  calculate_master_key: function(pre_master_key, client_random, server_random) {
    return this.md5(pre_master_key + this.sha1('A' + pre_master_key + client_random + server_random)) +
           this.md5(pre_master_key + this.sha1('BB' + pre_master_key + client_random + server_random)) +
           this.md5(pre_master_key + this.sha1('CCC' + pre_master_key + client_random + server_random));
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

  generate_keys: function() {
    // Retreive the key length and exponent values
    var key_length = this.prefs.getIntPref("key_length");
    var exponent   = this.prefs.getIntPref("exponent");

    // Generate the key
    var keys = forge.pki.rsa.generateKeyPair(key_length, exponent);

    this.public_key  = keys['publicKey'];
    this.private_key = keys['privateKey'];

    // Store the values generated
    this.prefs.setCharPref("pub_key", forge.pki.publicKeyToPem(this.public_key));
    this.prefs.setCharPref("priv_key", forge.pki.privateKeyToPem(this.private_key));
  },

  // This function loads the keys from the preferences
  load_keys: function() {
    this.private_key = forge.pki.privateKeyFromPem(this.prefs.getCharPref("priv_key"));
    this.public_key  = forge.pki.publicKeyFromPem(this.prefs.getCharPref("pub_key"));
  },
};

// Setup the initializer
window.addEventListener("load", function(e) { Foamicator.on_load(e); }, false);
