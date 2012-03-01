var Foamicator = {
  RANDOM_LENGTH: function() {
    return 28; // in bytes
  },

  SENDER_CLIENT: function() {
    return '0x434C4E54';
  },

  generate_padding: function() {
    var pad1_char = '36';
    var pad2_char = '5c';
    var pad1_md5  = '0x';
    var pad2_md5  = '0x';
    var pad1_sha  = '';
    var pad2_sha  = '';
    for (i = 0; i < 48; i++) {
      pad1_md5 += pad1_char;
      pad2_md5 += pad2_char;
      if (i === 40) {
        pad1_sha = pad1_md5;
        pad2_sha = pad2_md5;
      }
    }
    return { md5: { pad1: pad1_md5, pad2: pad2_md5 },
             sha: { pad1: pad1_sha, pad2: pad2_sha }};
  },

  on_load: function() {
    // initialization code
    this.initialized = true;
    this.logged_in = false;

    // Create the RSA object
    this.rsakey = new RSAKey();
    this.secure_random = new SecureRandom();

    rng_seed_time();

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

          // Listener for the Show value button
          var showvalue = doc.getElementById("showvalue");
          showvalue.addEventListener("click", function(e) { Foamicator.show(); }, false);
        }
      }
    };

    // Add the listener
    Services.obs.addObserver(observer, "addon-options-displayed", false);
  },

  show: function() {
    //alert(Foamicator.prefs.getCharPref("e"));
    alert(this.rsakey.decrypt('49c6b5ad967786f97d68a50026870d1967304ad12e5aba86cc6aaec9d0c39618cca6b58032e8c3704f1a0c75412b2ab8d8768acd95c931fbc17e3f1636da3ff17132eb722f3507f7a9525b954d433b945ed7a471a48e10c69ee7f1b43bfd83350afa77c0238d59d397b0c3be82a5fb243f9339bad79126510636d08b24951301'));
  },

  login: function (event) {
    if (this.logged_in === true) {
      return;
    }
    // Fetch the URL to authenticate with from the page.
    var auth_url = jQuery('form > input:hidden#foamicate_url', content.document).val();

    var username = this.prefs.getCharPref("username");

    // Generate random data
    var client_random = (new Date()).getTime() + (new BigInteger(this.RANDOM_LENGTH(), this.secure_random)).toString(16);

    var foam = this;

    var transmitted_messages = username + client_random;

    // Send the username to the the url specified and listen for the encrypted pre_master_key
    jQuery.post("http://127.0.0.1/~dan/" + auth_url, { username: username, random: client_random },
      function(data) {
        // Now that we have received the server response, decrypt the pre_master_key
        var pre_master_key = foam.rsakey.decrypt(data['key']);
        var server_random  = foam.rsakey.decrypt(data['random']);

        // Now we need to generate the master key
        var master_key = foam.calculate_master_key(pre_master_key, client_random, server_random);
        foam.log('master_key: ' + master_key);

        // Generate the validation hashes to return to the server
        transmitted_messages = transmitted_messages + master_key + server_random;
        var hashes = foam.calculate_hashes(master_key, client_random, server_random, transmitted_messages);
        foam.log('md5: ' + hashes['md5']);
        foam.log('sha: ' + hashes['sha']);
        foam.log('hashes: ' + JSON.stringify(hashes, null));
        var encrypted_hashes = foam.rsakey.doPrivate(JSON.stringify(hashes, null));
        foam.log(encrypted_hashes);
        jQuery.post("http://127.0.0.1/~dan/" + auth_url, { response: encrypted_hashes },
          function(data) {
            var redirect_url = foam.rsakey.decrypt(data['redirect_url']);
            foam.log(redirect_url);
            foam.logged_in = true;
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
    var md5 = this.md5(master_key + padding['md5']['pad2'] + this.md5(transmitted_messages + this.SENDER_CLIENT() + master_key + padding['md5']['pad1']));
    var sha = this.sha1(master_key + padding['sha']['pad2'] + this.sha1(transmitted_messages + this.SENDER_CLIENT() + master_key + padding['sha']['pad1']));
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
    this.rsakey.generate(key_length, exponent.toString());

    // Store the values generated
    this.prefs.setCharPref("priv_key", this.rsakey.d.toString(16));
    this.prefs.setCharPref("pub_key", this.rsakey.n.toString(16));
    this.prefs.setCharPref("e", this.rsakey.e.toString(16));
    this.prefs.setCharPref("p", this.rsakey.p.toString(16));
    this.prefs.setCharPref("q", this.rsakey.q.toString(16));
    this.prefs.setCharPref("dmp1", this.rsakey.dmp1.toString(16));
    this.prefs.setCharPref("dmq1", this.rsakey.dmq1.toString(16));
    this.prefs.setCharPref("coeff", this.rsakey.coeff.toString(16));
  },

  // This function loads the keys from the preferences
  load_keys: function() {
    var n     = this.prefs.getCharPref("pub_key");
    var e     = this.prefs.getCharPref("e");
    var d     = this.prefs.getCharPref("priv_key");
    var p     = this.prefs.getCharPref("p");
    var q     = this.prefs.getCharPref("q");
    var dmp1  = this.prefs.getCharPref("dmp1");
    var dmq1  = this.prefs.getCharPref("dmq1");
    var coeff = this.prefs.getCharPref("coeff");

    // Set the key
    this.rsakey.setPrivateEx(n, e, d, p, q, dmp1, dmq1, coeff);
  },
};

// Setup the initializer
window.addEventListener("load", function(e) { Foamicator.on_load(e); }, false);
