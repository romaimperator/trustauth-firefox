/**
 * This is the main code for the TrustAuth addon.
 *
 * @author Daniel Fox
 * @link trustauth.com
 * @license BSD-3 Clause License http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2012, Daniel Fox
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *     Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *     Neither the name of TrustAuth nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
(function() {

if (typeof(window) !== "undefined") {

window.TrustAuth = function() {
  var TRUSTAUTH_ENC_KEY_SALT = '2EEC776BE2291D76E7C81706BD0E36C0C10D62A706ADB12D2799CA731503FBBA';
  var TRUSTAUTH_STORAGE_SALT = '7CAB8505B677344B34B83C77B6A3EF527DC31FEFDF531B9F5F623DCE040A4351';

  var TRUSTAUTH_AJAX_LOADER = 'chrome://trustauth/skin/ajax-loader.gif';
  var TRUSTAUTH_BUTTON      = 'chrome://trustauth/skin/button.png';
  var TRUSTAUTH_DISABLED    = 'chrome://trustauth/skin/button-disabled.png';

  var TOKEN_NAME_CSS = "[name='csrf-param']";
  var AUTH_TOKEN_CSS = "[name='csrf-token']";

  var initialized = false;
  var disabled    = false;
  var prefs       = null;

  var encryption_key = null;

/*****************/
/* TrustAuth 1.0 */
/*****************/

    /**
     * This function is called whenever a page is loaded and has an element with
     * and ID of "trustauth-challenge". If there is a key already generated for this
     * site then the key is used to encrypte the random value in this field. The random
     * value is placed into the value attribute of the element that contained the challenge.
     *
     * If there is not a key for this site then the addon does nothing.
     */
    var encrypt_login = function() {
      if (is_unlocked()) {
        var domain = get_domain();
        if (domain_exist(domain)) {
          var challenge_element = get_doc().getElementById("trustauth-challenge");

          disable_child_submit(challenge_element.parentNode);

          var keys = fetch_key_pair(domain);
          var private_key = forge.pki.privateKeyFromPem(keys['private_key']);

          get_doc().getElementById("trustauth-challenge").value = encrypt(private_key, challenge_element.value);
          enable_child_submit(challenge_element.parentNode);
        }
      }
    };

    /**
     * Disables all of the submit buttons that are a child of the given element.
     *
     * @param {HTMLElement} parent the element containing submit buttons to disable
     */
    var disable_child_submit = function(parent) {
      var buttons = parent.getElementsByTagName("button");

      for (i in buttons) {
        if (buttons[i].getAttribute("type") == "submit") {
          buttons[i].disabled = true;
        }
      }
    };


    /**
     * Enables all of the submit buttons that are a child of the given element.
     *
     * @param {HTMLElement} parent the element containing submit buttons to enable
     */
    var enable_child_submit = function(parent) {
      var buttons = parent.getElementsByTagName("button");

      for (i in buttons) {
        if (buttons[i].getAttribute("type") == "submit") {
          buttons[i].disabled = false;
        }
      }
    };

    /**
     * This function is called to bind a click listener to the Add TrustAuth Key button.
     */
    var add_key_listener = function() {
      log("called add_key_listener");
      if (is_unlocked()) {
        get_doc().getElementById("trustauth-register").addEventListener("click", add_trustauth_key, true);
      }
    };

    /**
     * This function injects the public key into a hidden form field with an ID of
     * "trustauth-key" whenever the Add TrustAuth Key button is clicked.
     */
    var add_trustauth_key = function() {
      log("called add_trustauth_key");
      if (is_unlocked()) {
        var register_element = get_doc().getElementById("trustauth-register");

        register_element.removeEventListener("click", add_trustauth_key, true);
        disable_child_submit(register_element.parentNode);

        var domain = get_domain();
        if (domain_exist(domain)) {
          var keys = fetch_key_pair(domain);
          get_doc().getElementById("trustauth-key").value = keys['public_key'];
        } else {
          // Grab the cached key and setup a submit listener
        }
        enable_child_submit(register_element.parentNode);
      }
    };

  /**
   * Executes after the addon is unlocked. Used to encrypt the login challenge and bind the button.
   */
  var after_unlock = function() {
    encrypt_login();
    add_key_listener();
  };

/*********************/
/* Primary API calls */
/*********************/

    /*
     * Authenticates this addon with the remote server.
     */
    var login = function () {
      if ( ! disabled) {
        if ( ! is_password_set()) {
          prompt_new_password();
        } else {
          if (is_unlocked()) {
            var domain = get_domain();

            // Check to see if this domain already has a key
            if (domain_exist(domain)) {
              // Login if the user already has a key for this site
              login_to_domain(domain);
            } else {
              // Create a new key and store it in the database for this domain
              generate_key_pair(domain);
              // Then login with the new pair
              login_to_domain(domain);
            }
          } else {
            if (prompt_password()) {
              login();
            }
          }
        }
      }
    };

/*****************************/
/* Pure Javascript functions */
/*****************************/

  /*
   * Runs the ajax requests that authenticate the given key with the server.
   *
   * @param keys a hash of the public and private keys to use for encryption and decryption
   * @return none
   */
  var authenticate = function(keys) {
    // Fetch the URL to authenticate with from the page.
    var auth_url      = get_auth_url();
    var client_random = get_random();
    var token_name    = jQuery(TOKEN_NAME_CSS, get_doc()).attr('content');
    var auth_token    = jQuery(AUTH_TOKEN_CSS, get_doc()).attr('content');
    //log(auth_token);
    //log(auth_url);

    var key_objects = {
      'public_key': forge.pki.publicKeyFromPem(keys['public_key']),
      'private_key': forge.pki.privateKeyFromPem(keys['private_key']),
    };

    // Send the public_key to the the url specified and listen for the encrypted pre_master_key
    var params = { public_key: escape(keys['public_key']), random: client_random };
    params[token_name] = auth_token;
    jQuery.post(auth_url, params,
      function(data) {
          //log('first:' + JSON.stringify(data, null));
          if (data['status'] === STATUS['stage_fail']) {
              // The server says we were in the middle of a previous authentication so try again.
              log(data['error']);
              authenticate(keys);
              return;
          } else if (data['status'] === STATUS['auth']) {
              auth_url = isset(data['auth_response_url']) ? data['auth_response_url'] : auth_url;
              //log(auth_url);
              //foam.log('secret: ' + data['secret']);
              // Now that we have received the server response, decrypt the pre_master_key
              var pre_master_secret = decrypt(key_objects['private_key'], data['secret']);
              //foam.log('pre_master_secret: ' + pre_master_secret);
              var server_random  = decrypt(key_objects['private_key'], data['random']);
              //foam.log('user random: ' + client_random);
              //foam.log('server random: ' + server_random);

              // Now we need to generate the master secret
              var master_secret = get_master_secret(pre_master_secret, client_random, server_random);
              //foam.log('master_secret: ' + master_secret);

              // Generate the validation hashes to return to the server
              var transmitted_messages = client_random + master_secret + server_random;
              //foam.log('transmitted_messages: ' + transmitted_messages);

              var hashes = get_hashes(master_secret, client_random, server_random, transmitted_messages);
              //foam.log('md5: ' + hashes['md5']);
              //foam.log('sha: ' + hashes['sha']);
              hashes['md5'] = encrypt(key_objects['private_key'], hashes['md5']);
              hashes['sha'] = encrypt(key_objects['private_key'], hashes['sha']);
              //foam.log('hashes: ' + JSON.stringify(hashes, null));
              params = { md5: hashes['md5'], sha: hashes['sha'] }
              params[token_name] = auth_token;
              jQuery.post(auth_url, params,
                function(data) {
                    //log('second:' + JSON.stringify(data, null));
                    if (data['status'] === STATUS['auth_fail']) {
                        log(data['error']);
                    } else if (data['status'] === STATUS['logged_in']) {
                        log('login successful');
                    }
                    //log('redirect url: ' + data['url']);
                    openUILinkIn(data['url'], 'current');
              }, 'json').fail(output_fail);
          } else {
              log('Status not supported: ' + data['status']);
          }
    }, 'json').fail(output_fail);
  };

  /*
   * Calculates the encryption key for the key pairs
   *
   * @param password the password to use
   * @return the encryption key
   */
  var calculate_encryption_key = function(password) {
    return sha256(password + TRUSTAUTH_ENC_KEY_SALT);
  };

  /*
   * Checks to see if the site supports TrustAuth. It enables the addon if it
   * does and disables the addon if it doesn't.
   */
  var check_page = function() {
      if (typeof(get_auth_url()) != "undefined") {
        enable();
      } else {
        disable();
      }
  };

  /*
   * Decodes an string from bytes
   *
   * @param bytes the bytes to decode
   * @return the decoded string
   */
  var decode_bytes = function(bytes) {
    return decode_hex(forge.util.bytesToHex(bytes));
  };

  /*
   * Decodes an string from hex
   *
   * @param hex the hex string to decode
   * @return the decoded string
   */
  var decode_hex = function(hex) {
    var retval = '';
    var i = 0;

    for(; i < hex.length; i+= 2) {
      retval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return retval;
  };

  /*
   * Decrypts the hex data with the key.
   *
   * @param key the decryption key as forge key object
   * @param the encrypted data in hex
   * @return the plaintext data
   */
  var decrypt = function(key, data) {
    return key.decrypt(forge.util.hexToBytes(data));
  };

  /*
   * Decrypts the hex data using the key and AES.
   *
   * @param key the decryption key as a hex string
   * @param the data in hex
   * @return the decrypted data
   */
  var decrypt_aes = function(key, data) {
    var cipher = forge.aes.startDecrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(TRUSTAUTH_ENC_KEY_SALT), null);
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(data)));
    cipher.finish();
    return decode_hex(cipher.output.toHex());
  };

  /*
   * Encodes a unicode string as hex
   *
   * @param string the string to convert
   * @return the hex encoded string
   */
  var encode_bytes = function(string) {
    return forge.util.hexToBytes(encode_hex(string));
  };

  /*
   * Encodes an ASCII string as hex
   *
   * @param string the string to convert
   * @return the hex encoded string
   */
  var encode_hex = function(string) {
    var retval = '';
    var i = 0;
    var tmp = '';

    for(; i < string.length; i++) {
      tmp = string.charCodeAt(i).toString(16);
      if (tmp.length === 1) {
        tmp = '0' + tmp;
      } else if (tmp.length !== 2) {
        log('encode of: ' + string + ' produced character length of: ' + tmp.length + ' at character: ' + i);
      }
      retval += tmp;
    }
    return retval;
  };

  /*
   * Encrypts the hex data with the key.
   *
   * @param key the encryption key as forge key object
   * @param the data in hex
   * @return the encrypted data
   */
  var encrypt = function(key, data) {
    return forge.util.bytesToHex(key.encrypt(forge.util.hexToBytes(data)));
  };

  /*
   * Encrypts the hex data using the key and AES.
   *
   * @param key the encryption key as a hex string
   * @param the data in hex
   * @return the encrypted data
   */
  var encrypt_aes = function(key, data) {
    var cipher = forge.aes.startEncrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(TRUSTAUTH_ENC_KEY_SALT), null);
    cipher.update(forge.util.createBuffer(encode_bytes(data)));
    cipher.finish();
    return cipher.output.toHex();
  };

  /*
   * Generates a public / private key pair and stores it in the database for
   * the domain
   *
   * @param domain the domain this key pair is for
   */
  var generate_key_pair = function(handle_keys) {
    // Retreive the key length and exponent values
    var key_length = get_i_pref("key_length");
    var exponent   = get_i_pref("exponent");

    var worker = new Worker('chrome://trustauth/content/generate_key_pair.js');
    worker.onerror   = function(event) {
      log('error: ' + event.message);
    };
    worker.onmessage = function(event) {
      handle_keys({
        'publicKey':  forge.pki.publicKeyFromPem(event.data['publicKey']),
        'privateKey': forge.pki.privateKeyFromPem(event.data['privateKey']),
      });
    };
    worker.postMessage({'key_length':key_length, 'exponent':exponent});
  };

  /*
   * Returns the authentication url from the webpage if it exists.
   */
  var get_auth_url = function() {
    //var auth_ele = jQuery('input:hidden#foamicate_url', get_doc());
    var auth_ele = jQuery("meta[name='trustauth']", get_doc());
    if (typeof(auth_ele) != "undefined") {
      return 'http://' + get_domain() + auth_ele.attr('content');
    } else {
      return auth_ele;
    }
  };

  var get_encryption_key = function() {
    return encryption_key;
  };

  /*
   * Returns a hash of the encryption key that is safe to store for
   * password verification.
   *
   * @param encryption_key the key to get a storage hash of
   * @return the hash of the key
   */
  var get_storage_hash = function(encryption_key) {
    return sha256(encryption_key + TRUSTAUTH_STORAGE_SALT);
  };

  /*
   * Generate random data for the authentication process
   *
   * @return hex string of random data
   */
  var get_random = function() {
      var byte_buffer = forge.util.createBuffer();
      byte_buffer.putInt32((new Date()).getTime());
      byte_buffer.putBytes(forge.random.getBytes(RANDOM_LENGTH));
      return byte_buffer.toHex();
  };

  /*
   * Checks to see if the variable is set.
   *
   * @param variable the variable to check
   * @return true if it is, false otherwise
   */
  var isset = function(variable) {
      return typeof(variable) != "undefined" && variable !== null;
  };

  /*
   * Returns true if the master password has been set before.
   *
   * @return boolean
   */
  var is_password_set = function() {
    return get_stored_hash() !== null;
  };

  /*
   * Returns true if the master password has been entered to unlock the addon
   *
   * @return boolean
   */
  var is_unlocked = function() {
    return get_encryption_key() !== null;
  };

  /*
   * The main function used to login to the website. It fetches the key pair and
   * uses them to login to the website.
   *
   * The login is handled asynchronously.
   *
   * @param domain the domain of the page to login to
   */
  var login_to_domain = function(domain) {
    var decrypted_keys = fetch_key_pair(domain)
    if (decrypted_keys !== null) {
      authenticate(decrypted_keys);
    } else {
      log('error fetching keys');
    }
  };

  /*
   * Initializes the addon.
   */
  var on_load = function() {
    // initialization code
    initialized = true;

    init_pref();
    init_db();
    init_listener();
    set_button_image(TRUSTAUTH_BUTTON);

    if (get_b_pref('first_run')) {
      set_b_pref('first_run', false);
      install_button("nav-bar", "trustauth-main-button");
      // The "addon-bar" is available since Firefox 4
      install_button("addon-bar", "trustauth-main-button");
    }
  };

  /*
   * Runs whenever a page is finished loading.
   */
  var on_page_load = function(event) {
    if (event.originalTarget instanceof HTMLDocument) {
      var win = event.originalTarget.defaultView;
      if (win.frameElement) {
        return;
      } else {
        add_key_listener();
        encrypt_login();
      }
    }
  };

  /*
   * Outputs the error mesasge if the post request failed.
   */
  var output_fail = function(msg, textStatus, errorThrown) {
    log(msg.status + ";" + msg.statusText + ";" + msg.responseXML);
  };





/******************************/
/* Browser Specific Functions */
/******************************/

  /*
   * Connects to the database.
   */
  var db_connect = function() {
    Components.utils.import("resource://gre/modules/Services.jsm");
    Components.utils.import("resource://gre/modules/FileUtils.jsm");

    // Establish a connection to the database
    var file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
    var file_exists = file.exists();
    return Services.storage.openDatabase(file);
  };

  /*
   * Disables the addon and grays out the button and text.
   */
  var disable = function() {
    disabled = true;
    set_button_image(TRUSTAUTH_DISABLED);
    jQuery('#trustauth-menu-login', document).addClass('trustauth-disabled');
  };

  /*
   * Checks to see if the given domain has a key in the database
   *
   * @param domain the domain to look for
   * @return true if the domain is in the database false otherwise
   */
  var domain_exist = function(domain) {
    var db = db_connect();

    var domain_exists = false;
    try {
      // Create the statement to fetch the most recently created key for this domain
      var statement = db.createStatement("SELECT domain FROM keys, sites, keys_sites WHERE keys.id=keys_sites.key_id AND sites.id=keys_sites.site_id AND sites.domain=:domain ORDER BY keys.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        domain_exists = domain === statement.row.domain;
      }
    } catch (ex) {
      dump(ex);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
    }

    db.close();
    return domain_exists;
  };

  /*
   * A debugging function used to try and dump an object to the log
   *
   * @param obj the object to dump
   */
  var dump = function(obj) {
    var out = '';
    for (var i in obj) {
        out += i + ": " + obj[i] + "\n";
    }

    log(out);
  };

  /*
   * Disables the addon and grays out the button and text.
   */
  var enable = function() {
    disabled = false;
    set_button_image(TRUSTAUTH_BUTTON);
    jQuery('#trustauth-menu-login', document).removeClass('trustauth-disabled');
  };

  /*
   * Fetches the most recently created key pair for the given domain, decrypts them
   * using the encryption key and returns the pair as a hash.
   *
   * @param domain the domain to fetch keys for
   * @return hash of the public and private key pair or null if the domain doesn't have a key pair
   */
  var fetch_key_pair = function(domain) {
    var db = db_connect();

    var key_pair = null;
    try {
      var statement = db.createStatement("SELECT k.id, public_key, private_key FROM keys as k, sites as s, keys_sites as ks WHERE k.id=ks.key_id AND s.id=ks.site_id AND s.domain=:domain ORDER BY k.created DESC");

      // Bind the parameter
      statement.params.domain = domain;

      // Execute the query synchronously
      if (statement.executeStep()) {
        var encryption_key = get_encryption_key();
        key_pair = {
          'id': statement.row.id,
          'public_key': decrypt_aes(encryption_key, statement.row.public_key),
          'private_key': decrypt_aes(encryption_key, statement.row.private_key),
        };
      }
    } catch (ex) {
      dump(ex);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
    }

    db.close();
    return key_pair;
  };

  var get_b_pref = function(preference) {
      return prefs.getBoolPref(preference);
  };

  var get_c_pref = function(preference) {
      return prefs.getCharPref(preference);
  };

  /*
   * Initializes the doc attribute with the document of the current page.
   */
  var get_doc = function() {
    return content.document;
  };

  /*
   * Returns the domain of the current page.
   * @return the current page's domain
   */
  var get_domain = function() {
    return get_doc().domain;
  };

  var get_i_pref = function(preference) {
      return prefs.getIntPref(preference);
  };

  /**
   * Retrieves the hash stored in the database.
   *
   * @return {string} the hash if there is one, null otherwise
   */
  var get_stored_hash = function() {
    var db = db_connect();

    var hash = null;
    try {
      var statement = db.createStatement("SELECT hash FROM password_verify LIMIT 1");

      if (statement.executeStep()) {
        hash = statement.row.hash;
        log('hash: ' + hash);
      }
    } catch(ex) {
      dump(ex);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return hash;
  };

  /*
   * Returns the site_id for the domain or null if the domain wasn't found.
   *
   * @param domain the domain to get the site_id for
   * @return the site_id
   */
  var get_site_id = function(domain) {
    var db = db_connect();

    var row_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM sites WHERE domain=:domain");
      statement.params.domain = domain;
      if (statement.executeStep()) {
        row_id = statement.row.id;
      }
    } catch (ex) {
      dump(ex);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
    }

    db.close();
    return row_id;
  };

  /*
   * The abstract function to use the firefox object to calculate the hash
   * using the browser function instead of a javascript function.
   *
   * @param ch the crypto hash object initalized to the correct hash function
   * @param string the string to hash
   * @return the calculated hash
   */
  var hash = function(ch, string) {
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
  };

  /*
   * Initializes the place to store the public and private key pairs.
   */
  var init_db = function() {
    var db = db_connect();

    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, public_key TEXT, private_key TEXT, created TEXT)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS sites (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS keys_sites (key_id NUMERIC, site_id NUMERIC)");
    db.executeSimpleSQL("CREATE TABLE IF NOT EXISTS password_verify (hash TEXT)");

    db.close();
  };

  /*
   * Initializes the javascript listeners for the buttons on the preference page.
   */
  var init_listener = function() {
    gBrowser.tabContainer.addEventListener("TabAttrModified", tab_modified, false);
    gBrowser.addEventListener("load", on_page_load, true);
    document.getElementById('trustauth-menu-login').addEventListener("click", login, false);
  };

  // Fetch the preferences for the addon
  var init_pref = function() {
    prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefService).getBranch("extensions.trustauth.");
  };

  /**
   * Installs the toolbar button with the given ID into the given
   * toolbar, if it is not already present in the document.
   *
   * @param {string} toolbarId The ID of the toolbar to install to.
   * @param {string} id The ID of the button to install.
   * @param {string} afterId The ID of the element to insert after. @optional
   */
  var install_button = function(toolbarId, id, afterId) {
      if (!document.getElementById(id)) {
          var toolbar = document.getElementById(toolbarId);

          // If no afterId is given, then append the item to the toolbar
          var before = null;
          if (afterId) {
              let elem = document.getElementById(afterId);
              if (elem && elem.parentNode == toolbar)
                  before = elem.nextElementSibling;
          }

          toolbar.insertItem(id, before);
          toolbar.setAttribute("currentset", toolbar.currentSet);
          document.persist(toolbar.id, "currentset");

          if (toolbarId == "addon-bar")
              toolbar.collapsed = false;
      }
  };

  /*
   * Logs a message to the console as a TrustAuth message.
   *
   * @param aMessage the message to log
   */
  var log = function(aMessage) {
      var console = Components.classes['@mozilla.org/consoleservice;1'].
                getService(Components.interfaces.nsIConsoleService);
      console.logStringMessage('TrustAuth: ' + aMessage);
  };

  /*
   * Calculates the md5 hash of the given string
   *
   * @param string the string to hash
   * @return the md5 hash
   */
  var md5 = function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.MD5);
    return hash(ch, string);
  };

  /*
   * Prompts the user to enter a new master password.
   *
   * @param message optional message to use
   */
  var prompt_new_password = function(message) {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                  .getService(Components.interfaces.nsIPromptService);
    var password = {value: null};
    var checked = {value: null};
    message = message || "Please enter a master password to use for TrustAuth:";

    prompts.promptPassword(null, message, null, password, null, checked);
    if (password.value !== null) {
      encryption_key = calculate_encryption_key(password.value);
      store_encryption_key(encryption_key);
    }
  };

  /*
   * Prompts the user to enter her / his master password until the correct password
   * is entered or the user cancels the prompt.
   *
   * @return true if the user entered the correct password, false otherwise
   */
  var prompt_password = function() {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                  .getService(Components.interfaces.nsIPromptService);
    var password = {value: null};
    var checked = {value: null};

    if (prompts.promptPassword(null, "Enter your master password for TrustAuth:", null, password, null, checked)) {
      while ( ! verify_password(password.value)) {
        if ( ! prompts.promptPassword(null, "Incorrect master password", null, password, null, checked)) return false;
      }
      encryption_key = calculate_encryption_key(password.value);
      after_unlock();
      return true;
    }
    return false;
  };

  var set_b_pref = function(preference, value) {
      prefs.setBoolPref(preference, value);
  };

  /*
   * This function sets the button image on the toolbar.
   *
   * @param image the image url to change the image to
   */
  var set_button_image = function(image) {
    jQuery('#trustauth-main-button', document).attr('image', image);
  };

  /*
   * This function changes the label of the main button to text.
   *
   * @param text the text to change the button to.
   */
  var set_status = function(text) {
    document.getElementById('trustauth-status').value = text;
  };

  var set_c_pref = function(preference, value) {
      prefs.setCharPref(preference, value);
  };

  var set_i_pref = function(preference, value) {
      prefs.setIntPref(preference, value);
  };

  /*
   * Calculates the sha-1 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-1 hash
   */
  var sha1 = function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA1);
    return hash(ch, string);
  };

  /*
   * Calculates the sha-256 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-256 hash
   */
  var sha256 = function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA256);
    return hash(ch, string);
  };

  /*
   * Calculates the sha-512 hash of the given string
   *
   * @param string the string to hash
   * @return the sha-512 hash
   */
  var sha512 = function(string) {
    // Get the hash function object
    var ch = Components.classes["@mozilla.org/security/hash;1"]
                   .createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA512);
    return hash(ch, string);
  };

  /*
   * Prompts the user with the password dialog.
   *
   * NOTE: currently not in use.
   */
  var show_master_password_dialog = function() {
    var win = window.openDialog("chrome://trustauth/content/password_dialog.xul",
                      "trustauthPasswordDialog", "chrome,centerscreen");
  };

  /*
   * This function stores the key in the browser's password manager
   *
   * @param key the key to store
   */
  var store_encryption_key = function(key) {
    var success = false;
    if (! is_password_set()) {
      var db = db_connect();

      try {
        var statement = db.createStatement("INSERT OR ABORT INTO password_verify (hash) VALUES(:hash)");
        statement.params.hash = get_storage_hash(key);

        success = statement.executeStep();
      } catch (ex) {
        dump(ex);
        log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }

    }
    return success;
  };

  /*
   * Stores the key pair for the matching domain
   *
   * @param domain the domain associated with this key pair
   * @param public_key the public key of the pair as a forge object
   * @param private_key the private key of the pair as a forge object
   */
  var store_key_pair = function(domain, public_key, private_key) {
    var db = db_connect();

    // First try to insert the domain if it's not already there.
    var site_id = get_site_id(domain);
    db.beginTransaction();
    if (site_id === null) {
      try {
        var statement = db.createStatement("INSERT OR ABORT INTO sites (domain) VALUES(:domain)");
        statement.params.domain = domain;
        statement.execute();

        site_id = db.lastInsertRowID;
      } catch (e) {
        if (db.lastErrorString !== "column domain is not unique") {
          log(db.lastErrorString);
          dump(e);
          db.rollbackTransaction();

          db.close();
          return;
        }
      } finally {
        statement.finalize();
      }
    }
    log('site_id: ' + site_id);

    // Now that the domain is there, try to insert the new keys
    try {
      var statement = db.createStatement("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)");
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = (new Date()).getTime();
      statement.execute();

      var key_id = db.lastInsertRowID;
      log('key_id: ' + key_id);
    } catch (e) {
      dump(e);
      log(db.lastErrorString);
      db.rollbackTransaction();

      db.close();
      return;
    } finally {
      statement.finalize();
    }

    // Last but not least, if both the domain and the keys were inserted then link them
    if (key_id !== null && site_id !== null) {
      try {
        var statement = db.createStatement("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)");
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        log('combo result: ' + statement.executeStep());
      } catch (e) {
        dump(e);
        log(db.lastErrorString);
        db.rollbackTransaction();

        db.close();
        return;
      } finally {
        statement.finalize();
      }
    } else {
      db.rollbackTransaction();
      return;
    }

    // If everything was ok then commit the transaction
    log('key stored successfully');
    db.commitTransaction();

    db.close();
  };

  /*
   * Triggered when any attribute changes on a tab.
   */
  var tab_modified = function(event) {
    if (event.target.selected) {
      check_page();
    }
  };

  /**
   * Verifies that the password given is the correct password.
   *
   * @param {string} password the password to check
   * @return {bool} true if it is, false otherwise
   */
  var verify_password = function(password) {
    var hash = get_stored_hash();

    log('checking hash: ' + get_storage_hash(calculate_encryption_key(password)));
    return (hash !== null && hash === get_storage_hash(calculate_encryption_key(password)));
  };

  // Initialize the TrustAuth object
  window.addEventListener("load", function on_load_call(e) {
    this.removeEventListener("load", on_load_call, false);
    on_load(e);
  }, false);

}();

}

})();

