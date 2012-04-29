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

  var initialized = false;
  var disabled    = false;
  var prefs       = null;

  var encryption_key = null;

/*****************************/
/* Pure Javascript functions */
/*****************************/

  /**
   * Adds a listener to all submit buttons that are children of parent.
   *
   * @param {HTMLElement} parent the element to check children of
   * @param {string}      type the type of event to listen for
   * @param {function}    handler the handler to call when the event fires
   * @param {bool}        capture useCapture or not
   */
  var add_child_submit_listener = function(parent, type, handler, capture) {
    var buttons = parent.getElementsByTagName("button");

    for (i in buttons) {
      if (buttons[i].getAttribute("type") == "submit") {
        buttons[i].addEventListener(type, handler, capture);
      }
    }
  };

  /**
   * This function is called to bind a click listener to the Add TrustAuth Key button.
   */
  var add_key_listener = function() {
    if (is_unlocked()) {
      var add_key_button = get_doc().getElementById("trustauth-register");
      if (add_key_button) {
        add_key_button.addEventListener("click", add_trustauth_key, true);
      }
    }
  };

  /**
   * This function injects the public key into a hidden form field with an ID of
   * "trustauth-key" whenever the Add TrustAuth Key button is clicked.
   */
  var add_trustauth_key = function() {
    if (is_unlocked()) {
      var register_element = get_doc().getElementById("trustauth-register");
      register_element.removeEventListener("click", add_trustauth_key, true);

      disable_child_submit(register_element.parentNode);

      var domain = get_domain();
      if (domain_exist(domain)) {
        insert_key();
      } else {
        assign_pair_and_replace(domain);
        insert_key();
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

  /**
   * Associates a cache key with the domain and generates a replacement key.
   *
   * @param {string} domain the domain to assign a key to
   * @return {bool} true on success; false otherwise
   */
  var assign_pair_and_replace = function(domain) {
    var site_id = fetch_or_store_domain(domain);
    var key_id = fetch_cache_id();
    if (key_id === null) {
      // No cached key exists so generate one
      create_cache_pair(function() {
        key_id = fetch_cache_id();
        associate_key(key_id, site_id);
        create_cache_pair();
      });
    } else {
      associate_key(fetch_cache_id(), site_id);
      create_cache_pair();
    }
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

  /**
   * Generates a key in background and stores it in the database as a backup key.
   *
   * @param {function} after_creation optional function to call after the keys have been stored in the database
   */
  var create_cache_pair = function(after_creation) {
    if (is_unlocked()) {
      log("generating new key pair...");
      generate_key_pair( function(keys) {
        var encryption_key = get_encryption_key();
        var encrypted_keys = {
          'publicKey': encrypt_aes(encryption_key, forge.pki.publicKeyToPem(keys['publicKey'])),
          'privateKey': encrypt_aes(encryption_key, forge.pki.privateKeyToPem(keys['privateKey'])),
        };
        store_cache_pair(encrypted_keys['publicKey'], encrypted_keys['privateKey']);

        if (after_creation) { after_creation(); }
      });
    } else {
      if (prompt_password()) {
        create_cache_key();
      }
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

        if (challenge_element) {
          disable_child_submit(challenge_element.parentNode);

          var keys = fetch_key_pair(domain);
          var private_key = forge.pki.privateKeyFromPem(keys['private_key']);

          get_doc().getElementById("trustauth-challenge").value = encrypt(private_key, challenge_element.value);
          enable_child_submit(challenge_element.parentNode);
        }
      }
    }
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

  /**
   * Inserts the key for the current domain into the "trustauth-key" field.
   */
  var insert_key = function() {
    if (is_unlocked()) {
      var keys = fetch_key_pair(get_domain());
      get_doc().getElementById("trustauth-key").value = keys['public_key'];
    }
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

  /**
   * Removes a listener from all submit buttons that are children of parent.
   *
   * @param {HTMLElement} parent the element to check children of
   * @param {string}      type the type of event to listen for
   * @param {function}    handler the handler to call when the event fires
   * @param {bool}        capture useCapture or not
   */
  var remove_child_submit_listener = function(parent, type, handler, capture) {
    var buttons = parent.getElementsByTagName("button");

    for (i in buttons) {
      if (buttons[i].getAttribute("type") == "submit") {
        buttons[i].removeEventListener(type, handler, capture);
      }
    }
  };



/******************************/
/* Browser Specific Functions */
/******************************/

  /**
   * Associates the given key id with the given domain id. This function fails if the key is
   * already assigned to another domain.
   *
   * @param {integer} key_id the key id to associate this domain to
   * @param {integer} site_id the id of the domain to associate this key to
   * @return {bool} true if successful; false otherwise
   */
  var associate_key = function(key_id, site_id) {
    var db = db_connect();

    var result = false;
    // If this key is available then assign it to this domain
    if ( ! is_key_assigned(key_id)) {
      try {
        var statement = db.createStatement("INSERT INTO keys_sites (key_id, site_id) VALUES(:key_id, :site_id)");
        statement.params.key_id  = key_id;
        statement.params.site_id = site_id;
        statement.execute();
        log('key associated successfully');
        result = true;
      } catch (e) {
        dump(e);
        log(db.lastErrorString);
      } finally {
        statement.finalize();
        db.close();
      }
    }
    return result;
  };

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
      db.close();
    }

    return domain_exists;
  };

  /**
   * Fetches the first cached key id from the database.
   */
  var fetch_cache_id = function() {
    var db = db_connect();

    var key_id = null;
    try {
      var statement = db.createStatement("SELECT id FROM keys WHERE id not in (SELECT key_id FROM keys_sites) LIMIT 1");
      if (statement.executeStep()) {
        key_id = statement.row.id;
      }
    } catch (e) {
      dump(e);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return key_id;
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
      db.close();
    }

    return key_pair;
  };

  /**
   * Adds the domain name to the database and returns the site_id of the domain.
   *
   * @param {string} domain the domain name to add
   * @return {integer} the id of the either the new domain or the previously inserted domain
   */
  var fetch_or_store_domain = function(domain) {
    var db = db_connect();

    // First try to insert the domain if it's not already there.
    var site_id = get_site_id(domain);
    if (site_id === null) {
      try {
        var statement = db.createStatement("INSERT INTO sites (domain) VALUES(:domain)");
        statement.params.domain = domain;
        statement.execute();

        site_id = db.lastInsertRowID;
      } catch (e) {
        log(db.lastErrorString);
        dump(e);
      } finally {
        statement.finalize();
        db.close();
      }
    }

    return site_id;
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
    function toHexString(charCode) {
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
    gBrowser.addEventListener("load", on_page_load, true);
    document.getElementById('trustauth-menu-unlock').addEventListener("click", prompt_password, false);
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

  /**
   * Checks to see if the key_id is already assigned to a domain.
   *
   * @param {integer} key_id the key id to check
   * @return {bool} true if the key is assigned already; false otherwise
   */
  var is_key_assigned = function(key_id) {
    var db = db_connect();

    var result = false;
    try {
      var statement = db.createStatement("SELECT * FROM keys_sites WHERE key_id=:key_id");
      statement.params.key_id = key_id;

      if (statement.executeStep()) {
        if (statement.row.key_id) {
          result = true;
        }
      }
    } catch (e) {
      dump(e);
      log(db.lastErrorString);
      result = true;
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
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

  var set_c_pref = function(preference, value) {
    prefs.setCharPref(preference, value);
  };

  var set_i_pref = function(preference, value) {
    prefs.setIntPref(preference, value);
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

  /**
   * Stores a cache key in the database for future use.
   *
   * @param {forge key objects} keys the key pair to store as the next cache key.
   */
  var store_cache_pair = function(public_key, private_key) {
    var db = db_connect();

    var result = false;
    try {
      var statement = db.createStatement("INSERT INTO keys (public_key, private_key, created) VALUES(:public_key, :private_key, :created)");
      statement.params.public_key  = public_key;
      statement.params.private_key = private_key;
      statement.params.created     = (new Date()).getTime();
      if (statement.executeStep()) result = true;
    } catch (e) {
      dump(e);
      log(db.lastErrorString);
    } finally {
      statement.finalize();
      db.close();
    }

    return result;
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

  /**
   * Verifies that the password given is the correct password.
   *
   * @param {string} password the password to check
   * @return {bool} true if it is, false otherwise
   */
  var verify_password = function(password) {
    var hash = get_stored_hash();

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
