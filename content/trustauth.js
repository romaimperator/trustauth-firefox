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

Components.utils.import("chrome://trustauth/content/forge/forge.jsm");
Components.utils.import("chrome://trustauth/content/utils.jsm");
Components.utils.import("chrome://trustauth/content/crypto.jsm");
Components.utils.import("chrome://trustauth/content/constants.jsm");
Components.utils.import("chrome://trustauth/content/db.jsm");

/* These are the firefox specific utility functions that must be implemented. */

/*
 * Logs a message to the console as a TrustAuth message.
 *
 * @param message the message to log
 */
utils.log = function(message) {
    var console = Components.classes['@mozilla.org/consoleservice;1'].
              getService(Components.interfaces.nsIConsoleService);
    console.logStringMessage('TrustAuth: ' + message);
};

/*
 * Initializes the doc attribute with the document of the current page.
 */
utils.get_doc = function() {
  return content.document;
};

/*
 * Returns the domain of the current page.
 * @return the current page's domain
 */
utils.get_domain = function() {
  return utils.get_doc().domain;
};

(function() {

  var initialized = false;
  var disabled    = false;
  var prefs       = null;

  var encryption_key = null;



/*****************************/
/* Pure Javascript functions */
/*****************************/
  var log = function(message) {
    utils.log(message);
  };

  /**
   * This function is called to bind a click listener to the Add TrustAuth Key button.
   */
  var add_key_listener = function() {
    if (is_unlocked()) {
      var add_key_button = utils.get_doc().getElementById(TRUSTAUTH_REGISTER_ID);
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
      var register_element = utils.get_doc().getElementById(TRUSTAUTH_REGISTER_ID);
      register_element.removeEventListener("click", add_trustauth_key, true);

      utils.disable_child_submit(register_element.parentNode);

      var domain = utils.get_domain();
      if (db.domain_exist(domain)) {
        insert_key();
        utils.enable_child_submit(register_element.parentNode);
      } else {
        assign_pair_and_replace(domain, function() {
          insert_key();
          utils.enable_child_submit(register_element.parentNode);
        });
      }
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
   * @param {function} after_assign an optional function to execute after a key pair is assigned to domain
   * @return {bool} true on success; false otherwise
   */
  var assign_pair_and_replace = function(domain, after_assign) {
    var site_id = db.fetch_or_store_domain(domain);
    var key_id = db.fetch_cache_id();
    if (key_id === null) {
      // No cached key exists so generate one
      create_cache_pair(function() {
        key_id = db.fetch_cache_id();
        db.associate_key(key_id, site_id);
        create_cache_pair();
        if (after_assign) { after_assign(); }
      });
    } else {
      db.associate_key(db.fetch_cache_id(), site_id);
      create_cache_pair();
    }
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
        var encrypted_keys = ta_crypto.encrypt_keys({
            'public_key': forge.pki.publicKeyToPem(keys['publicKey']),
            'private_key': forge.pki.privateKeyToPem(keys['privateKey'])},
          get_encryption_key());
        db.store_cache_pair(encrypted_keys['public_key'], encrypted_keys['private_key']);

        if (after_creation) { after_creation(); }
        log("finished generating key pair");
      });
    } else {
      if (prompt_password()) {
        create_cache_key();
      }
    }
  };

  /**
   * This function is called whenever a page is loaded and has an element with
   * and ID of "trustauth-challenge". If there is a key already generated for this
   * site then the key is used to encrypt the random value in this field.
   *
   * If there is not a key for this site then this function does nothing.
   */
  var encrypt_login = function() {
    if (is_unlocked()) {
      var domain = utils.get_form_hostname(get_login_form());

      if ( ! db.domain_exist(domain)) { log("No key for this domain."); return; }

      var challenge_element = utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID);

      if ( ! challenge_element) { log("Could not find the challenge element."); return; }

      utils.disable_child_submit(challenge_element.parentNode);
      var data = unpack_data(challenge_element.value);

      if (data['time'] + TIMEOUT < utils.get_time()) { log('The challenge has expired. Refresh the page to get a new challenge.'); return; }
      if (data['hash'] !== data['calculated_hash']) { log('There was an error verifying the integrity of the challenge message.'); return; }
      if (domain !== data['domain']) { log('Domain did not match.'); return; }

      var keys = ta_crypto.decrypt_keys(db.fetch_key_pair(domain), get_encryption_key());
      var private_key = forge.pki.privateKeyFromPem(keys['private_key']);

      utils.get_doc().getElementById(TRUSTAUTH_RESPONSE_ID).value = pack_response({ 'response': data['challenge'], 'hash': data['hash'], 'domain': domain }, private_key);
      utils.enable_child_submit(challenge_element.parentNode);
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

  /**
   * Returns the form element containing the TrustAuth challenge element.
   *
   * @return {HTMLNode} the login form element
   */
  var get_login_form = function() {
    return utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID).parentNode;
  };

  /*
   * Returns a hash of the encryption key that is safe to store for
   * password verification.
   *
   * @param encryption_key the key to get a storage hash of
   * @return the hash of the key
   */
  var get_storage_hash = function(encryption_key) {
    return utils.sha256(encryption_key + TRUSTAUTH_STORAGE_SALT);
  };

  /**
   * Inserts the key for the current domain into the "trustauth-key" field.
   */
  var insert_key = function() {
    if (is_unlocked()) {
      var keys = ta_crypto.decrypt_keys(db.fetch_key_pair(utils.get_domain()), get_encryption_key());
      utils.get_doc().getElementById(TRUSTAUTH_KEY_ID).value = keys['public_key'];
    }
  };

  /*
   * Returns true if the master password has been set before.
   *
   * @return boolean
   */
  var is_password_set = function() {
    return db.get_stored_hash() !== null;
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
    db.init();
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

        dump(unpack_data(utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID).value));
        add_key_listener();
        encrypt_login();
      }
    }
  };

  /**
   * This function packs the data into a hex string of data in the format for TrustAuth. The type
   * specifies which type of message this is. The data is a hash of data required for the format.
   *
   * Currently there are two formats supported:
   *   challenge => {
   *     'type'     : the type of message this is,
   *     'time'     : the unix time in seconds since the epoch this challenge was created,
   *     'challenge': the random value generated by the server,
   *     'domain'   : the domain name given by the server,
   *     'hash'     : the sha-256 HMAC of the challenge message minus this hash,
   *   }
   *
   *   response => {
   *     'type'       : the type of message this is,
   *     'time'       : the current unix time in seconds since the epoch,
   *     'challenge'  : the random value given by the server as the challenge,
   *     'domain'     : domain name of the site,
   *     'server_hash': the hash from the challenge message,
   *     'hash'       : the hash of this message encrypted with the private key for the site,
   *   }
   *
   * @param {enum} type the type of message to pack
   * @param {hash} data the data required for the message type
   * @param {forge key object}
   * @return {string} a hex string of the packed data
   */
  var pack_data = function(type, data, key) {
    var b = forge.util.createBuffer();
    if (type === MESSAGE_TYPE['response']) {
      b.putByte(type);
      b.putBytes(forge.util.hexToBytes(utils.pad_front(data['time'].toString(16), 8, '0')));
      var encoded_response = utils.encode_bytes(data['response']);
      var encoded_domain   = utils.encode_bytes(data['domain']);
      b.putInt16(encoded_response.length);
      b.putInt16(encoded_domain.length);
      b.putBytes(encoded_response);
      b.putBytes(encoded_domain);
      b.putBytes(forge.util.hexToBytes(data['hash']));
      var encrypted_hash = ta_crypto.encrypt(key, utils.sha256(b.toHex()));
      b.putInt16(encrypted_hash.length);
      b.putBytes(forge.util.hexToBytes(encrypted_hash));
      return b.toHex();
    } else {
      log("Unrecognized message type: " + type);
    }
  };

  /**
   * See pack_data
   *
   * @param {hex string} data the trustauth message to unpack
   * @return {hash} the unpacked data as a hash
   */
  var unpack_data = function(data) {
    var b = forge.util.createBuffer(forge.util.hexToBytes(data));
    var hash_buf = b.copy();
    hash_buf.truncate(HASH_LENGTH);

    var type = b.getByte();
    if (type === MESSAGE_TYPE['challenge']) {
      var meta = {
        'time'            : b.getInt32(),
        'challenge_length': b.getInt16(),
        'domain_length'   : b.getInt16(),
      };
      return {
        'type'     : type,
        'time'     : meta['time'],
        'challenge': utils.decode_bytes(b.getBytes(meta['challenge_length'])),
        'domain'   : utils.decode_bytes(b.getBytes(meta['domain_length'])),
        'hash'     : forge.util.bytesToHex(b.getBytes(HASH_LENGTH)),
        'calculated_hash': utils.sha256(hash_buf.toHex()),
      };
    } else {
      log("Unrecognized message type: " + type);
    }
  };

  /**
   * Packs a response message given the following data and a Forge Key object.
   *
   * data = {
   *   'response' => the challenge from the challenge message
   *   'hash'     => the message hash from the challenge message
   *   'domain'   => the domain the login form's action submits to
   * }
   *
   * @param {hash} data the data to pack
   * @param {forge key object} key the key to use for encryption
   * @return {hex string} the packed response
   */
  var pack_response = function(data, key) {
    data.time = utils.get_time();
    return pack_data(MESSAGE_TYPE['response'], data, key);
  };


  /**
   * Converts an absolute or relative URL to an absolute URL.
   *
   * @param {string} url the URL to convert
   * @return {string} the absolute URL
   */
  utils.relative_to_absolute = function(url) {
    var a = get_doc().createElement('a');
    a.href = url;
    return a.href;
  };


/******************************/
/* Browser Specific Functions */
/******************************/

  var get_b_pref = function(preference) {
      return prefs.getBoolPref(preference);
  };

  var get_c_pref = function(preference) {
      return prefs.getCharPref(preference);
  };

  var get_i_pref = function(preference) {
      return prefs.getIntPref(preference);
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
      encryption_key = utils.calculate_encryption_key(password.value, TRUSTAUTH_ENC_KEY_SALT);
      db.store_encryption_key(encryption_key);
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
      encryption_key = utils.calculate_encryption_key(password.value, TRUSTAUTH_ENC_KEY_SALT);
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
    document.getElementById('trustauth-main-button').setAttribute('image', image);
  };

  var set_c_pref = function(preference, value) {
    prefs.setCharPref(preference, value);
  };

  var set_i_pref = function(preference, value) {
    prefs.setIntPref(preference, value);
  };

  /**
   * Verifies that the password given is the correct password.
   *
   * @param {string} password the password to check
   * @return {bool} true if it is, false otherwise
   */
  var verify_password = function(password) {
    var hash = db.get_stored_hash();

    return (hash !== null && hash === get_storage_hash(utils.calculate_encryption_key(password, TRUSTAUTH_ENC_KEY_SALT)));
  };

  // Initialize the TrustAuth object
  window.addEventListener("load", function on_load_call(e) {
    this.removeEventListener("load", on_load_call, false);
    on_load(e);
  }, false);

})();

}

})();
