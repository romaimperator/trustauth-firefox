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
Components.utils.import("chrome://trustauth/content/prefs.jsm");

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

SALTS['ENC_KEY'] = db.fetch_or_store_salt(SALT_IDS['ENC_KEY']);
SALTS['STORAGE'] = db.fetch_or_store_salt(SALT_IDS['STORAGE']);
SALTS['PASSWORD'] = db.fetch_or_store_salt(SALT_IDS['PASSWORD']);

(function() {

  var initialized = false;
  var disabled    = false;

  var password_key   = null;
  var encryption_key = null;

  var idle_timeout = 0;
  var idle_timeout_func = null;


/*****************************/
/* Pure Javascript functions */
/*****************************/
  var log = function(message) {
    utils.log(message);
  };

  /**
   * This function injects the public key into a hidden form field with an ID of
   * "trustauth-key" whenever the Add TrustAuth Key button is clicked.
   */
  var add_trustauth_key = function() {
    if (is_unlocked()) {
      var register_element = utils.get_doc().getElementById(TRUSTAUTH_KEY_ID);
      var challenge_element = utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID);

      if ( ! register_element) { return ; } // No register element on the page

      utils.disable_child_submit(register_element.parentNode);

      var domain = utils.get_domain();
      if (db.domain_exist(domain)) {
        log("inserting key...");
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

  var add_trustauth_key_listener = function() {
    if ( ! is_unlocked()) { return; }

    var button = utils.get_doc().getElementById(TRUSTAUTH_REGISTER_ID);

    if (button) {
      button.addEventListener("click", add_trustauth_key, false);
    } else {
      add_trustauth_key();
    }
  };

  /**
   * Executes after the addon is unlocked. Used to encrypt the login challenge and bind the button.
   */
  var after_unlock = function() {
    encrypt_login();
    add_trustauth_key_listener();
    set_button_image(TRUSTAUTH_LOGO);
    add_listener(FIREFOX_CHANGE_PASSWORD_ID, "click", change_password);
    add_listener(FIREFOX_IMPORT_ENCRYPTED_ID, "click", function anon_import() { import_encrypted_database(); });
    add_listener(FIREFOX_EXPORT_ENCRYPTED_ID, "click", function anon_export() { export_encrypted_database(); });
    set_disabled_status(FIREFOX_CHANGE_PASSWORD_ID, false);
    set_disabled_status(FIREFOX_IMPORT_ENCRYPTED_ID, false);
    set_disabled_status(FIREFOX_EXPORT_ENCRYPTED_ID, false);
    replenish_cache(); // Needs to be last since it is not asynchronous
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
        replenish_cache();
        if (after_assign) { after_assign(); }
      });
    } else {
      db.associate_key(db.fetch_cache_id(), site_id);
      replenish_cache();
    }
  };

  /**
   * Runs whenever the change password button is clicked. It prompts for a new password and
   * is responsible for verifying the old one and storing the new one.
   */
  var change_password = function(event, message) {
    if (is_unlocked()) {
      message = utils.isset(message) ? {old:'','new':''} : message;
      var params = {'in': message, out:null};
      window.openDialog("chrome://trustauth/content/change_password.xul", "",
        "chrome, dialog, modal, resizable=no", params).focus();
      if (params.out) {
        // User clicked ok. Process changed arguments;
        var verified_password = verify_password(params.out.old_password);
        if (verified_password && params.out.new_password !== "") {
          var new_password_key   = ta_crypto.calculate_password_key(params.out.new_password, SALTS['PASSWORD']);
          var old_encryption_key = get_encryption_key();
          if (db.replace_password_and_encryption_keys(old_encryption_key, new_password_key)) {
            password_key   = new_password_key;
            encryption_key = null;
          } else {
            log("There was an error changing the master password.");
          }
        } else if ( ! verified_password) {
          change_password(event, {'old':'trustauth-error'});
          return;
        } else {
          change_password(event, {'new':'trustauth-error'});
          return;
        }
      } else {
        // User clicked cancel. Typically, nothing is done here.
      }
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
        var encrypted_keys = ta_crypto.encrypt_keys(keys, get_encryption_key());
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

      var challenge_element = utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID);

      if ( ! challenge_element) { log("Could not find the challenge element."); return; }

      var domain = utils.get_form_hostname(get_login_form());

      if ( ! db.domain_exist(domain)) { log("No key for this domain."); return; }

      utils.disable_child_submit(challenge_element.parentNode);
      var data = unpack_data(challenge_element.value);

      if (data['time'] + TIMEOUT < utils.get_time()) { set_problem('The challenge has expired. Refresh the page to get a new challenge.'); return; }
      if (data['hash'] !== data['calculated_hash']) { set_problem('There was an error verifying the integrity of the challenge message.'); return; }
      if (domain !== data['domain']) { set_problem('Domain did not match.'); return; }

      var keys = ta_crypto.decrypt_keys(db.fetch_key_pair(domain), get_encryption_key());
      var private_key = forge.pki.privateKeyFromPem(keys['private_key']);

      utils.get_doc().getElementById(TRUSTAUTH_RESPONSE_ID).value = pack_response({ 'response': data['challenge'], 'hash': data['hash'], 'domain': domain }, private_key);
      utils.enable_child_submit(challenge_element.parentNode);
      set_success();
      setTimeout(timeout_expired, (data['time'] + TIMEOUT - utils.get_time()) * 1000 );
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
    var prefered_length = prefs.get_i_pref("key_length");
    var key_length = prefered_length in KEY_LENGTHS ? KEY_LENGTHS[prefered_length] : DEFAULT_KEY_LENGTH;
    var exponent   = EXPONENT;

    var worker = new Worker('chrome://trustauth/content/generate_key_pair.js');
    worker.onerror   = function(event) {
      log('generate error: ' + event.message);
    };
    worker.onmessage = function(event) {
      handle_keys({
        'public_key':  event.data['publicKey'],
        'private_key': event.data['privateKey'],
      });
    };
    worker.postMessage({'key_length':key_length, 'exponent':exponent});
  };

  var get_encryption_key = function() {
    if (is_unlocked()) {
      if ( ! db.is_encryption_key_set()) {
        db.store_encryption_key(ta_crypto.generate_encryption_key(), password_key);
      }
      return encryption_key = (encryption_key === null) ? db.fetch_encryption_key(password_key) : encryption_key;
    } else {
      return null;
    }
  };

  var get_password_key = function() {
    return password_key;
  };

  /**
   * Returns the form element containing the TrustAuth challenge element.
   *
   * @return {HTMLNode} the login form element
   */
  var get_login_form = function() {
    return utils.get_doc().getElementById(TRUSTAUTH_CHALLENGE_ID).parentNode;
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
   * Returns true if the master password has been entered to unlock the addon
   *
   * @return boolean
   */
  var is_unlocked = function() {
    return get_password_key() !== null;
  };

  /**
   * Locks the add-on.
   */
  var lock = function() {
    password_key = null;
    set_button_image(TRUSTAUTH_LOGO_DISABLED);
    remove_listener(FIREFOX_CHANGE_PASSWORD_ID, "click", change_password);
    remove_listener(FIREFOX_IMPORT_ENCRYPTED_ID, "click", anon_import);
    remove_listener(FIREFOX_EXPORT_ENCRYPTED_ID, "click", anon_export);
    set_disabled_status(FIREFOX_CHANGE_PASSWORD_ID, true);
    set_disabled_status(FIREFOX_IMPORT_ENCRYPTED_ID, true);
    set_disabled_status(FIREFOX_EXPORT_ENCRYPTED_ID, true);
  }

  /**
   * Runs once every minute to check if it's time to lock the plugin. If it is then it stops the
   * interval function and locks the add-on.
   */
  var on_idle_interval = function() {
    idle_timeout += 1;
    if (idle_timeout >= prefs.get_i_pref("idle_timeout")) {
      clearInterval(idle_timeout_func);
      idle_timeout_func = null;
      lock();
    }
  };

  /*
   * Initializes the addon.
   */
  var on_load = function() {
    // initialization code
    if (prefs.get_b_pref('first_run')) {
      prefs.set_b_pref('first_run', false);
      install_button("nav-bar", FIREFOX_BUTTON_ID);
    }

    init_listener();
    initialized = true;
  };

  /**
   * Runs every time the mouse is moved. Used to implement the automatic idle locking feature.
   */
  var on_mouse_move = function(event) {
    if ( ! is_unlocked() ) { return; }

    if (prefs.get_i_pref("idle_timeout") !== 0) {
      if (idle_timeout_func === null) {
          idle_timeout_func = setInterval(on_idle_interval, 1000);
      }
      idle_timeout = 0;
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
        if (is_unlocked()) {
          add_trustauth_key_listener();
          encrypt_login();
        }
      }
    }
  };

  /**
   * This function packs the data into a hex string of data in the format for TrustAuth. The type
   * specifies which type of message this is. The data is a hash of data required for the format.
   *
   * Currently there are two formats supported:
   *   challenge => {
   *     'version'  : hash of the version number of 'major', 'minor', and 'patch' keys
   *     'type'     : the type of message this is,
   *     'time'     : the unix time in seconds since the epoch this challenge was created,
   *     'challenge': the random value generated by the server,
   *     'domain'   : the domain name given by the server,
   *     'hash'     : the sha-256 HMAC of the challenge message minus this hash,
   *   }
   *
   *   response => {
   *     'version'    : hash of the version number of 'major', 'minor', and 'patch' keys
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
      b.putByte(1);
      b.putByte(0);
      b.putByte(0);
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

    var version = {
      'major': b.getByte(),
      'minor': b.getByte(),
      'patch': b.getByte(),
    };
    if (version.major != 1 || version.minor != 0 || version.patch != 0) {
      log("Unsupported protocol version: " + version.major + "." + version.minor + "." + version.patch);
      return null;
    }
    var type = b.getByte();
    if (type === MESSAGE_TYPE['challenge']) {
      var meta = {
        'time'            : b.getInt32(),
        'challenge_length': b.getInt16(),
        'domain_length'   : b.getInt16(),
      };
      return {
        'version'  : version,
        'type'     : type,
        'time'     : meta['time'],
        'challenge': utils.decode_bytes(b.getBytes(meta['challenge_length'])),
        'domain'   : utils.decode_bytes(b.getBytes(meta['domain_length'])),
        'hash'     : forge.util.bytesToHex(b.getBytes(HASH_LENGTH)),
        'calculated_hash': utils.sha256(hash_buf.toHex()),
      };
    } else {
      log("Unrecognized message type: " + type);
      return null;
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
   * If there is a password set, prompt for it. If not, ask to set one.
   */
  var prompt_or_set_new_password = function() {
    if (db.is_password_set()) {
      prompt_password();
    } else {
      if (prompt_import_database()) {
        import_encrypted_database(true);
        prompt_password();
      } else {
        prompt_new_password();
      }
    }
  };

  /**
   * Removes any TrustAuth tooltips from the document.
   */
  var remove_tooltip = function() {
    var tooltip = utils.get_doc().getElementById("trustauth-tooltip");
    while (tooltip) {
      tooltip.parentNode.removeChild(tooltip);
      tooltip = utils.get_doc().getElementById("trustauth-tooltip");
    }
  };

  /**
   * Creates new key pairs for the cache of keys until the CACHE_KEY_COUNT is reached.
   */
  var replenish_cache = function() {
    if (is_unlocked()) {
      if (db.count_cache_keys() < CACHE_KEY_COUNT) {
        create_cache_pair(replenish_cache);
      }
    }
  };

  /**
   * Performs the actions necessary to show the user that there was a problem. This includes
   * changing the form's border and adding a tooltip.
   *
   * @param {string} error the error message to display in the tooltip
   */
  var set_problem = function(error) {
    var element = utils.find_parent_form_element(utils.get_doc().getElementById(TRUSTAUTH_RESPONSE_ID));

    element.addEventListener("mouseenter", function(event) { tooltip_hover(event, error); }, false);
    element.addEventListener("mouseleave", tooltip_unhover, false);

    var css = "background-image: url('data:image/gif;base64," + BASE64_LOGO_DISABLED + "');" +
    "background-repeat: no-repeat;" +
    "background-attachment: scroll;" +
    "background-position: right center;" +
    "border: 1px solid #c01f2f";
    element.setAttribute("style", css);
  };

  /**
   * Performs the actions necessary to show the user that the work was successful. This includes changing
   * the form's border and adding the logo.
   */
  var set_success = function() {
    var element = utils.find_parent_form_element(utils.get_doc().getElementById(TRUSTAUTH_RESPONSE_ID));
    var css = "background-image: url('data:image/gif;base64," + BASE64_LOGO + "');" +
    "background-repeat: no-repeat;" +
    "background-attachment: scroll;" +
    "background-position: right center;" +
    "border: 1px solid #5bb65b";
    var cur_style = element.hasAttribute("style") ? element.getAttribute("style") : '';
    element.setAttribute("style", cur_style + css);
  };

  /**
   * Is triggered after the timeout from the challenge message has expired.
   */
  var timeout_expired = function() {
    set_problem("Challenge timeout expired. Refresh the page to get a new challenge.");
  };

  /**
   * Is triggered whenever the mouse enters the element. It possitions a tooltip containing
   * the message where the mouse is. Removes any existing tooltips to prevent duplicates.
   *
   * @param {MouseEvent} event the event from the mouse moving
   * @param {string} message the message to put in the tooltip
   */
  var tooltip_hover = function(event, message) {
    // Don't add the tooltip if we're moving out from it
    if (event.relatedTarget.getAttribute("id") === "trustauth-tooltip") { return; }

    // Remove any tooltips that may still exist
    remove_tooltip();

    var tooltip = utils.get_doc().createElement("div");
    tooltip.appendChild(utils.get_doc().createTextNode(message));
    tooltip.setAttribute("id", "trustauth-tooltip");
    tooltip.setAttribute("style", "position: fixed;" +
                        "left: " + event.clientX + "px;" +
                        "top: " + event.clientY + "px;" +
                        "padding: 7px 7px 7px 7px;" +
                        "-webkit-box-shadow: 3px 3px 5px 0px #000;" +
                        "box-shadow: 3px 3px 5px 0px #000;" +
                        "-webkit-border-radius: 5px;" +
                        "border-radius: 5px;" +
                        "font-weight: bold;" +
                        "color: #c01f2f;" +
                        "background: rgb(239,239,239);" +
                        "background: -moz-linear-gradient(top, rgba(239,239,239,1) 0%, rgba(196,196,196,1) 100%);" +
                        "background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(239,239,239,1)), color-stop(100%,rgba(196,196,196,1)));" +
                        "background: -webkit-linear-gradient(top, rgba(239,239,239,1) 0%,rgba(196,196,196,1) 100%);" +
                        "background: -o-linear-gradient(top, rgba(239,239,239,1) 0%,rgba(196,196,196,1) 100%);" +
                        "background: -ms-linear-gradient(top, rgba(239,239,239,1) 0%,rgba(196,196,196,1) 100%);" +
                        "background: linear-gradient(top, rgba(239,239,239,1) 0%,rgba(196,196,196,1) 100%);" +
                        "filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#efefef', endColorstr='#c4c4c4',GradientType=0 );");
    utils.get_doc().getElementsByTagName("body")[0].appendChild(tooltip);
  };

  /**
   * Is triggered whenever the mouse leaves the element. It removes any tooltips that exist.
   *
   * @param {MouseEvent} event the mouse event that triggered this
   */
  var tooltip_unhover = function(event) {
    // Don't remove the tooltip if we're hovering over it
    if (event.relatedTarget.getAttribute("id") === "trustauth-tooltip") { return; }

    remove_tooltip();
  };



/******************************/
/* Browser Specific Functions */
/******************************/

  /**
   * Adds the event listener to the element.
   *
   * @param {string} id the id of the element to add the listener to
   * @param {string} event the name of the event to listen for
   * @param {function} func the function to handle the event
   */
  var add_listener = function(id, event, func) {
    var element = document.getElementById(id);
    if (element) {
      element.addEventListener(event, func, false);
    }
  };

  /**
   * Handles exporting a database from the add-on.
   */
  var export_encrypted_database = function() {
    if ( ! is_unlocked()) { return; }

    var output_file = open_dialog(true);
    if (output_file) {
      Components.utils.import("resource://gre/modules/FileUtils.jsm");
      var file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
      var ext = (output_file.leafName.substr(-4, 4) === '.tdb') ? '' : '.tdb';
      file.copyTo(output_file.parent, output_file.leafName + ext);
      show_notification("Database successfully exported!", 3000);
    }
  };

  /**
   * Handles importing a database to the add-on.
   *
   * @param {bool} initial_import if true the database overwrite warning is not displayed reguardless of the preference
   */
  var import_encrypted_database = function(initial_import) {
    initial_import = (utils.isset(initial_import)) ? initial_import : false;

    if ( ! is_unlocked() && ! initial_import) { return; }

    // Check if the user should be notified of the overwrite
    if ( ! initial_import && prefs.get_b_pref("inform_database_overwrite")) {
      var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                          .getService(Components.interfaces.nsIPromptService);
      var check = {value: false};
      var result = prompts.confirmCheck(null,
                                        "Your existing database will be overwritten!",
                                        "If you choose to import a database, your existing database will be replaced." +
                                        " If you want to save it hit cancel and export it first. Afterwards import the new database."
                                        , "Don't show again", check);
      prefs.set_b_pref("inform_database_overwrite", !check.value);
      if ( ! result) { return; }
    }

    var input_file = open_dialog(false);
    if (input_file) {
      Components.utils.import("resource://gre/modules/FileUtils.jsm");
      var output_file = FileUtils.getFile("ProfD", ["trustauth", "trustauth.sqlite"]);
      input_file.copyTo(output_file.parent, output_file.leafName);

      // Update the salts
      SALTS['ENC_KEY'] = db.fetch_or_store_salt(SALT_IDS['ENC_KEY']);
      SALTS['STORAGE'] = db.fetch_or_store_salt(SALT_IDS['STORAGE']);
      SALTS['PASSWORD'] = db.fetch_or_store_salt(SALT_IDS['PASSWORD']);

      show_notification("Database successfully imported!", 3000);
    }
  }

  /*
   * Initializes the javascript listeners for the buttons on the preference page.
   */
  var init_listener = function() {
    gBrowser.addEventListener("load", on_page_load, true);
    add_listener(FIREFOX_UNLOCK_ID, "click", prompt_or_set_new_password);
    gBrowser.addEventListener("mousemove", on_mouse_move, true);
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
   * Opens a dialog to select an output or input TrustAuth database file.
   *
   * @param {bool} open_save if true opens a save dialog, if false opens an open dialog
   * @return {nsILocalFile} the file picked by the user
   */
  var open_dialog = function(open_save) {
    var nsIFilePicker = Components.interfaces.nsIFilePicker;
    var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);

    var mode = (open_save) ? nsIFilePicker.modeSave : nsIFilePicker.modeOpen;
    var message = (open_save) ? "Select a place to save the database:" : "Select a database to import:";

    fp.init(window, message, mode);
    fp.appendFilter("TrustAuth Database", "*.tdb");

    var res = fp.show();
    if (res != nsIFilePicker.returnCancel) {
      return fp.file;
    } else {
      return null;
    }
  };

  /**
   * Asks the user if they want to import an existing database or to create a new one.
   */
  var prompt_import_database = function() {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                            .getService(Components.interfaces.nsIPromptService);

    var check = {value: false}; // default the checkbox to false

    var flags = prompts.BUTTON_POS_0 * prompts.BUTTON_TITLE_YES +
                prompts.BUTTON_POS_1 * prompts.BUTTON_TITLE_CANCEL  +
                prompts.BUTTON_POS_2 * prompts.BUTTON_TITLE_NO;

    var button = prompts.confirmEx(null, "New Database!",
                                   "It appears you don't currently have a TrustAuth database. Would you like to import one? If not one will be created for you.",
                                   flags, "", "", "", null, check);

    // The checkbox will be hidden, and button will contain the index of the button pressed 0, 1, or 2.
    return (button === 0); // Return true only if they selected yes
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
      password_key = ta_crypto.calculate_password_key(password.value, SALTS['PASSWORD']);
      db.store_password_key(password_key);
      var encrypted_keys = ta_crypto.encrypt_keys({ public_key: DEMO_SITE_PUBLIC_KEY, private_key: DEMO_SITE_PRIVATE_KEY }, get_encryption_key());
      db.store_cache_pair(encrypted_keys['public_key'], encrypted_keys['private_key']);
      db.associate_key(db.fetch_cache_id(), db.fetch_or_store_domain("trustauth.com"));
      after_unlock();
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
      password_key = ta_crypto.calculate_password_key(password.value, SALTS['PASSWORD']);
      after_unlock();
      return true;
    }
    return false;
  };

  /**
   * Removes the event listener from the element.
   *
   * @param {string} id the id of the element to remove the listener from
   * @param {string} event the name of the event to listen for
   * @param {function} func the function to handle the event
   */
  var remove_listener = function(id, event, func) {
    var element = document.getElementById(id);
    if (element) {
      element.removeEventListener(event, func, false);
    }
  };

  /*
   * This function sets the button image on the toolbar.
   *
   * @param image the image url to change the image to
   */
  var set_button_image = function(image) {
    document.getElementById(FIREFOX_BUTTON_ID).setAttribute('image', image);
  };

  /**
   * Sets enabled or disabled on the change password button.
   *
   * @param {bool} disabled_status if true the button is disabled, false enabled
   */
  var set_disabled_status = function(id, disabled_status) {
    document.getElementById(id).setAttribute("disabled", disabled_status);
  };

  /**
   * Shows a doorhanger notification to the user for timeout milliseconds.
   *
   * @param {string} message the message to show the user
   * @param {integer} timeout the length of time to show the notification before hiding in milliseconds
   */
  var show_notification = function(message, timeout) {
    var notif = PopupNotifications.show(gBrowser.selectedBrowser, "sample-popup",
      message,
      null, /* anchor ID */
      null  /* secondary action */
      );
    setTimeout(function(){
      notif.remove();
    }, timeout);
  };

  /**
   * Verifies that the password given is the correct password.
   *
   * @param {string} password the password to check
   * @return {bool} true if it is, false otherwise
   */
  var verify_password = function(password) {
    var hash = db.get_stored_hash();

    return (hash !== null && hash === db.get_storage_hash(ta_crypto.calculate_password_key(password, SALTS['PASSWORD'])));
  };

  // Initialize the TrustAuth object
  window.addEventListener("load", function on_load_call(e) {
    this.removeEventListener("load", on_load_call, false);
    on_load(e);
  }, false);

})();

}

})();
