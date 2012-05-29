/**
 * This is the utility code for the TrustAuth addon. This is browser agnostic code.
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
var EXPORTED_SYMBOLS = [ 'utils' ];

Components.utils.import("chrome://trustauth/content/constants.jsm");

var utils = {

  /**
   * Adds a listener to all submit buttons that are children of parent.
   *
   * @param {HTMLElement} parent the element to check children of
   * @param {string}      type the type of event to listen for
   * @param {function}    handler the handler to call when the event fires
   * @param {bool}        capture useCapture or not
   */
  add_child_submit_listener: function(parent, type, handler, capture) {
    var buttons = parent.getElementsByTagName("button");

    for (i in buttons) {
      if (buttons[i].getAttribute("type") == "submit") {
        buttons[i].addEventListener(type, handler, capture);
      }
    }
  },

  /*
   * Calculates the encryption key for the key pairs
   *
   * @param password the password to use
   * @param salt the salt to use
   * @return the encryption key
   */
  calculate_encryption_key: function(password, salt) {
    return this.sha256(password + salt);
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

  /**
   * Disables all of the submit buttons that are a child of the given element.
   *
   * @param {HTMLElement} parent the element containing submit buttons to disable
   */
  disable_child_submit: function(parent) {
    var buttons = [parent.getElementsByTagName("button"), parent.getElementsByTagName("submit")];

    for (i in buttons) {
      for (var j = 0; j < buttons[i].length; j++) {
        if (buttons[i][j].getAttribute("type") == "submit") {
          buttons[i][j].disabled = true;
        }
      }
    }
  },

  /**
   * Enables all of the submit buttons that are a child of the given element.
   *
   * @param {HTMLElement} parent the element containing submit buttons to enable
   */
  enable_child_submit: function(parent) {
    var buttons = [parent.getElementsByTagName("button"), parent.getElementsByTagName("submit")];

    for (i in buttons) {
      for (var j = 0; j < buttons[i].length; j++) {
        if (buttons[i][j].getAttribute("type") == "submit") {
          buttons[i][j].disabled = false;
        }
      }
    }
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
        //log('encode of: ' + string + ' produced character length of: ' + tmp.length + ' at character: ' + i);
      }
      retval += tmp;
    }
    return retval;
  },

  /**
   * Returns the hostname from the form element's action attribute.
   *
   * @param {HTMLNode} form_element the form element to get the hostname from
   * @return {string} the hostname from the form's action
   */
  get_form_hostname: function(form_element) {
    var action = form_element.getAttribute("action");
    return this.get_hostname_from_url(this.relative_to_absolute(action));
  },

  /**
   * Returns the hostname from the given URL.
   *
   * @param {string} url the url to parse
   * @return {string} the hostname from the url
   */
  get_hostname_from_url: function(url) {
    return url.replace("http://", "").replace("https://", "").split("/")[0];
  },

  /**
   * Returns the current time since the epoch in seconds.
   *
   * @return {int} the current time in seconds since the epoch
   */
  get_time: function() {
    return Math.round((new Date()).getTime() / 1000);
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
    function toHexString(charCode) {
      return ("0" + charCode.toString(16)).slice(-2);
    };

    // convert the binary hash data to a hex string.
    return [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
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

  /**
   * Pads the front of a string with a given character until the string reaches length.
   *
   * @param {string} str the string to pad
   * @param {int} length the length to pad the string to
   * @param {char} pad_char the character to pad the string with
   * @return {string} the padded string
   */
  pad_front: function(str, length, pad_char) {
    for (var i = str.length; i < length; i++) {
      str = pad_char + str;
    }
    return str;
  },

  /**
   * Removes a listener from all submit buttons that are children of parent.
   *
   * @param {HTMLElement} parent the element to check children of
   * @param {string}      type the type of event to listen for
   * @param {function}    handler the handler to call when the event fires
   * @param {bool}        capture useCapture or not
   */
  remove_child_submit_listener: function(parent, type, handler, capture) {
    var buttons = parent.getElementsByTagName("button");

    for (i in buttons) {
      if (buttons[i].getAttribute("type") == "submit") {
        buttons[i].removeEventListener(type, handler, capture);
      }
    }
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
};
