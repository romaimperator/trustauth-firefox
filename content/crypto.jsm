/**
 * These are the cryptography functions for the TrustAuth addon. This is browser independent code.
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
var EXPORTED_SYMBOLS = [ 'ta_crypto' ];

Components.utils.import("chrome://trustauth/content/utils.jsm");
Components.utils.import("chrome://trustauth/content/forge/forge.jsm");
Components.utils.import("chrome://trustauth/content/constants.jsm");

var ta_crypto = {
  /*
   * Calculates the encryption key for the key pairs
   *
   * @param password the password to use
   * @param salt the salt to use
   * @return the encryption key
   */
  calculate_password_key: function(password, salt) {
    var md = forge.md.sha256.create();
    return forge.util.bytesToHex(forge.pkcs5.pbkdf2(forge.util.hexToBytes(utils.encode_hex(password)), salt, ITERATION_COUNT, KEY_LENGTH, md));
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
    var cipher = forge.aes.startDecrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(SALTS['ENC_KEY']), null);
    cipher.update(forge.util.createBuffer(forge.util.hexToBytes(data)));
    cipher.finish();
    return utils.decode_hex(cipher.output.toHex());
  },

  /**
   * This function decrypts both a public_key and a private_key from keys using AES and
   * encrypt_key as the encryption key.
   *
   * @param {hash} keys hash containing both a public_key and private_key encrypted with AES
   * @param {string} encrypt_key the AES encryption key used to encrypt the keys
   * @return {hash} hash containing the decrypted public and private key
   */
  decrypt_keys: function(keys, encrypt_key) {
    if ( ! utils.isset(keys) || ! utils.isset(keys['public_key']) || ! utils.isset(keys['private_key'])) { return null; }

    return {
      'public_key': this.decrypt_aes(encrypt_key, keys.public_key),
      'private_key': this.decrypt_aes(encrypt_key, keys.private_key),
    };
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
    var cipher = forge.aes.startEncrypting(forge.util.createBuffer(forge.util.hexToBytes(key)), forge.util.createBuffer(SALTS['ENC_KEY']), null);
    cipher.update(forge.util.createBuffer(utils.encode_bytes(data)));
    cipher.finish();
    return cipher.output.toHex();
  },

  /**
   * This function encrypts both a public_key and a private_key from keys using AES and
   * encrypt_key as the encryption key.
   *
   * @param {hash} keys hash containing both a public_key and private_key
   * @param {string} encrypt_key the AES encryption key used to encrypt the keys
   * @return {hash} hash containing the encrypted public and private key
   */
  encrypt_keys: function(keys, encrypt_key) {
    if ( ! utils.isset(keys['public_key']) || ! utils.isset(keys['private_key'])) { return null; }

    return {
      'public_key': this.encrypt_aes(encrypt_key, keys['public_key']),
      'private_key': this.encrypt_aes(encrypt_key, keys['private_key']),
    };
  },

  /**
   * Generates a 256-bit random encryption key returning the value in hex.
   *
   * @return {hex string} the 256-bit hex encryption key
   */
  generate_encryption_key: function() {
    return forge.random.getBytes(ENCRYPTION_KEY_LENGTH);
  },

};
