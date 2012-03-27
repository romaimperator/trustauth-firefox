/**
 * This is the main code for generating key pairs on a separate thread.
 *
 * @author Daniel Fox
 * @link foamicate.com
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
 *     Neither the name of Foamicate nor the names of its contributors may be used to endorse or promote products derived from this software
 *         without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
var window = {};
onmessage = function(event) {
  importScripts(
    "chrome://foamicator/content/jsbn.js",
    "chrome://foamicator/content/util.js",
    "chrome://foamicator/content/aes.js",
    "chrome://foamicator/content/asn1.js",
    "chrome://foamicator/content/md5.js",
    "chrome://foamicator/content/sha1.js",
    "chrome://foamicator/content/sha256.js",
    "chrome://foamicator/content/oids.js",
    "chrome://foamicator/content/prng.js",
    "chrome://foamicator/content/random.js",
    "chrome://foamicator/content/rsa.js",
    "chrome://foamicator/content/pki.js"
  );

  var key_length = event.data['key_length'];
  var exponent   = event.data['exponent'];

  var keys = window.forge.pki.rsa.generateKeyPair(key_length, exponent);

  keys['publicKey'] = window.forge.pki.publicKeyToPem(keys['publicKey']);
  keys['privateKey'] = window.forge.pki.privateKeyToPem(keys['privateKey']);

  self.postMessage(keys);
}
