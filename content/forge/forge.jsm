/**
 * This code loads the Forge library. This is Firefox specific code.
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
var EXPORTED_SYMBOLS = [ 'forge' ];

Components.utils.import("chrome://trustauth/content/utils.jsm");

/* This function was taken from the forum post on this page: http://forums.mozillazine.org/viewtopic.php?p=921150#921150 */
function getContents(aURL){
  var ioService=Components.classes["@mozilla.org/network/io-service;1"]
    .getService(Components.interfaces.nsIIOService);
  var scriptableStream=Components
    .classes["@mozilla.org/scriptableinputstream;1"]
    .getService(Components.interfaces.nsIScriptableInputStream);

  var channel=ioService.newChannel(aURL,null,null);
  var input=channel.open();
  scriptableStream.init(input);
  var str=scriptableStream.read(input.available());
  scriptableStream.close();
  input.close();
  return str;
}

var window = {};

var forge_parts = [
    "chrome://trustauth/content/forge/jsbn.js",
    "chrome://trustauth/content/forge/util.js",
    "chrome://trustauth/content/forge/aes.js",
    "chrome://trustauth/content/forge/asn1.js",
    "chrome://trustauth/content/forge/md5.js",
    "chrome://trustauth/content/forge/sha1.js",
    "chrome://trustauth/content/forge/sha256.js",
    "chrome://trustauth/content/forge/oids.js",
    "chrome://trustauth/content/forge/prng.js",
    "chrome://trustauth/content/forge/random.js",
    "chrome://trustauth/content/forge/rsa.js",
    "chrome://trustauth/content/forge/pki.js"
];

for (i in forge_parts) {
  eval(getContents(forge_parts[i]));
}
var forge = window.forge;
