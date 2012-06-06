/**
 * These are the constants used in the TrustAuth addon. This is browser independent code.
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
var EXPORTED_SYMBOLS = [
  'TRUSTAUTH_AJAX_LOADER',
  'TRUSTAUTH_BUTTON',
  'TRUSTAUTH_DISABLED',
  'TRUSTAUTH_CHALLENGE_ID',
  'TRUSTAUTH_RESPONSE_ID',
  'TRUSTAUTH_REGISTER_ID',
  'TRUSTAUTH_KEY_ID',
  'TRUSTAUTH_ENC_KEY_SALT',
  'TRUSTAUTH_STORAGE_SALT',
  'TIMEOUT',
  'HASH_LENGTH',
  'MESSAGE_TYPE',
  'CACHE_KEY_COUNT',
  'ITERATION_COUNT',
  'KEY_LENGTH',
  'ENCRYPTION_KEY_LENGTH',
];

var TRUSTAUTH_AJAX_LOADER = 'chrome://trustauth/skin/ajax-loader.gif';
var TRUSTAUTH_BUTTON      = 'chrome://trustauth/skin/button.png';
var TRUSTAUTH_DISABLED    = 'chrome://trustauth/skin/button-disabled.png';

var TRUSTAUTH_CHALLENGE_ID = "trustauth-challenge";
var TRUSTAUTH_RESPONSE_ID  = "trustauth-response";
var TRUSTAUTH_REGISTER_ID  = "trustauth-register";
var TRUSTAUTH_KEY_ID       = "trustauth-key";

var TRUSTAUTH_ENC_KEY_SALT = '2EEC776BE2291D76E7C81706BD0E36C0C10D62A706ADB12D2799CA731503FBBA';
var TRUSTAUTH_STORAGE_SALT = '7CAB8505B677344B34B83C77B6A3EF527DC31FEFDF531B9F5F623DCE040A4351';

var TIMEOUT = 30; // The length of time a message will be valid in seconds

var HASH_LENGTH = 32;

var MESSAGE_TYPE = {
  'challenge': 0,
  'response' : 1,
};

var CACHE_KEY_COUNT = 2;

var ITERATION_COUNT = 2048;

var KEY_LENGTH = 32; // 256 bits
var ENCRYPTION_KEY_LENGTH = 32; // 256 bits
