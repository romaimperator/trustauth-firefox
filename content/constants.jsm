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
  'TRUSTAUTH_LOGO',
  'TRUSTAUTH_LOGO_DISABLED',
  'TRUSTAUTH_CHALLENGE_ID',
  'TRUSTAUTH_RESPONSE_ID',
  'TRUSTAUTH_REGISTER_ID',
  'TRUSTAUTH_KEY_ID',
  'FIREFOX_BUTTON_ID',
  'FIREFOX_UNLOCK_ID',
  'FIREFOX_CHANGE_PASSWORD_ID',
  'TIMEOUT',
  'HASH_LENGTH',
  'MESSAGE_TYPE',
  'CACHE_KEY_COUNT',
  'ITERATION_COUNT',
  'KEY_LENGTH',
  'ENCRYPTION_KEY_LENGTH',
  'SALT_IDS',
  'SALT_LENGTH',
  'SALTS',
  'DEMO_SITE_PUBLIC_KEY',
  'DEMO_SITE_PRIVATE_KEY',
  'IDLE_TIMEOUT_INTERVAL',
  'KEY_LENGTHS',
  'EXPONENT',
  'DEFAULT_KEY_LENGTH',
];

var TRUSTAUTH_AJAX_LOADER   = 'chrome://trustauth/skin/ajax-loader.gif';
var TRUSTAUTH_LOGO          = 'chrome://trustauth/skin/logo_small_shorter_22.png';
var TRUSTAUTH_LOGO_DISABLED = 'chrome://trustauth/skin/logo_small_shorter_disabled_22.png';

var TRUSTAUTH_CHALLENGE_ID = "trustauth-challenge";
var TRUSTAUTH_RESPONSE_ID  = "trustauth-response";
var TRUSTAUTH_REGISTER_ID  = "trustauth-register";
var TRUSTAUTH_KEY_ID       = "trustauth-key";

var FIREFOX_BUTTON_ID          = 'trustauth-main-button';
var FIREFOX_UNLOCK_ID          = 'trustauth-menu-unlock';
var FIREFOX_CHANGE_PASSWORD_ID = 'trustauth-menu-change-password';

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

var SALT_IDS   = { 'ENC_KEY': 1, 'STORAGE': 2, 'PASSWORD': 3 };
var SALT_LENGTH = 32; // 256 bits

var SALTS = { 'ENC_KEY': null, 'STORAGE': null, 'PASSWORD': null };

var DEMO_SITE_PUBLIC_KEY  = "-----BEGIN PUBLIC KEY-----\n" +
"MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCVoeQxVmYsm9expDrr+14rbxtv\n" +
"wL58Qlr/HkG4H/CW8DjnNUte2W2rLZXUlN62kJCaqsz5LgvPCKftbX0CQTdLQuOC\n" +
"/uMOiirgtBrA02XFzMD7LR296T6gjXTrsIMm9aGdVlRyGp5wIxw73uQy4gUUjQYM\n" +
"NgeXamudQvniZVWPUwIBAw==\n" +
"-----END PUBLIC KEY-----";
var DEMO_SITE_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
"MIICWgIBAAKBgQCVoeQxVmYsm9expDrr+14rbxtvwL58Qlr/HkG4H/CW8DjnNUte\n" +
"2W2rLZXUlN62kJCaqsz5LgvPCKftbX0CQTdLQuOC/uMOiirgtBrA02XFzMD7LR29\n" +
"6T6gjXTrsIMm9aGdVlRyGp5wIxw73uQy4gUUjQYMNgeXamudQvniZVWPUwIBAwKB\n" +
"gGPBQsuO7shn5SEYJ0f86XJKEkqAfv2Bkf9pgSVqoGSgJe943OnmSRzJDo24lHm1\n" +
"tbxx3ft0B99bGp5I/gGAz4Z7J6pq/LZmSC1IQi45vMhLPqdmeWJzgrHSD35e9MCn\n" +
"kIo6/ZAXUIR/9NMiBJCiQ5d+NWCtcB+veWnKUsB1lo4LAkEA3C8/QtW0FWTAyAOJ\n" +
"8CMaDphJSPKfImpNNeJiHs2vZF61z83/KCYTKpYBl1SRTA1+5mtaqQIQxyk5y/BY\n" +
"QPyVmwJBAK34xBuSSNtZ2/+z8Yynf01Ktsp1CxmQSJx7TANGVpXqGC4KGs9/ljiW\n" +
"/ZSIyKKSMmlKoIjdVxwMRMeNaXP3JKkCQQCSyiosjngOQyswAlv1bLwJutuF9xTB\n" +
"nDN5QZa/M8pC6c6KiVTFbrdxuVZk4wuICP9ER5HGAWCExiaH9ZArUw5nAkBz+y1n\n" +
"tts85pKqd/ZdxP+I3HncTgdmYDBoUjKs2Y8OnBAesWc0/7l7D1O4WzBsYXbw3GsF\n" +
"6OS9XYMvs5uipMMbAkAdhhQFPpIkrxT6zvof6RSMlh+2PzrEfGrxmgug9cLp/8Lu\n" +
"JXa4T8LWsoaLyQwAR4Xbazy2W+vXkbeSK1m48mHV\n" +
"-----END RSA PRIVATE KEY-----";

var IDLE_TIMEOUT_INTERVAL = 60; // In seconds

var KEY_LENGTHS = { 1: 1024, 2: 2048, 3: 4096 }; // Lengths in bits
var EXPONENT    = 3;
var DEFAULT_KEY_LENGTH = 2048;
