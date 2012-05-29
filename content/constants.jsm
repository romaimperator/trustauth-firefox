
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
