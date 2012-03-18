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
