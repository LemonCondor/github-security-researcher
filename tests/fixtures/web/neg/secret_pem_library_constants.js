// PEM helpers as found in vendored crypto libraries (jsencrypt / forge style): markers, no key material
var PRIV_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
JSEncryptRSAKey.prototype.getPrivateKey = function () {
  var key = "-----BEGIN RSA PRIVATE KEY-----\n";
  key += this.wordwrap(this.getPrivateBaseKeyB64()) + "\n";
  key += "-----END RSA PRIVATE KEY-----";
  return key;
};
function isPem(s) { return /-----BEGIN (?:EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(s); }
