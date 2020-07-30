const words = require('./utils/words.js');
const Address = require('./utils/address.js');
const curve25519 = require('./utils/curve25519.js');
const curve25519_ = require('./utils/curve25519_.js');
const converters = require('./utils/converters.js');
const pako = require('pako');

var crypto = require('crypto');
const CryptoJS = require("crypto-js");
const BigInteger = require("big-integer");

const QooberUtils = {
  isValidAddress(address){
    const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const re = new RegExp('^(QOOB-['+alphabet+']{4}-['+alphabet+']{4}-['+alphabet+']{4}-['+alphabet+']{5})$');
    return re.test(address);
  },
  isValidPublicKey(publicKey){
    publicKey = publicKey.replace(/[^A-z0-9]/g,"");
    if(publicKey.length != 64){
      return false;
    }
    return true;
  },
  isValidPassphrase(passPhrase){
    let phraseWords = passPhrase.split(" ");
    if(phraseWords.length != 12 && phraseWords.length != 18){
      return false;
    }

    let matches = 0;
    for(let key in words){
      for(let key2 in phraseWords){
        if(phraseWords[key2] == words[key]){
          matches++;
        }
      }
    }

    if(phraseWords.length !== matches){
      return false;
    }

    return true;
  },
  generatePassphrase(){    
    var bits = 192;
    var random = crypto.randomBytes( bits / 32 ).readUInt32BE(0, true);
    random = getRandomValues( bits / 32 );
    var n = words.length;
    var	phraseWords = [];
    var	x, w1, w2, w3;
    for (var i=0; i < random.length; i++) {
      x = random[i];
      w1 = x % n;
      w2 = (((x / n) >> 0) + w1) % n;
      w3 = (((((x / n) >> 0) / n) >> 0) + w2) % n;


      phraseWords.push(words[w1]);
      phraseWords.push(words[w2]);
      phraseWords.push(words[w3]);
    }

    return phraseWords.join(" ");
  },
  getPrivateKey(passPhrase){
    var bytes = simpleHash(converters.stringToByteArray(passPhrase));
    return converters.shortArrayToHexString(curve25519_clamp(converters.byteArrayToShortArray(bytes)));
  },
  getPublicKey(passPhrase){
    passPhrase = converters.stringToHexString(passPhrase);
    var secretPhraseBytes = converters.hexStringToByteArray(passPhrase);
    var digest = simpleHash(secretPhraseBytes);
    return converters.byteArrayToHexString(curve25519.keygen(digest).p);
  },
  getAccountId(passPhrase){
    let publicKey = this.getPublicKey(passPhrase)
    var hex = converters.hexStringToByteArray(publicKey);
    var account = simpleHash(hex);
    account = converters.byteArrayToHexString(account);
    var slice = (converters.hexStringToByteArray(account)).slice(0, 8);
    var accountId = byteArrayToBigInteger(slice).toString();
    return accountId;
  },
  getAddress(passPhrase){
    let accountId = this.getAccountId(passPhrase);

    let address = new Address();
    if (address.set(accountId)) {
      return address.toString();
    }
    
    return "";
  },
  signTransaction(tx, secretPhrase){
    let signature = signBytes(tx.unsignedTransactionBytes, converters.stringToHexString(secretPhrase));

    let publicKey = this.getPublicKey(secretPhrase);
    if(!verifyBytes(signature, tx.unsignedTransactionBytes, publicKey)){
      return false;
    }

    return signTransactionBytes(tx.unsignedTransactionBytes, signature, tx);
  },
  encryptMessage(message, recipientPublicKey, passphrase){
    let options = {
      nonce: crypto.randomBytes(32),
      publicKey: converters.hexStringToByteArray(recipientPublicKey),
      privateKey: converters.hexStringToByteArray(this.getPrivateKey(passphrase)),
    }
    options.sharedKey = converters.shortArrayToByteArray(
      curve25519_(
        converters.byteArrayToShortArray(options.privateKey),
        converters.byteArrayToShortArray(options.publicKey),
        null
      )
    );

    message = converters.stringToByteArray(message);
    let compressedMessage = pako.gzip(new Uint8Array(message));
    
    var data = aesEncrypt(compressedMessage, options);

    return {
      nonce: converters.byteArrayToHexString(options.nonce),
      data: converters.byteArrayToHexString(data)
    };
  }
}

function signTransactionBytes(transactionBytes, signature, tx){
  var payload = transactionBytes.substr(0, 192) + signature + transactionBytes.substr(320);
  tx.transactionBytes = payload;
  tx.transactionJSON.signature = signature;
  return tx;
}

function signBytes(message, secretPhrase) {
  var messageBytes = converters.hexStringToByteArray(message);
  var secretPhraseBytes = converters.hexStringToByteArray(secretPhrase);

  var digest = simpleHash(secretPhraseBytes);
  var s = curve25519.keygen(digest).s;
  var m = simpleHash(messageBytes);
  var x = simpleHash(m, s);
  var y = curve25519.keygen(x).p;
  var h = simpleHash(m, y);
  var v = curve25519.sign(h, x, s);

  return converters.byteArrayToHexString(v.concat(h));
};
function verifyBytes(signature, message, publicKey) {
  var signatureBytes  = converters.hexStringToByteArray(signature);
  var messageBytes    = converters.hexStringToByteArray(message);
  var publicKeyBytes  = converters.hexStringToByteArray(publicKey);
  var v = signatureBytes.slice(0, 32);
  var h = signatureBytes.slice(32);
  var y = curve25519.verify(v, h, publicKeyBytes);
  var m = simpleHash(messageBytes);
  var h2 = simpleHash(m, y);
  return areByteArraysEqual(h, h2);
}

function areByteArraysEqual(bytes1, bytes2) {
  if (bytes1.length !== bytes2.length) {
    return false;
  }
  for (var i = 0; i < bytes1.length; ++i) {
    if (bytes1[i] !== bytes2[i])
      return false;
  }
  return true;
}

function aesEncrypt(payload, options) {
  let ivBytes = crypto.randomBytes(16);
  
  // CryptoJS likes WordArray parameters
  let wordArrayPayload = converters.byteArrayToWordArray(payload);
  let sharedKey = options.sharedKey;

  if (options.nonce !== undefined) {
    for (var i = 0; i < 32; i++) {
      sharedKey[i] ^= options.nonce[i];
    }
  }

  var key = CryptoJS.SHA256(converters.byteArrayToWordArray(sharedKey));
  var encrypted = CryptoJS.AES.encrypt(wordArrayPayload, key, {
    iv: converters.byteArrayToWordArray(ivBytes)
  });
  var ivOut = converters.wordArrayToByteArray(encrypted.iv);
  var ciphertextOut = converters.wordArrayToByteArray(encrypted.ciphertext);
  
  return ivOut.concat(ciphertextOut);
}

function getRandomValues(size){
  let values = [];
  for(let i=0; i<size; i++){
    values.push(crypto.randomBytes(4).readUInt32BE(0, true));
  }
  return values;
}
function simpleHash(b1, b2){
  var sha256 = CryptoJS.algo.SHA256.create();
  sha256.update(converters.byteArrayToWordArray(b1));
  if (b2) {
    sha256.update(converters.byteArrayToWordArray(b2));
  }
  var hash = sha256.finalize();
  return converters.wordArrayToByteArrayImpl(hash, false);
}
function byteArrayToBigInteger(byteArray) {
  var value = new BigInteger("0", 10);
  var temp1, temp2;
  for (var i = byteArray.length - 1; i >= 0; i--) {
    temp1 = value.multiply(new BigInteger("256", 10));
    temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
    value = temp2;
  }
  return value;
}

module.exports = QooberUtils;