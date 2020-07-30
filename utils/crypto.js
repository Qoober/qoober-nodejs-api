import words from './utils/words.js'
import Address from './utils/address.js'
import curve25519 from './utils/curve25519.js'
import converters from './utils/converters.js'

const CryptoJS = require("crypto-js");
const getRandomValues = require('get-random-values');
const BigInteger = require("big-integer");

export default {
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
    var random = new Uint32Array(bits / 32);
    getRandomValues(random);
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
  }
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