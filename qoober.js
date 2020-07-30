var qUtils = require('./qoober-utils');
var axios = require('axios');
var FormData = require('form-data');
const QooberUtils = require('./qoober-utils');

var Qoober = {
  server_url: 'https://api.qoober.space',
  setServerUrl(server_url){
    this.server_url = server_url;
  },
  create(){
    let account = {id: '', passphrase: '', publicKey: '', address: ''}
    account.passphrase = qUtils.generatePassphrase();
    account.privateKey = qUtils.getPrivateKey(account.passphrase);
    account.publicKey = qUtils.getPublicKey(account.passphrase);
    account.address = qUtils.getAddress(account.passphrase);
    account.id = qUtils.getAccountId(account.passphrase);
    return account;
  },
  async balance(account){
    let res = await axios.get(this.server_url + '/nxt?requestType=getBalance&account='+account);
    return res.data;
  },
  async getTransactions(account, firstIndex, lastIndex){
    let res = await axios.get(this.server_url + '/nxt?requestType=getBlockchainTransactions&account='+account+'&firstIndex='+firstIndex+'&lastIndex='+lastIndex);
    return res.data;
  },
  async sendMoney(payload, secretPhrase){
    if(payload.message != ''){
      let encryptMessage = qUtils.encryptMessage(payload.message, payload.recipientPublicKey, payload.passphrase);

      payload['encrypt_message'] = 1;
      payload['messageToEncryptIsText'] = 1;
      payload['encryptedMessageIsPrunable'] = 1;
      payload['encryptedMessageData'] = encryptMessage.data;
      payload['encryptedMessageNonce'] = encryptMessage.nonce;
    }
    delete payload.message;

    var form = new FormData();
    for(let key in payload){
      form.append(key, payload[key]);
    }
    
    let res = await axios.post(this.server_url + '/nxt?requestType=sendMoney', form, {headers: form.getHeaders()});
    let txUnsigned = res.data;
    let txSigned = qUtils.signTransaction(txUnsigned, secretPhrase);
    
    form = new FormData();
    form.append('transactionBytes', txSigned.transactionBytes);
    form.append('prunableAttachmentJSON', JSON.stringify(txSigned.transactionJSON.attachment));
    let resBroadcast = await axios.post(this.server_url + '/nxt?requestType=broadcastTransaction', form, {headers: form.getHeaders()});
    if(resBroadcast.data && resBroadcast.data.transaction){
      return {
        transaction: resBroadcast.data.transaction,
        fullHash: resBroadcast.data.fullHash,
      }
    }

    throw("send error");
  }
}

module.exports = Qoober;