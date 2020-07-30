# Qoober API

```
/create - Create new account and return all parameters
```	
```
/balance?account=QOOB-... - Return account balance
```	
```
/transactions?account=QOOB-... - Return account transactions
```	
```
/send - Send request add parameters:
recipient - Recipient Address (QOOB-...)
recipientPublicKey - Recipient Public Key
amount - Amount, example: 10.55
fee - default 0, or minimum 1 QOOB
message - Text message to send
publicKey - Sender Public Key
secretPhrase - Sender Secret Phrase (18 words)
```	