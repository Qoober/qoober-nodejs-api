var express = require('express');
var app = express();

var api_port = 3000;
var api_host = '127.0.0.1';
var qoober_server_url = 'https://rpc.qoober.space/';

app.use(express.urlencoded());
app.use(express.json());

app.use(function(req, res, next) {
	res.setHeader('Content-Type', 'application/json');
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});

function getParam(name, req){
	var value = (typeof req.query[name] == 'object') ? req.query[name][0] : req.query[name];
	if(req.body && req.body[name]){
		value = req.body[name];
	}
	return value;
}

var qoober = require('./qoober');
qoober.setServerUrl(qoober_server_url);

app.all('/', function (req, res) {
	res.json( "Incorrect request" );
});

app.all('/create', function (req, res) {
  try{
		res.json( qoober.create() )
	}catch(err){ res.json( {error: 'unknow'} ) }
});

app.all('/balance', async function (req, res) {
	let account = getParam('account', req);

  try{
		res.json( await qoober.balance(account) )
	}catch(err){ res.json( {error: 'unknow'} ) }
});

app.all('/transactions', async function (req, res) {
	let account = getParam('account', req);
	let firstIndex = parseInt(getParam('firstIndex', req));
	let lastIndex = parseInt(getParam('lastIndex', req));
	
	if(!firstIndex || firstIndex < 0) firstIndex = 0;
	if(!lastIndex || lastIndex < 1) firstIndex = 15;

  try{
		res.json( await qoober.getTransactions(account, firstIndex, lastIndex) )
	}catch(err){ res.json( {error: 'unknow'} ) }
});

app.all('/send', async function (req, res) {
	let amount = parseFloat(getParam('amount', req));
	if(!amount || amount < 0) amount = 0;
	
	let fee = parseFloat(getParam('fee', req));
	if(!fee || fee < 0) fee = 0;

	let secretPhrase = getParam('secretPhrase', req);
	let message = getParam('message', req);
	if(!message) message = '';

	let payload = {
		recipient: getParam('recipient', req),
		recipientPublicKey: getParam('recipientPublicKey', req),
		publicKey: getParam('publicKey', req),
		secretPhrase: "",
		amountNQT: parseInt(amount * 100),
		feeNQT: parseInt(fee * 100),
		deadline: 1440,
		message: message,
	};

	let data = await qoober.sendMoney(payload, secretPhrase);

  try{
		res.json({
			payload: payload,
			send: data,
		})
	}catch(err){ res.json( err ) }
});

app.listen(api_port, api_host, function () {
  console.log('Qoober API listening on port '+ api_port +' at ' + api_host);
});