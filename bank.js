'use strict'

var express = require('express');
var session = require('client-sessions');
var mysql = require('mysql');
var parseBody = require('body-parser');
var xssFilters = require('xss-filters');
var domPure = require('dompurify');
var parseString = require('xml2js').parseString;
var fs = require('fs');
const bcrypt = require('bcrypt');
const csp = require('helmet-csp');
const validatePW = require('owasp-password-strength-test');
const https = require('https');

var app = express();

var db = mysql.createConnection({
    host: 'localhost',
    user: 'bank',
    password: 'test.bank.pass',
    database: 'test'
});
db.connect(function(err){
    if(err)
    {
		console.log('Could not connect to db\n');
		throw err;
	}
	else
	{
		console.log('Connected to db\n');
	}
});

app.use(parseBody.urlencoded({extended: true}));

app.use(csp({
    directives:{
        defaultSrc:["'self'"],
        scriptSrc:["'self'"]
    }
}));

app.use(session({
    cookieName: 'loggedin',
    secret: 'scalable.surface.parked.staunch.flag',
    duration: 3 * 60 * 1000, //min * sec/min * milli/sec
    ativeDuration: 3 * 60 * 1000,
    httpOnly: true,
    secure: true,
    ephemeral: true
}));

app.use(session({
	cookieName: 'account',
	secret: 'tall.faced.plastic.neural.robins',
	duration: 3 * 60 * 1000,
    ativeDuration: 3 * 60 * 1000,
    httpOnly: true,
    secure: true,
    ephemeral: true
}));

var rounds = 10;//for bcrypt

var options = {
	key: fs.readFileSync('serverkey.pem'),
	cert: fs.readFileSync('servercert.pem'),
	ca: fs.readFileSync('cacert.pem')
};

app.get('/', function(req, res){
    if(req.loggedin.id === undefined)
    {
        res.sendFile(__dirname + '/index.html');
    }
    else
    {
        res.redirect('/home');       
    }
});

app.get('/login', function(req, res){
    if(req.loggedin.id === undefined)
    {
        res.sendFile(__dirname + '/login.html');
    }
    else
    {
        res.redirect('/home');
    }
});

app.get('/signup', function(req, res){
    if(req.loggedin.id === undefined)
    {
        res.sendFile(__dirname + '/signup.html');
    }
    else
    {
        res.redirect('/home');
    }
});

app.get('/logout', function(req, res){
    req.loggedin.reset();
    res.redirect('/');
});

app.get('/home', function(req, res){
    if(req.loggedin.id === undefined)
    {
        res.redirect('/login');
    }
    else
    {
        res.sendFile(__dirname + '/home.html');
    }
});

app.get('/accounts', function(req, res){
	if(req.loggedin.id === undefined)
	{
		res.redirect('/login');
	}
	else
	{
		var prep = 'SELECT * FROM accounts WHERE idUsers = ?';
		var insert = [req.loggedin.id];
		prep = mysql.format(prep, insert);
		console.log('Sending this query to the db:\n\t' + prep + '\n\n');
		
		db.query(prep, function(err, result){
			if(err)
			{
				console.log('Error while searching for accounts of user\n');
				throw err;
			}
			else
			{
				var dynHTML;
				fs.readFile('accounts.html', function(err, data){
					dynHTML = data;
					for(let i = 0; i < Object.keys(result).length; i++)
					{
						dynHTML += '<li><a href=\'/accounts/' + xssFilters.inHTMLData(result[i].idAcc) + '\'>' + xssFilters.inHTMLData(result[i].accountname) + '</a></li>';
					}
					dynHTML += '</ul></div></body></html>';
					res.send(dynHTML);
				});
			}
		});
	}
})

app.post('/addAcct', function(req, res){
	if(req.loggedin.id === undefined)
	{
		res.redirect('/login');
	}
	else
	{
		var prep = 'INSERT INTO accounts (idUsers, balance, accountname) VALUES(?, ?, ?)';
		var insert = [req.loggedin.id, 0, req.body.acctnm];
		prep = mysql.format(prep, insert);
		console.log('Sending this query to the db:\n\t' + prep + '\n\n');
		
		db.query(prep, function(err, result){
			if(err)
			{
				console.log('Error while inserting new account\n');
				throw err;
			}
			else
			{
				res.redirect('/accounts');
			}
		});
	}
})

app.get('/accounts/:uuid', function(req, res){
	if(req.loggedin.id === undefined)
	{
		res.redirect('/login');
	}
	else
	{
		req.account.reset();
		var prep = 'SELECT * FROM accounts WHERE idAcc = ?';
		var insert = [req.params.uuid]
		prep = mysql.format(prep, insert);
		console.log('Sending this query to the db:\n\t' + prep + '\n\n');
		
		db.query(prep, function(err, result){
			if(Object.keys(result).length === 0)
			{
				res.redirect('/accounts');
			}
			else
			{
				req.account.uuid = result[0].idAcc;
				res.sendFile(__dirname + '/options.html');
			}
		});
	}
})

app.get('/balance', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var prep = 'SELECT balance FROM accounts WHERE idAcc = ?';
			var insert = [req.account.uuid];
			prep = mysql.format(prep, insert);
			console.log('Sending this query to the db\n\t' + prep + '\n\n');
			
			db.query(prep, function(err, result){
				if(err){
					console.log('Error balance query\n');
					throw err;
				}
				else{
					var dynHTML = '<!DOCTYPE html><html><head><title>Balance</title></head><body><p>Your balance is: <strong>' + xssFilters.inHTMLData(result[0].balance) + '</strong>.<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</p></body></html>';
					res.send(dynHTML);
				}
			});
		}
	}
});

app.get('/withdraw', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var dynHTML = '<!DOCTYPE html><html><head><title>Withdraw</title></head><body><p><strong>Please Set an amount to withdraw:</strong></p><form action=\'/wr\' method=\'post\'><label>Amount: <input type=\'number\' name=\'amnt\' placeholder=\'Amount\' min=\'0\' step=\'0.01\' required></label><br><button type=\'submit\'>Submit</button></form><br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</body></html>';
			res.send(dynHTML);
		}
	}
});

app.post('/wr', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var prep = 'SELECT balance FROM accounts WHERE idAcc = ?';
			var insert = [req.account.uuid];
			prep = mysql.format(prep, insert);
			console.log('Sending this query to the db\n\t' + prep + '\n\n');
			
			db.query(prep, function(err, result){
				if(err){
					console.log('Error balance query for withdrawal\n');
					throw err;
				}
				else{
					var dynHTML;
					var sub = Number(result[0].balance) - Number(req.body.amnt);
					sub.toFixed(2);
					if(sub >= 0){
						var prp = 'UPDATE accounts SET balance = ? WHERE idAcc = ?';
						var ins = [sub, req.account.uuid];
						prp = mysql.format(prp, ins);
						console.log('Sending this query to the db\n\t' + prp + '\n\n');
						
						db.query(prp, function(er, rslt){
							if(er){
								console.log('Error update query for withdrawal\n');
								throw er;
							}
							else{
								dynHTML = '<!DOCTYPE html><html><head><title>Results</title></head><body><p>You successfully withdrew <strong>$' + xssFilters.inHTMLData(req.body.amnt) + '</strong>.<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</p></body></html>';
								res.send(dynHTML);
							}
						});
					}
					else{
						dynHTML = '<!DOCTYPE html><html><head><title>Error</title></head><body><p>Insufficient Funds<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to try again.</p></body></html>';
						res.send(dynHTML);
					}
				}
			});
		}
	}
});

app.get('/deposit', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var dynHTML = '<!DOCTYPE html><html><head><title>Deposit</title></head><body><p><strong>Please Set an amount to deposit:</strong></p><form action=\'/dr\' method=\'post\'><label>Amount: <input type=\'number\' name=\'amnt\' placeholder=\'Amount\' min=\'0\' step=\'0.01\' required></label><br><button type=\'submit\'>Submit</button></form><br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</body></html>';
			res.send(dynHTML);
		}
	}
});

app.post('/dr', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var prep = 'SELECT balance FROM accounts WHERE idAcc = ?';
			var insert = [req.account.uuid];
			prep = mysql.format(prep, insert);
			console.log('Sending this query to the db\n\t' + prep + '\n\n');
			
			db.query(prep, function(err, result){
				if(err){
					console.log('Error balance query for deposit\n');
					throw err;
				}
				else{
					var dynHTML;
					var sub = Number(result[0].balance) + Number(req.body.amnt);
					sub.toFixed(2);
					var prp = 'UPDATE accounts SET balance = ? WHERE idAcc = ?';
					var ins = [sub, req.account.uuid];
					prp = mysql.format(prp, ins);
					console.log('Sending this query to the db\n\t' + prp + '\n\n');
					
					db.query(prp, function(er, rslt){
						if(er){
							console.log('Error update query for deposit\n');
							throw er;
						}
						else{
							dynHTML = '<!DOCTYPE html><html><head><title>Results</title></head><body><p>You successfully deposited <strong>$' + xssFilters.inHTMLData(req.body.amnt) + '</strong>.<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</p></body></html>';
							res.send(dynHTML);
						}
					});
				}
			});
		}
	}
});

app.get('/transfer', function(req, res){
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var prep = 'SELECT * FROM accounts WHERE idUsers = ? AND NOT idAcc = ?';
			var insert = [req.loggedin.id, req.account.uuid];
			prep = mysql.format(prep, insert);
			console.log('Sending this query to the db\n\t' + prep + '\n\n');
			
			db.query(prep, function(err, result){
				if(err){
					console.log('Error fetching accounts for transfer\n');
					throw err;
				}
				else{
					var dynHTML;
					if(Object.keys(result).length < 1){
						dynHTML = '<!DOCTYPE html><html><head><title>Error</title></head><body><p>You need at least two accounts to make a transfer<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to try again.</p></body></html>';
						res.send(dynHTML);
					}
					else{
						fs.readFile('transfer.html', function(e, data){
							dynHTML = data;
							for(let i = 0; i < Object.keys(result).length; i++){
								dynHTML += '<option value=\'' + xssFilters.inHTMLData(result[i].idAcc) + '\'>' + xssFilters.inHTMLData(result[i].accountname) + '</option>';
							}
							dynHTML += '</select><br><button type=\'submit\'>Transfer</button></form></body></html>';
							res.send(dynHTML);
						});
					}
				}
			});
		}
	}
});

app.post('/tr', function(req, res){//TODO
	if(req.loggedin.id === undefined){
		res.redirect('/');
	}
	else{
		if(req.account.uuid === undefined){
			res.redirect('/accounts');
		}
		else{
			var prep = 'SELECT * FROM accounts WHERE (idAcc = ? OR idAcc = ?) AND idUsers = ?';
			var insert = [req.account.uuid, req.body.uuid, req.loggedin.id];
			prep = mysql.format(prep, insert);
			console.log('Sending this query to the db\n\t' + prep + '\n\n');
			
			db.query(prep, function(err, result){
				if(err){
					console.log('Error transfer prepare query\n');
					throw err;
				}
				else{
					var from, to;
					if(result[0].idAcc === req.account.uuid){
						from = Number(result[0].balance);
						to = Number(result[1].balance);
					}
					else{
						to = Number(result[0].balance);
						from = Number(result[1].balance);
					}
					var sub = from - Number(req.body.amnt);
					sub.toFixed(2);
					console.log('from: ' + from + ' to: ' + to);
					if(sub < 0){
						var dynHTML = '<!DOCTYPE html><html><head><title>Error</title></head><body><p>Insufficient Funds<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to try again.</p></body></html>';
						res.send(dynHTML);
					}
					else{
						var add = to + Number(req.body.amnt)
						var prp = 'UPDATE accounts SET balance = ? WHERE idAcc = ?';
						var ins = [sub, req.account.uuid];
						prp = mysql.format(prp, ins);
						console.log('Sending this query to the db\n\t' + prp + '\n\n');
						
						db.query(prp, function(er, rslt){
							if(er){
								console.log('Error updating `from` acc on transfer\n');
								throw er;
							}
							else{
								var p = 'UPDATE accounts SET balance = ? WHERE idAcc = ?';
								var i = [add, req.body.uuid]
								p = mysql.format(p, i);
								console.log('Sending this query to the db\n\t' + p + '\n\n');
								
								db.query(p, function(e, r){
									if(e){
										console.log('Error updating `to` acc on transfer\n');
										throw e;
									}
									else{
										var dynHTML = '<!DOCTYPE html><html><head><title>Results</title></head><body><p>You successfully transferred <strong>$' + xssFilters.inHTMLData(req.body.amnt) + '</strong>.<br>Click <a href=\'/accounts/' + xssFilters.inHTMLData(req.account.uuid) + '\'>here</a> to go back.</p></body></html>';
										res.send(dynHTML);
									}
								});
							}
						});
					}
				}
			});
		}
	}
})

app.post('/attempt', function(req, res){
    console.log('login attempt\n');
   
    var dynHTML = '';
    
    var prep = 'SELECT * FROM users WHERE username = ?';
    var insert = [req.body.usrnm];
    prep = mysql.format(prep, insert);
    console.log('Sending this query to the db:\n\t' + prep + '\n\n');
    
    db.query(prep, function(err, result){
        if(err)
        {
            console.log('Error while retrieving username from database on login attempt\n');
            throw err;
        }
        else
        {
			if(Object.keys(result).length === 0)
			{
				console.log('Username `' + req.body.usrnm + '` does not exist\n');
				dynHTML = '<!DOCTYPE html><html><head><title>VSOB Error</title></head><body><p>Username or password incorrect.<br><a href=\'/login\'>Click here to try again</a></p></body></html>';
			}
			else
			{
				bcrypt.compare(req.body.pswd, result[0].password, function(er, rslt){
					if(rslt == true)
					{
						req.loggedin.id = result[0].idUsers;
						res.redirect('/home');
					}
					else
					{
						console.log(result[0].password);
						console.log('\nIncorrect input password: ' + req.body.pswd + '\n');
						dynHTML = '<!DOCTYPE html><html><head><title>VSOB Error</title></head><body><p>Username or password incorrect.<br><a href=\'/login\'>Click here to try again</a></p></body></html>';
						res.send(dynHTML);
					}
				});
			}
        }
    });
});

app.post('/create', function(req, res){//TODO use password strength validator
    console.log('New user creation attempt\n');
    var pwis = validatePW.test(req.body.pswd);
    var dynHTML;
    if(pwis.strong){
		var prep = 'SELECT * FROM users WHERE username = ?';
		var insert = [req.body.usrnm];
		prep = mysql.format(prep, insert);
		console.log('Sending this query to the db:\n\t' + prep + '\n\n');
		
		db.query(prep, function(err, result){
			if(err)
			{
				console.log('Error while retrieving username on new user creation\n');
				throw err;
			}
			else
			{
				if(Object.keys(result).length === 0) //empty result means username does not exist in db yet (i.e. successful account creation)
				{
					bcrypt.hash(req.body.pswd, rounds, function(error, hp){
						var sql = 'INSERT INTO users (username, password, firstname, lastname, address) VALUES (?, ?, ?, ?, ?)';
						var ins = [req.body.usrnm, hp, req.body.fname, req.body.lname, req.body.address];
						sql = mysql.format(sql, ins);
						console.log('Sending this query to the db:\n\t' + sql + '\n\n');
					
						db.query(sql, function(er, rslt){
							if(er)
							{
								console.log('Error on insert new account into db\n');
								throw er;
							}
							else
							{
								req.loggedin.id = rslt.insertId;
								res.redirect('/home');
							}
						});
					});
				}
				else //non-empty result means username already taken (ask user to pick a different username)
				{
					console.log('Username taken\n');
					dynHTML = '<!DOCTYPE html><html><head><title>VSOB Error</title></head><body><p>Sorry, that username is already taken. Please choose a different username.<br><a href=\'/signup\'>Click here to try again</a></p></body></html>';
					res.send(dynHTML);
				}
			}
		});
	}
	else{//weak password
		dynHTML = '<!DOCTYPE html><html><head><title>VSOB Error</title></head><body><p>Sorry, that is a pathetic password. Please read the strong password guidelines and then choose a stronger password<br><a href=\'/signup\'>Click here to try again</a></p></body></html>';
		res.send(dynHTML);
	}
});

app.get('/exit', function(req, res){
	req.loggedin.reset();
	req.account.reset();
	res.redirect('/');
})

https.createServer(options, app).listen(3000);
