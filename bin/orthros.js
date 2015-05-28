#!/usr/bin/env node
/*
	Copyright 2015 Dylan "Haifisch" Laws
*/
var fs = require('fs');
var path = require('path');
var mkdirp = require('mkdirp');
var colors = require('colors');
var Prompt = require('prompt-improved');
var uuid = require('uuid');
var NodeRSA = require('node-rsa');
var crypto = require('crypto');
var read = require('read');
var request = require('request');
var ursa = require('ursa');
var pkginfo = require('pkginfo')(module);

var key = new NodeRSA();
var args = process.argv.slice(2);
var version = module.exports.version
var help = "Command line options;"
			+ "\n./orthros send [Recieving UUID] \"[Message]\" - Sends supplied message to UUID, put message in quotes."
			+ "\n./orthros check - Checks for messages in queue"
			+ "\n./orthros read [Message ID] - Decrypts and reads message given its ID"
			+ "\n./orthros delete [Message ID] - Deletes a message given its ID"
			+ "\n./orthros whoami - Prints your Orthros ID";
var orthros_settings =  process.env['HOME'] + "/.orthros";
var orthros_config = orthros_settings + "/config.json";
var orthros_api_url = "https://api.orthros.ninja?"
var prompt = new Prompt({
    prefix        : '',
    suffix        : ': ',
    defaultPrefix : ' (',
    defaultSuffix : ')',
    textTheme     : Prompt.chalk.bold,
    prefixTheme   : Prompt.chalk.white,
    suffixTheme   : Prompt.chalk.white,
    defaultTheme  : Prompt.chalk.white,
    inputError    : 'Error encountered, try again.',
    requiredError : 'Required! Try again.',
    invalidError  : 'Invalid input: ',
    attemptsError : 'Maximum attempts reached!',
    stdin         : process.stdin,
    stdout        : process.stdout,
    stderr        : process.stderr,
    timeout       : null
});

/* Configuration check functions */
function checkConfigDirectory (callback) {
	fs.exists(orthros_settings, function(exists) {
	    if (!exists) {
	        mkdirp(orthros_settings, function(err) {
	        	if (err) {console.log("Error settings directory in; " + orthros_settings); callback(false);};
	        	callback(true);
			});
	    } else {
	    	callback(true);
	    }
	});
}

function getConfigFile (callback) {
	fs.readFile(orthros_config, {encoding: 'utf-8'}, function(err,data){
		if (err) {
			callback(null);
		} else {
			var configParsed = JSON.parse(data);
			if (configParsed["uuid"] === null){
		    	callback(null);
			}
			callback(configParsed);
		}
	});
}

function uuid_from_config (callback) {
	var configFile = getConfigFile(function (parsedConfig) {
		if (parsedConfig === null) {
			callback(null);
		} else {
			callback(parsedConfig["uuid"]);
		};
	});
}

function all_msgs_in_que (uuid, callback) {
	request.get(orthros_api_url+'action=list&UUID='+uuid, function(error, response, body) {
		var parsedRes = JSON.parse(body);
		if (parsedRes["error"] == 1) {
		  	console.log("No messages found!");
		  	callback(null);
		} else if (parsedRes["error"] == 0) {
		  	console.log("Messages in queue;".green);
		  	var msgs = parsedRes["msgs"];
		  	callback(msgs);
		};
	});
}

function sender_for_msg (msg_id, uuid, callback) {
	request.get(orthros_api_url+'action=get&UUID='+uuid+'&msg_id='+msg_id, function(error, response, body) {
		var parsedRes = JSON.parse(body);
		if (parsedRes["msg"]) {
			callback([msg_id,parsedRes["msg"]["sender"]]);
		};
	});
}

function check_for_messages (argument) {
	var uuidFromConfig = uuid_from_config(function (uuid_ret) {
		if (uuid_ret === null) {
			console.log("We're missing the user ID from the config!".red);
		} else {
			var msgs = all_msgs_in_que(uuid_ret, function (msgs_qued) {
				if (msgs_qued != null) {
					for (var i = 0; i < msgs_qued.length; i++) {
					sender_for_msg(msgs_qued[i], uuid_ret, function (sender) {
						var d = new Date(0);
						d.setUTCSeconds(sender[0]);
						console.log(('Message ID: '+sender[0]).blue)
						console.log(('\tFrom user: '+sender[1]).green);
						console.log(('\tSent timestamp: '+d).green)
					})
				};
				};
			})
		};
	});
}

function get_private_key (callback) {
	read({ prompt : 'Password:', silent : true }, function (err, pass) {
		read({ prompt : 'Confirm password: ', silent : true }, function (err, pass_conf) {
			if (pass == pass_conf) {
				var configFile = getConfigFile(function (parsedConfig) {
					if (parsedConfig === null) {
						console.log("Private key not found!");
					} else {
						var decipher = crypto.createDecipher('aes-256-ctr',pass_conf)
						var dec = decipher.update(parsedConfig["priv"],'hex','utf8')
						dec += decipher.final('utf8');
						callback(dec)
					};
				});
			} else {
				console.log("Passwords don't match! Try again.".red);
			};
		});
	});
}

function read_message (msg_id) {
	var uuidFromConfig = uuid_from_config(function (uuid_ret) {
		if (uuid_ret === null) {
			console.log("We're missing the user ID from the config!".red);
		} else {
			request.get(orthros_api_url+'action=get&UUID='+uuid_ret+'&msg_id='+msg_id, function(error, response, body) {
				var parsedRes = JSON.parse(body);
				if (parsedRes["msg"]) {
					var crypted_msg = parsedRes["msg"]["msg"];
					crypted_msg = crypted_msg.replace(/ /g,"+");
					var privatekey = get_private_key(function (key) {
						ursa_key = ursa.createPrivateKey(key);
						var dec_msg = ursa_key.decrypt(crypted_msg, 'base64', 'utf8');
						console.log("Message: ".green + dec_msg)
					});
				};
			});
		};
	});
}

function send_message (receiver, message) {
	var uuidFromConfig = uuid_from_config(function (uuid_ret) {
		if (uuid_ret === null) {
			console.log("We're missing the user ID from the config!".red);
		} else {
			request.get(orthros_api_url+'action=download&UUID='+uuid_ret+'&receiver='+receiver, function(error, response, body) {
				var parsedRes = JSON.parse(body);
				if (parsedRes["error"] == 1) {console.log("Failed to send message, be sure that the receiving address is correct.")};
				if (parsedRes["pub"]) {
					// strip, fix, replace.
					public_key = parsedRes["pub"].replace(/-----BEGIN PUBLIC KEY-----/g,"");
					public_key = public_key.replace(/-----END PUBLIC KEY-----/g,"");
					public_key = public_key.replace(/ /g,"+");
					public_key = "-----BEGIN PUBLIC KEY-----"+public_key+"-----END PUBLIC KEY-----";
					ursa_key = ursa.createPublicKey(public_key);
					var enc_msg = ursa_key.encrypt(message, 'utf8', 'base64');
					request.get(orthros_api_url+'action=gen_key&UUID='+uuid_ret, function(error, response, body) {
						var parsedRes = JSON.parse(body);
						var privatekey = get_private_key(function (key) {
							var send_key = parsedRes["key"]
							ursa_key = ursa.createPrivateKey(key);
							var dec_key = ursa_key.decrypt(send_key, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING);
							var json_msg = {"msg":enc_msg, "sender":uuid_ret}
							request.post({
							  headers: {'content-type' : 'application/x-www-form-urlencoded'},
							  url:     orthros_api_url+'action=send&UUID='+uuid_ret+'&receiver='+receiver,
							  body:    "msg="+JSON.stringify(json_msg)+"&key="+dec_key,
							}, function(error, response, body){
								var parsedRes = JSON.parse(body);
								if (parsedRes["error"] == 1) {
									console.log("Something went wrong while sending!".red);
								} else if (parsedRes["error"] == 0) {
									console.log("Message written to queue!".green)
								}
							});
						});
					});
				};
			});
		};
	});
}

function delete_message (msg_id) {
	var uuidFromConfig = uuid_from_config(function (uuid_ret) {
		if (uuid_ret === null) {
			console.log("We're missing the user ID from the config!".red);
		} else {
			request.get(orthros_api_url+'action=gen_key&UUID='+uuid_ret, function(error, response, body) {
				var parsedRes = JSON.parse(body);
				var delete_key = parsedRes["key"]

				var privatekey = get_private_key(function (key) {
					var send_key = parsedRes["key"]
					ursa_key = ursa.createPrivateKey(key);
					var dec_key = ursa_key.decrypt(send_key, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING);
					request.post({
					  headers: {'content-type' : 'application/x-www-form-urlencoded'},
					  url:     orthros_api_url+'action=delete_msg&UUID='+uuid_ret+'&msg_id='+msg_id,
					  body:    "key="+dec_key
					}, function(error, response, body){
						var parsedRes = JSON.parse(body);
						if (parsedRes["error"] == 1) {
							console.log("Message has already been deleted or doesn't exsist!".red);
						} else if (parsedRes["error"] == 0) {
							console.log("Message deleted successfully!");
						}
					});
				});
			});
		};
	});
}

function setupAccount (argument) {
	prompt.ask([{
		question: 'Would you like to create one now?',
		key: 'answer-key',
		attempts: 3,
		required: true,
	    default: 'Y',
	    validate: /^(?:y(?:es)?|n(?:o)?)$/i,
	    after: function(value) {
	        value = value.toLowerCase();
	        if (value === 'y' || value === 'yes') return true;
	        return false;
	    }
		}], function(err, res) {
	    if (err) return console.error(err);
	    if (res["answer-key"] == true) {
	    	var gen_uuid = uuid.v4();
	    	console.log("Generating keys...".green);
	    	key.generateKeyPair(1024, 65537);
	    	read({ prompt : 'Set a password (10 character minumum, don\'t forget this!):', silent : true }, function (err, pass) {
	    		if (pass.length > 10) {
	    			read({ prompt : 'Confirm password: ', silent : true }, function (err, pass_conf) {
						if (pass == pass_conf) {
							var cipher = crypto.createCipher('aes-256-ctr',pass_conf)
							var crypted = cipher.update(key.exportKey('private'),'utf8','hex')
							crypted += cipher.final('hex');
						    var user_config = {"uuid":gen_uuid, "public_key":key.exportKey('public'), "priv":crypted};
							console.log("Submitting public key to server");
							request.post({
							  headers: {'content-type' : 'application/x-www-form-urlencoded'},
							  url:     orthros_api_url+'action=upload&UUID='+user_config["uuid"],
							  body:    "pub="+key.exportKey('public')
							}, function(error, response, body){
							  if (JSON.parse(body)["error"] == 0) {
							  	console.log("Successfully submitted!".green);
							  	fs.writeFile(orthros_config, JSON.stringify(user_config), function(err) {
									if(err) {
										return console.log(err);
									}
									console.log("Config created successfully!".green);
									var uuidFromConfig = uuid_from_config(function (uuid_ret) {
										console.log(("Your new ID: "+uuid_ret).blue);
									});
								});
							  };
							});

						} else {
							console.log("Passwords don't match! Try again.".red);
						};
					});
	    		} else {
	    			console.log("Password must be at least 10 characters.".red);
	    		}
			});
		} else {
		   console.log("Goodbye!");
		}
	});
}

function checkArgs () {
	if (args.length > 0) {
		if (args[0] == "send") {
			if (args[1] == null) {console.log("We're missing the recieving ID"); return 0;};
			if (args[1] == null) {console.log("We're missing the message to send"); return 0;};
			send_message(args[1], args[2]);
		} else if (args[0] == "check") {
			check_for_messages();
		} else if (args[0] == "read") {
			if (args[1] == null) {
				console.log("We're missing the message ID!".red);
				return 0;
			} else {
				console.log("Retrieving message: "+args[1])
				read_message(args[1]);
			}
		} else if (args[0] == "delete") {
			if (args[1] == null) {
				console.log("We're missing the message ID!".red)
				return 0;
			} else {
				console.log("Deleting message: "+args[1])
				delete_message(args[1]);
			}
		} else if (args[0] == "whoami") {
			var uuidFromConfig = uuid_from_config(function (uuid_ret) {
				if (uuid_ret === null) {
					console.log("We're missing the user ID from the config!".red);
				} else {
					console.log(("Your ID: "+uuid_ret).blue);
				};
			});
		} else {
			console.log(help);
		}
	} else {
		console.log(help);
	}
}

process.on('uncaughtException', function (err) {
	// TODO: better error checking, currently assumes the server was unreachable and returned data that couldn't be parsed.
	console.log(err.stack);
  console.log("An error was caught when performing this action.".red+"\nPlease make sure you're able to connect to the Orthros server or your own local server.");
  process.exit(1)
});

function main (argument) {
	console.log(("Orthros Messenger " + version).bgMagenta);
	var checkDir = checkConfigDirectory(function (doesExsist) {
		if (doesExsist == true) {
			fs.exists(orthros_settings+"/.development.config", function(exists) {
				fs.readFile(orthros_settings+"/.development.config", {encoding: 'utf-8'}, function(err,data){
					if (!err) {
						var configParsed = JSON.parse(data);
						if (!(configParsed["development_url"] === null)){
							if (exists) {orthros_api_url = configParsed["development_url"]; console.log("!!! Using development server !!!".red)};
						}
					}
				});
			});
			var configFile = getConfigFile(function (parsedConfig) {
				if (parsedConfig === null) {
					console.log("We're missing the user config!".red);
					setupAccount();
				} else {
					checkArgs();
				};
			});
		};
	});
}

main();
