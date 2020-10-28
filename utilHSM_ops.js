/*
 *  Copyright (C) 2018 SafeNet. All rights reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const path = require('path');
const fs = require('fs-extra');
const util = require('util');
var jsrsa = require('jsrsasign');
var KEYUTIL = jsrsa.KEYUTIL;
var ecdsaKey = require('fabric-client/lib/impl/ecdsa/key.js');
const Client = require('fabric-client');
const copService = require('fabric-ca-client/lib/FabricCAServices.js');
const User = require('fabric-client/lib/User.js');
const PKCS11_LIB = '/etc/hyperledger/fabric/dpod/fabric/libs/64/libCryptoki2.so';
const PKCS11_SLOT = 0;
const PKCS11_PIN = 'Password';
const PKCS11_USER_TYPE = 1;

const CRYPTO_SUITE_OPTS = {software: false, lib: PKCS11_LIB, slot: PKCS11_SLOT, pin: PKCS11_PIN, user_type: PKCS11_USER_TYPE};

module.exports.KVS = '/tmp/hfc-kvs'
module.exports.storePathForOrg = function(org) {
	return module.exports.KVS
};

console.log('sdk-node : test utilHSM');
var client = Client.loadFromConfig('../fabric-sdk-node/artifacts/network.yaml');

console.log('sdk-node : call createChannel');
var create_response = createChannel(client);
console.log('sdk-node : create channel response : ' + JSON.stringify(create_response));
console.log('sdk-node : call installChaincode');
var install_response = installChaincode(client);
console.log('sdk-node : install chaincode response : ' + JSON.stringify(install_response));

testClient(client);
const tlsOptions = {
	trustedRoots: [],
	verify: false
};

function getMember(username, password, client) {
	console.log('sdk-node : getMember');
	const caUrl = 'https://<url>:10002';
	const caName = 'testInstanceca';

	const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	if (client._stateStore) {
		cryptoSuite.setCryptoKeyStore(Client.newCryptoKeyStore({path: module.exports.storePathForOrg('testInstance')}));
	}
	client.setCryptoSuite(cryptoSuite);

	return client.getUserContext(username, true)
		.then((user) => {
			// eslint-disable-next-line no-unused-vars
			return new Promise((resolve, reject) => {
				if (user && user.isEnrolled()) {
					console.log('sdk-node : successfully loaded member from persistence');
					return resolve(user);
				}

				const member = new User(username);
				member.setCryptoSuite(cryptoSuite);

				// need to enroll it with CA server
				const cop = new copService(caUrl, tlsOptions, caName, cryptoSuite);

				return cop.enroll({
					enrollmentID: username,
					enrollmentSecret: password
				}).then((enrollment) => {
					console.log('sdk-node : Successfully enrolled user ' + username);
					return member.setEnrollment(enrollment.key, enrollment.certificate, 'testInstance');
				}).then(() => {
					let skipPersistence = false;
					if (!client.getStateStore()) {
						skipPersistence = true;
					}
					return client.setUserContext(member, skipPersistence);
				}).then(() => {
					return resolve(member);
				}).catch((err) => {
					console.log('sdk-node : failed to enroll and persist user. error: ' + err.stack ? err.stack : err);
				});
			});
		});
}

module.exports.setAdmin = function(client) {
	return getAdmin(client);
};

async function getAdmin(client) {
//function getAdmin(client) {
	console.log('sdk-node : getAdmin');
	const certPath = '../fabric-sdk-node/artifacts/crypto/peerOrganizations/testInstance/admincert/';
	const certPEM = readAllFiles(certPath)[0];
	console.log('sdk-node : getAdmin : newCryptoSuite');
	//const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	const cryptoSuite = Client.newCryptoSuite({software: false, hash: 'SHA2', keysize: 256, lib: '/etc/hyperledger/fabric/dpod/fabric/libs/64/libCryptoki2.so', slot: 0, pin: 'Password', usertype: 1});
	console.log('sdk-node : getAdmin : newCryptoSuite : instantiated');
	cryptoSuite.setCryptoKeyStore(Client.newCryptoKeyStore({ path: '/tmp/hfc-test-kvs_peerOrg1' }));
	console.log('sdk-node : getAdmin : newCryptoSuite : setCryptoKeyStore : done');
	client.setCryptoSuite(cryptoSuite);
	console.log('sdk-node : getAdmin : newCryptoSuite : set');
	const key = KEYUTIL.getKey(certPEM.toString());
	console.log('sdk-node : getAdmin : newCryptoSuite : geyKey done');
	const key2 = new ecdsaKey(key);
	const privateKeyObj = await cryptoSuite.getKey(Buffer.from(key2.getSKI(), 'hex'));
	//const privateKeyObj = cryptoSuite.getKey(Buffer.from(key2.getSKI(), 'hex'));
	console.log('sdk-node : getAdmin : newCryptoSuite : privateKeyObj done');
	return Promise.resolve(client.createUser({
		username: 'peerorg1Admin',
		mspid: 'testInstance',
		cryptoContent: {
			privateKeyObj: privateKeyObj,
			signedCertPEM: certPEM.toString()
		}
	}));
}

async function getOrdererAdmin(client) {
	const certPath = '../fabric-sdk-node/artifacts/crypto/ordererOrganizations/testInstance/admincert/';
	const certPEM = readAllFiles(certPath)[0];

	const cryptoSuite = Client.newCryptoSuite(CRYPTO_SUITE_OPTS);
	client.setCryptoSuite(cryptoSuite);

	const key = KEYUTIL.getKey(certPEM.toString());
	const key2 = new ecdsaKey(key);
	const privateKeyObj = await cryptoSuite.getKey(Buffer.from(key2.getSKI(), 'hex'));

	return Promise.resolve(client.createUser({
		username: 'peerorg1Admin',
		mspid: 'testInstance',
		cryptoContent: {
			privateKeyObj: privateKeyObj,
			signedCertPEM: certPEM.toString()
		}
	}));
}

function readAllFiles(dir) {
	const files = fs.readdirSync(dir);
	const certs = [];
	files.forEach((file_name) => {
		const file_path = path.join(dir, file_name);
		console.log('looking at file ::' + file_path);
		const data = fs.readFileSync(file_path);
		certs.push(data);
	});
	return certs;
}

module.exports.getOrderAdminSubmitter = function(client) {
	return getOrdererAdmin(client);
};

async function getSubmitter(client, peerAdmin) {
//module.exports.getSubmitter = function(client, peerAdmin) {
	console.log('sdk-node : getSubmitter');
	//client.setStateStore('/tmp/hfc-kvs');
	console.log('sdk-node : getSubmitter : get store object');
	const store = await Client.newDefaultKeyValueStore({
		path: '/tmp/hfc-test-kvs_peerOrg1'});
	console.log('sdk-node : getSubmitter : setStateStore');
	client.setStateStore(store);
	console.log('sdk-node : getSubmitter : setStateStore : done');
	if (peerAdmin) {
		return getAdmin(client);
	} else {
		return getAdmin(client);
		//return getMember('admin', 'adminpw', client, userOrg);
	}
}
function installChaincode(client) {
	console.log('sdk-node : installChaincode : call getSubmitter');
	getSubmitter(client, true).then((admin) => {
		console.log('sdk-node : test installChaincode : done getSubmitter');
		const peers = client.getPeersForOrg('testInstance');
		console.log('sdk-node : test installChaincode : peers : ' + JSON.stringify(peers));
		console.log('sdk-node : test installChaincode : send proposal to install');
		var chaincodePath = '../fabric-sdk-node/BalanceTransfer/artifacts/src/github.com/node/';
		var request = {
			targets: peers,
			chaincodePath: chaincodePath,
			//metadataPath: metadata_path, // notice this is the new attribute of the request
			chaincodeId: 'ccexample02',
			chaincodeType: 'node',
			chaincodeVersion: 'v0'
		};
		const results = client.installChaincode(request);
	}).then((results) => {
			console.log('sdk-node : test installChaincode : then');
			//var proposalResponses = results[0];
			// console.log('sdk-node : test installChaincode : Responses : ' + JSON.stringify(proposalResponses));
			// check the results
		}, (err) => {
			console.log('sdk-node : test installChaincode : failed to send install proposal due to error: ' + err.stack ? err.stack : err);
	}).catch( err=> {
			console.log('sdk-node : test installChaincode : catch');
			console.log('sdk-node : exception installChaincode : ' + err.stack ? err.stack : err);
			return Promise.reject(err);
	});
}

function createChannel(client) {
//try {
	console.log('sdk-node : test CreateChannel : call getSubmitter');
	getSubmitter(client, true).then((admin) => {
		console.log('sdk-node : test CreateChannel : done getSubmitter');
		console.log('sdk-node : test CreateChannel : read in the file to get binary config envelope');
		// get the correct channel.tx using configtxgen
		let envelope_bytes = fs.readFileSync('../fabric-sdk-node/artifacts/d2b20c0f-7d2f-4a55-a031-baa1d1c4693e-orderer0.tx');
		//let adminKey = fs.readFileSync(path.join(__dirname, '..','..','..','fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/pem.key'));
		//let adminCert = fs.readFileSync(path.join(__dirname, '..','..','..','fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/cacerts/ca.org1.example.com-cert.pem'));
		//client.setAdminSigningIdentity(adminKey.toString(),adminCert.toString(),"Org1MSP")
		// have the nodeSDK extract out the config update
		var signatures = new Array();

		var config_update = client.extractChannelConfig(envelope_bytes);
		console.log('sdk-node : test CreateChannel : extractChannelConfig done');
		var configSignature=client.signChannelConfig(config_update)
		console.log('sdk-node : test CreateChannel : signChannelConfig done');

		signatures.push(configSignature);
		// create an orderer object to represent the orderer of the network
		var orderer=client.getOrderer("d2b20c0f-7d2f-4a55-a031-baa1d1c4693e-orderer0");
		console.log('sdk-node : test CreateChannel : orderer constructed');
		let request = {
			config: config_update, //the binary config
			signatures: signatures, // the collected signatures
			name: 'default', // the channel name
			orderer: orderer, //the orderer from above
			txId: client.newTransactionID(true) //the generated transaction id
		};
		console.log(`configupdate${config_update}`);
		// this call will return a Promise
		console.log("sdk-node : test CreateChannel : transaction sent");
		const result = client.updateChannel(request);
	}).then((result) => {
		//const result = await client.createChannel(request);
		console.log("sdk-node : test CreateChannel : done ");
		console.log("sdk-node " + JSON.stringify(result));
		/*
		if(result.status && result.status === 'SUCCESS') {
			return Promise.resolve(result.status);
		} else {
			return Promise.reject(result.status);
		}
		*/
	}, (err) => {
		console.log('sdk-node : err');
		return Promise.reject(err);
	}).catch( err=> {
		console.log('sdk-node : catch');
		console.log('sdk-node : exception on create channel: ' + err.stack ? err.stack : err);
		return Promise.reject(err);
	});
	/*
	return {
		status: 200,
		data: {
			data: JSON.parse(result.toString())
		}
	};
	*/
/*
} catch (error) {
	console.log(`sdk-node : test CreateChannel : Failed to evaluate transaction: ${error}`);
	//  process.exit(1);
	return {
		status: 400,
		data: {
			data: `${error}`
		}
	};
 */
}


function testClient(client) {
	console.log('sdk-node : testClient : call getSubmitter');
	getSubmitter(client, true);
	console.log('sdk-node : testClient : getPeersForOrgOnChannel');
	const orgPeers = client.getPeersForOrgOnChannel('default');
	console.log('sdk-node : testClient : orgPeers' + JSON.stringify(orgPeers));
}
