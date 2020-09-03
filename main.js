var EC = require('elliptic').ec;
var EdDSA = require('elliptic').eddsa;
var pbkdf2 = require('pbkdf2');
var scrypt = require('scrypt-js');
var bs58 = require('bs58');
var shajs = require('sha.js')
var Ripemd160 = require ('ripemd160');
var keccak = require('keccak');
var BN = require('bn.js');

var OPS = require('bitcoin-ops');
var typeforce = require('typeforce');
var pushdata = require('pushdata-bitcoin');
var bech32 = require('bech32');

var s256 = new EC('secp256k1');
var ed25519 = new EdDSA('ed25519');

function sha256(s) {
  return shajs('sha256').update(s).digest();
}

function ripemd160(s) {
  return (new Ripemd160()).update(s).digest();
}

function hash160 (buffer) {
  return ripemd160(sha256(buffer));
}

function encode(pubKeyHash) {
   typeforce(typeforce.BufferN(20), pubKeyHash);
  return compile([OPS.OP_0, pubKeyHash]);
}

function keccak256(s) {
  return keccak('keccak256').update(s).digest();
}
function keccak256(s) {
  return keccak('keccak256').update(s).digest();
}

function reduce32(s) {
  return (new BN(s, 'le').mod(new BN('1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed', 16))).toArrayLike(Buffer, 'le', 32);
}

function b58checkencode(version, buffer, toCompress=false) {
  buffer = Buffer.concat([Buffer.alloc(1, version), buffer])

  if(toCompress) buffer = Buffer.concat([buffer, Buffer.alloc(1, 01)]);

  var hash = sha256(sha256(buffer));
  buffer = Buffer.concat([buffer, hash.slice(0, 4)]);
  var encoded = bs58.encode(buffer);
  return encoded;
}

function toBech32(data, version, prefix) {
  var words = bech32.toWords(data)
  words.unshift(version)

  return bech32.encode(prefix, words)
}

function bech32Encode (outputScript) {
  var bech32 = 'bc';

  if(pubKeyHashCheck(outputScript)) return toBech32(compile(outputScript).slice(2, 22), 0, bech32)
  if(scriptHashCheck(outputScript)) return toBech32(compile(outputScript).slice(2, 34), 0, bech32)

  throw new Error('No matching Address')
}

function pubKeyHashCheck(script) {
  var buffer = compile(script)

  return buffer.length === 22 &&
    buffer[0] === OPS.OP_0 &&
    buffer[1] === 0x14
}

function scriptHashCheck(script) {
  var buffer = compile(script)

  return buffer.length === 34 &&
    buffer[0] === OPS.OP_0 &&
    buffer[1] === 0x20
}

function compile(chunks) {
  // TODO: remove me
  if (Buffer.isBuffer(chunks)) return chunks

  typeforce(typeforce.Array, chunks)
  var bufferSize = chunks.reduce(function (accum, chunk) {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && (chunk[0] === 0x81 || (chunk[0] >= 1 && chunk[0] <= 16))) {
        return accum + 1
      }

      return accum + pushdata.encodingLength(chunk.length) + chunk.length
    }

    // opcode
    return accum + 1
  }, 0.0)
  var buffer = Buffer.alloc(bufferSize)
  var offset = 0

  chunks.forEach(function (chunk) {
    // data chunk
    if (Buffer.isBuffer(chunk)) {
      // adhere to BIP62.3, minimal push policy
      if (chunk.length === 1 && chunk[0] >= 1 && chunk[0] <= 16) {
        var opcode = OP_INT_BASE + chunk[0]
        buffer.writeUInt8(opcode, offset)
        offset += 1
        return
      }

      if (chunk.length === 1 && chunk[0] === 0x81) {
        buffer.writeUInt8(OPS.OP_1NEGATE, offset)
        offset += 1
        return
      }

      offset += pushdata.encode(buffer, chunk.length, offset)

      chunk.copy(buffer, offset)
      offset += chunk.length

    // opcode
    } else {
      buffer.writeUInt8(chunk, offset)
      offset += 1
    }
  })

  if (offset !== buffer.length) throw new Error('Could not decode chunks')
  return buffer
}

function keyToBitcoinish(key, version) {
  var pubkey = Buffer.from(s256.keyFromPrivate(key).getPublic(false, 'hex'), 'hex');
  return {
    private: b58checkencode(version + 0x80, key),
    public: b58checkencode(version, ripemd160(sha256(pubkey))),
  };
}

function keyToBitcoin(key) {
  return keyToBitcoinish(key, 0);
}

function keyToLitecoin(key) {
  return keyToBitcoinish(key, 48);
}

function keyToSegwit(key) {
  var pubKey = Buffer.from(s256.keyFromPrivate(key).getPublic(true, 'hex'), 'hex');
  var scriptHashKey = encode(hash160(pubKey));
  return {
    private: b58checkencode(0 + 0x80, key, true),
    public: bech32Encode(scriptHashKey)
  }
}

function keyToEthereum(key) {
  var pubkey = Buffer.from(s256.keyFromPrivate(key).getPublic(false, 'hex'), 'hex');
  return {
    private: key.toString('hex'),
    public: '0x' + keccak256(pubkey.slice(1)).slice(12).toString('hex')
  };
}

function keyToMonero(seed) {
  var private_spend = reduce32(seed);
  var private_view = reduce32(keccak256(private_spend));

  // Hack
  var kp = ed25519.keyFromSecret()
  kp._privBytes = Array.from(private_spend);
  var public_spend = Buffer.from(kp.pubBytes());
  var kp = ed25519.keyFromSecret()
  kp._privBytes = Array.from(private_view);
  var public_view = Buffer.from(kp.pubBytes());


  var address_buf = Buffer.concat([Buffer.alloc(1, 0x12), public_spend, public_view])
  address_buf = Buffer.concat([address_buf, keccak256(address_buf).slice(0,4)]);
  var address = ''
  for (var i = 0; i < 8; i++) {
    address += bs58.encode(address_buf.slice(i*8, i*8+8));
  }
  address += bs58.encode(address_buf.slice(64, 69));
  return {
    private_spend: private_spend.toString('hex'),
    private_view: private_view.toString('hex'),
    public_spend: public_spend.toString('hex'),
    public_view: public_view.toString('hex'),
    public: address
  }
}

function keyToLoki(seed) {
  var private_spend = reduce32(seed);
  var private_view = reduce32(keccak256(private_spend));

  // Hack
  var kp = ed25519.keyFromSecret()
  kp._privBytes = Array.from(private_spend);
  var public_spend = Buffer.from(kp.pubBytes());
  var kp = ed25519.keyFromSecret()
  kp._privBytes = Array.from(private_view);
  var public_view = Buffer.from(kp.pubBytes());


  var address_buf = Buffer.concat([Buffer.alloc(1, 0x72), public_spend, public_view])
  address_buf = Buffer.concat([address_buf, keccak256(address_buf).slice(0,4)]);
  var address = ''
  for (var i = 0; i < 8; i++) {
    address += bs58.encode(address_buf.slice(i*8, i*8+8));
  }
  address += bs58.encode(address_buf.slice(64, 69));
  return {
    private_spend: private_spend.toString('hex'),
    private_view: private_view.toString('hex'),
    public_spend: public_spend.toString('hex'),
    public_view: public_view.toString('hex'),
    public: address
  }
}

function encryptStrengh(power, altCoin) {  
  var spow = Math.pow(2, power);
  var spow2 = Math.pow(2, 16);
  var encryption = {}
  //default setting
  if ($('input[name="power-level"]:checked').val() == 'default') {
    spow = 262144;
    spow2 = 65000;
  } 
  
  if ($('input[name="power-level"]:checked').val() == 'Offline Hardened') {
    spow = 1048576;
    spow2 = 256000;
  }

  if(altCoin) { 
    spow = 2; 
    spow2 = 2;
  }

  //Detect custom hash for setting power levels
  var urlhash = new RegExp('[\?&]lvl=([^&#]*)').exec(window.location.href);
  if ((urlhash != null) && (altCoin == false)) {
    var lvl = decodeURI(urlhash[1]) || 0;
    var spow = Math.pow(2, lvl.substring(0,2));
    var spow2 = parseInt(lvl.substring(2,9)) || 65536;
  }
  
  encryption = { 
    scrypt:spow, 
    pbkdf2:spow2
  };

  return encryption;
}

function warpwallet(password, salt, power, hashSuffix, callback, altCoin=false) {
  var password_buffer = Buffer.from(password, 'utf-8');
  var salt_buffer = Buffer.from(salt, 'utf-8');
  var x1 = Buffer.alloc(1, hashSuffix);
  var x2 = Buffer.alloc(1, hashSuffix + 1);

  var encrypt = encryptStrengh(power, altCoin)

  scrypt(Buffer.concat([password_buffer, x1]), Buffer.concat([salt_buffer, x1]), encrypt.scrypt, 8, 1, 32, function(error, progress, key1) {
    if(key1) {
      pbkdf2.pbkdf2(Buffer.concat([password_buffer, x2]), Buffer.concat([salt_buffer, x2]), encrypt.pbkdf2, 32, 'sha256', function(err, key2) {
        for (var i = 0; i < 32; i++) {
          key2[i] = key2[i] ^ key1[i];
        }
        callback(1, key2);
      });
    }
    callback(progress, null);
  });
}

var currencies = {
  bitcoin: {
    fn: keyToBitcoin,
    hashSuffix: 1,
  },
  litecoin: {
    fn: keyToLitecoin,
    hashSuffix: 2,
  },
  monero: {
    fn: keyToMonero,
    hashSuffix: 3,
  },
  loki: {
    fn: keyToLoki,
    hashSuffix: 5,
  },
  ethereum: {
    fn: keyToEthereum,
    hashSuffix: 4
  },
  segwit: {
    fn: keyToSegwit,
    hashSuffix: 1
  }
}

function generateWallet(passphrase, salt, power, currency, callback, altCoin=false) {
  warpwallet(passphrase, salt, power, currencies[currency].hashSuffix, function(progress, result) {
    if(result) {
      var wallet = currencies[currency].fn(result);
      callback(1, wallet)
    } else {
      callback(progress, null);
    }
  }, altCoin);
}

module.exports = {
  generateWallet: generateWallet
};

//warpwallet('hello', 'a@b.c', 10);
