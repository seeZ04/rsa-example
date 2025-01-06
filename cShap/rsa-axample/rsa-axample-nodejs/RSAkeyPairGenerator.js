const { generateKeyPairSync } = require('crypto');
const fs = require('fs')


const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

console.log('Public Key:\n', publicKey);
console.log('Private Key:\n', privateKey);

// Create the public key file
fs.writeFileSync('../RSA/publicKey.pem', publicKey);

// Create the private key file
fs.writeFileSync('../RSA/privateKey.pem', privateKey);