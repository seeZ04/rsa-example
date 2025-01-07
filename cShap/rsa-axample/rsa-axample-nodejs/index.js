const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
var privateKeyGb = "";
function RsaEncrypt(toEncrypt, relativeOrAbsolutePathToPublicKey) {
    const absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey)
    const publicKey = fs.readFileSync(absolutePath, 'utf8')
    const buffer = Buffer.from(toEncrypt, 'utf8')
    const encrypted = crypto.publicEncrypt(publicKey, buffer)
    return encrypted.toString('base64')
}

function decrypt(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
    const absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey)
    const privateKey = fs.readFileSync(absolutePath, 'utf8')
    const buffer = Buffer.from(toDecrypt, 'base64')
    const decrypted = crypto.privateDecrypt(
        {
            key: privateKey.toString(),
            passphrase: '',
            padding: crypto.constants.RSA_PKCS1_PADDING
        },
        buffer,
    )
    return decrypted.toString('utf8')
}

function generateSignatureRsa(plainText, relativeOrAbsolutePathtoPrivateKey = '', privateKey = null, agorithm = "RSA-SHA256") {
    if (!privateKey) {
        var absolutePathPrivate = path.resolve(__dirname, relativeOrAbsolutePathtoPrivateKey)
        privateKey = fs.readFileSync(absolutePathPrivate, "utf8");
        privateKeyGb = privateKey;
    }
    let signer = crypto.createSign(agorithm);
    signer.update(plainText);
    let sign = signer.sign(privateKey, "base64");
    return sign;
}

function verifyRsaPublicKey(plainText, signature, relativeOrAbsolutePathToPublicKey = '', publicKey = null, agorithm = "RSA-SHA256") {
    if (!publicKey) {
        var absolutePath = path.resolve(__dirname, relativeOrAbsolutePathToPublicKey);
        publicKey = fs.readFileSync(absolutePath, "utf8");
    }

    try {
        let verifier = crypto.createVerify(agorithm);
        verifier.update(plainText);
        return verifier.verify(publicKey, signature, "base64");
    } catch (e) {
        console.log(e);
        return false;
    }
}

function main() {
    const args = process.argv.slice(2); 
    const plainText = args[0]; 
    let sign = generateSignatureRsa(plainText, "../RSA/privateKey.pem")

    // Trả về kết quả
    console.log(JSON.stringify({
        privateKey: privateKeyGb,
        sign: sign,
        plainText: plainText
    }));
}

main();


