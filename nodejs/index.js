const crypto = require('crypto')
const path = require('path')
const fs = require('fs')

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
    // console.log("publicKey",publicKey);
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
    console.log("start---------------")
    let plainText = "MyGmobile"

    let encrypt = RsaEncrypt(plainText,"../RSA/privateKey.pem")
    console.log("encrypt:", encrypt)

    let sign = generateSignatureRsa(plainText,"../RSA/privateKey.pem")
    console.log("sign:", sign)

    let verify = verifyRsaPublicKey(plainText,sign,"../RSA/publicKey.pem")
    console.log("verify:", verify)


    console.log("------------------------------")

    // let sign2 = generateSignatureRsa(plainText,"./base64.privateKey.pem")
    // console.log("sign2:", sign2)

    // let verify2 = verifyRsaPublicKey(plainText,sign,"./base64.publicKey.pem")
    // console.log("verify2:", verify2)
}

main();



