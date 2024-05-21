const scryptPbkdf = require('scrypt-pbkdf');
const base64 = require('base64-arraybuffer');
const { TextEncoder } = require('util');

const derivedKeyLength = 64;
const fastParams = { N: 1 << 15, r: 8, p: 1 };
const slowParams = { N: 1 << 20, r: 8, p: 1 };

async function deriveKey(password, salt, params) {
    const encoder = new TextEncoder();
    const passwordArray = encoder.encode(password);
    const saltArray = base64.decode(salt);
    const derivedKey = await scryptPbkdf.scrypt(passwordArray, saltArray, derivedKeyLength, params);
    return base64.encode(derivedKey);
}

function generateSalt() {
    return base64.encode(scryptPbkdf.salt(16));
}

module.exports = { deriveKey, generateSalt, fastParams, slowParams };

