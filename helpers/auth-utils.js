const scrypt = require('scrypt-pbkdf');
const base64 = require('base64-arraybuffer');

// Parámetros de scrypt
const fastParams = { N: 16384, r: 8, p: 1 };
const secureParams = { N: 65536, r: 8, p: 2 };

// Generar sal
const generateSalt = () => base64.encode(scrypt.salt(16)); // Usamos 16 bytes para la sal

// Derivar clave
const deriveKey = async (password, salt, params) => {
  const passwordArray = new TextEncoder().encode(password);
  const saltArray = base64.decode(salt);
  console.log('Password Array:', passwordArray);
  console.log('Salt Array:', saltArray);
  const hash = await scrypt.scrypt(passwordArray, saltArray, 32, params); // Derivar 32 bytes de clave
  return base64.encode(hash);
};

module.exports = { generateSalt, deriveKey, fastParams, secureParams };
