// require node/envshield.js which automatically intercepts process.env
require('./node/envshield');

console.log("Node Decrypted SECRET_API_KEY:", process.env.SECRET_API_KEY);
console.log("Node Decrypted DB_PASSWORD:", process.env.DB_PASSWORD);
