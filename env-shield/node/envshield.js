const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let envShieldCache = null;
let masterKeyCache = null;

function getMasterKey() {
    if (masterKeyCache) return masterKeyCache;
    
    // 1. Check ENV_SHIELD_KEY in environment
    if (process.env.ENV_SHIELD_KEY) {
        masterKeyCache = Buffer.from(process.env.ENV_SHIELD_KEY, 'hex');
        return masterKeyCache;
    }
    
    // 2. Check local env-shield.key file
    const keyPath = path.resolve(process.cwd(), 'env-shield.key');
    if (fs.existsSync(keyPath)) {
        masterKeyCache = Buffer.from(fs.readFileSync(keyPath, 'utf8').trim(), 'hex');
        return masterKeyCache;
    }
    
    throw new Error("Master key not found. Set ENV_SHIELD_KEY or provide env-shield.key file.");
}

function loadEncryptedData() {
    if (envShieldCache) return envShieldCache;
    const encPath = path.resolve(process.cwd(), '.env.enc');
    if (!fs.existsSync(encPath)) {
        return {};
    }
    envShieldCache = JSON.parse(fs.readFileSync(encPath, 'utf8'));
    return envShieldCache;
}

function decryptValue(encryptedObj) {
    const key = getMasterKey();
    const iv = Buffer.from(encryptedObj.iv, 'hex');
    const authTag = Buffer.from(encryptedObj.auth_tag, 'hex');
    const ciphertext = Buffer.from(encryptedObj.ciphertext, 'base64');
    
    // Verify HMAC
    const hmacKey = crypto.createHash('sha256').update(key).digest();
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(Buffer.concat([iv, ciphertext]));
    const computedTag = hmac.digest();
    
    if (!crypto.timingSafeEqual(authTag, computedTag)) {
        throw new Error("Authentication failed! Data has been tampered with.");
    }
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function init() {
    // Return a Proxy wrapping process.env
    return new Proxy(process.env, {
        get(target, prop) {
            // Priority 1: native unencrypted process.env values
            if (prop in target) {
                return target[prop];
            }
            
            // Priority 2: Check JIT encrypted values
            const data = loadEncryptedData();
            if (prop in data) {
                return decryptValue(data[prop]);
            }
            
            return undefined;
        }
    });
}

// Automatically replace process.env on require
process.env = init();

module.exports = process.env;
