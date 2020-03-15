var Encoding = require('dw/crypto/Encoding');
var Signature = require('dw/crypto/Signature');
var Bytes = require('dw/util/Bytes');
var Site = require('dw/system/Site');

/**
 * Before we use the token, we need to make sure that it was signed by Apple's private key. 
 * To do that, we need Apple's public key to verify the signature.
 * @param {String} encodedJWTToken Encoded JWT token
 * @returns{Boolean} valid or not
 */
function verifyJWT(encodedJWTToken) {
    var parts = encodedJWTToken.split('.');
    /**
     * header - base64urlencoded
     * payload - base64urlencoded
     * signature - base64urlencoded
    */
    var header = parts[0];
    var payload = parts[1];
    var jwtSignature = parts[2];

    var contentToVerify = header + '.' + payload;
    var contentToVerifyBytes = new Bytes(contentToVerify);

    var jwtSignatureBytes = new Encoding.fromBase64(jwtSignature);

    // returns json web key set from apple server
    var jsonWebKey = getJSONWebKey(encodedJWTToken);
    // get public key as string from modulus & exponential. highly custom logic
    var publicKey = getRSAPublicKey(jsonWebKey.modulus, jsonWebKey.exponential);

    var apiSig = new Signature();
    var verified = apiSig.verifyBytesSignature(jwtSignatureBytes, contentToVerifyBytes, new Bytes(publicKey), 'SHA256withRSA');

    return verified;
}

/**
 * Validate JWT payload. It validates claim, issuer & expiration
 * of the token
 * @param {String} encodedJWTToken encoded jwt token
 * @param {Object} options options
 */
function validateJWTData(encodedJWTToken, options) {
    var decodedJWTPayload = parseJwt(encodedJWTToken, 1);

    var tokenIssuer = decodedJWTPayload.iss;
    var clientId = decodedJWTPayload.aud;
    var expirationTime = decodedJWTPayload.exp;

    if (!tokenIssuer || tokenIssuer !== options.configuredIssuer) {
        return false;
    }

    if (!clientId || clientId !== options.configuredClientId) {
        return false;
    }

    var secondsSinceEpoch = ((new Date()).getTime()) / 100;
    if (secondsSinceEpoch < expirationTime) {
        return false;
    }

    return true;
}

/**
 * Retrieve the Json Web Key from apple server
 * @param {String} encodedJWTToken Encoded JWT Token
 * @returns{Object} JWKS key
 */
function getJSONWebKey(encodedJWTToken) {
    // parse the header
    var decodedJWTHeader = parseJwt(encodedJWTToken, 0);
    if (!decodedJWTHeader) {
        throw new Error('Error Decoding JWT token');
    }
    // JWKS key id part of existing token
    var kid = decodedJWTHeader.kid;

    var appleJWKSSVC = require('*/cartridge/scripts/services/appleJWKS.js');
    var jsonKeys = appleJWKSSVC.getJsonWebKeySets();

    if (!jsonKeys) {
        throw new Error('Error getting json web key sets from apple server');
    }

    var jsonWebKey = jsonKeys[kid];
    if (!jsonWebKey) {
        throw new Error('No matching public json web key found');
    }

    return jsonWebKey;
}

/**
 * Get public key as string using modulus & exponential
 * @param {String} modulus Modulus
 * @param {String} exponential Exponential
 * @returns{String} public key
 */
function getRSAPublicKey(modulus, exponential) {
    var rsa = require('*/cartridge/scripts/helpers/rsaToDer');
    var base64PublicKey = rsa.getRSAPublicKey(modulus, exponential);

    return base64PublicKey;
}

/**
 * Parse the encoded jwt token
 * @param {String} token encoded token
 * @param {Integer} index index
 */
function parseJwt(token, index) {
    var StringUtils = require('dw/util/StringUtils');
    var base64Url = token.split('.')[index];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(StringUtils.decodeBase64(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
};

module.exports.verifyJWT = verifyJWT;
module.exports.validateJWTData = validateJWTData;
module.exports.parseJwt = parseJwt;
