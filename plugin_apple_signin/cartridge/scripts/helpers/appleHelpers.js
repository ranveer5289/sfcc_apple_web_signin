var Encoding = require('dw/crypto/Encoding');
var Signature = require('dw/crypto/Signature');
var Bytes = require('dw/util/Bytes');
var Site = require('dw/system/Site');

var jwt = require('plugin_jwt');

/**
 * Before we use the token, we need to make sure that it was signed by Apple's private key. 
 * To do that, we need Apple's public key to verify the signature.
 * @param {String} encodedJWTToken Encoded JWT token
 * @returns{Boolean} valid or not
 */
function verifyJWT(encodedJWTToken) {

    var decodedToken = jwt.decode(encodedJWTToken);

    // returns json web key set from apple server
    var jsonWebKey = getJSONWebKey(decodedToken);
    // get public key as string from modulus & exponential. highly custom logic
    var publicKey = getRSAPublicKey(jsonWebKey.modulus, jsonWebKey.exponential);

    var apiSig = new Signature();
    var options = {};
    options.publicKeyOrSecret = publicKey;

    var verified = jwt.verify(encodedJWTToken, decodedToken.header.alg, options);

    return verified;
}

/**
 * Validate JWT payload. It validates claim, issuer & expiration
 * of the token
 * @param {Object} payload jwt payload
 * @param {Object} options options
 */
function validateJWTPayload(payload, options) {

    var tokenIssuer = payload.iss;
    var clientId = payload.aud;
    var expirationTime = payload.exp;

    if (!tokenIssuer || tokenIssuer !== options.configuredIssuer) {
        return false;
    }

    if (!clientId || clientId !== options.configuredClientId) {
        return false;
    }

    //seconds to ms
    var expirationDate = new Date(expirationTime * 1000);
    var currentDate = new Date();

    // expired
    if (expirationDate < currentDate) {
        return false;
    }

    return true;
}

/**
 * Retrieve the Json Web Key from apple server
 * @param {String} decodedToken decoded JWT Token
 * @returns{Object} JWKS key
 */
function getJSONWebKey(decodedToken) {
    // parse the header
    var decodedJWTHeader = decodedToken.header
    if (!decodedJWTHeader) {
        throw new Error('Error Decoding JWT token');
    }
    // JWKS key id part of existing token
    var kid = decodedJWTHeader.kid;

    var appleJWKSService = require('*/cartridge/scripts/services/appleJWKS.js');
    var jsonKeys = appleJWKSService.getJsonWebKeySets();

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

module.exports.verifyJWT = verifyJWT;
module.exports.validateJWTPayload = validateJWTPayload;
