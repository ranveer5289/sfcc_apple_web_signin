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

    var options = {};
    options.publicKeyOrSecret = getJSONWebKey;
    options.issuer = Site.getCurrent().getCustomPreferenceValue('appleSignInJWTIssuerId');
    options.audience = Site.getCurrent().getCustomPreferenceValue('appleSignInClientId');

    var verified = jwt.verify(encodedJWTToken, options);

    return verified;
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

module.exports.verifyJWT = verifyJWT;
