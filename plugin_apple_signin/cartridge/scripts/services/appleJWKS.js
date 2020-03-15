'use strict';

var Logger = require('dw/system/Logger');
var appleLogger = Logger.getLogger('appleWebSigIn', 'appleWebSigIn');
var Result = require('dw/svc/Result');

/**
 * Apple Service to get Json Web Key Set
 *
 * @returns {Object} Helper method
 */
function AppleJWKSService() {
    /**
     * Implement service callbacks
     *
     * @returns {Object} service callback
     * @private
     */
    function callback() {

        /**
         * Creates the actual HTTP request
         *
         * @param {dw.svc.HTTPService} svc SOAP service
         * @param {Object} params Parameters like order
         * @returns {Object} SOAp request
         */
        function createRequest(svc, params) {
            svc.addHeader('accept', 'application/json');
            svc.setRequestMethod('GET');
            return null;
        }

        /**
         * Parse the HTTP response
         *
         * @param {dw.svc.HTTPService} svc SOAP service
         * @param {Object} response Service response
         * @returns {Object} Service response
         */
        function parseResponse(svc, response) {
            var output = {};
            try {
                var response = JSON.parse(response.text);
                var keys = response.keys || [];
                keys.forEach(function(key) {
                    output[key.kid] = {};
                    output[key.kid]['modulus'] = key.n;
                    output[key.kid]['exponential'] = key.e;
                });
            } catch (error) {
                appleLogger.error('Error parsing response of apple JWKS Service {0}', e.message);
            }
            return output;
        }
        return {
            createRequest: createRequest,
            parseResponse: parseResponse
        };
    }

    /**
     * Call Apple Service
     * @returns{Object} key sets
     */
    function getJsonWebKeySets() {
        var LocalServiceRegistry = require('dw/svc/LocalServiceRegistry');
        var serviceID = 'apple_web_signin.get.jwks';
        var checkBalanceSvc = LocalServiceRegistry.createService(serviceID, callback());
        var result = checkBalanceSvc.call();
        var output = {};

        if (result.ok) {
            output = result.object;
        } else if (result.getStatus() === Result.ERROR) {
            appleLogger.error('Error in get apple JWKS Service {0}', result.getErrorMessage());
        } else if (result.getStatus() === Result.SERVICE_UNAVAILABLE) {
            appleLogger.error('Service {0} is unavailable : {1}', serviceID, result.getUnavailableReason());
        } else if (result.getStatus() === Result.UNAVAILABLE_CONFIG_PROBLEM) {
            appleLogger.error('No call was made because the service {0} was not configured correctly', serviceID);
        } else {
            appleLogger.error('Apple JWKS Service call was not successful because of error : {0} for service {1}', result.getMsg(), serviceID);
        }

        return output;
    }

    return {
        getJsonWebKeySets: getJsonWebKeySets
    };
}

module.exports = AppleJWKSService();
