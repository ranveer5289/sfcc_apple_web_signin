var server = require('server');
var jwt = require('plugin_jwt');

var oauthProviderID = 'AppleWebSignIn';

server.post('Redirect', function (req, res, next) {
    var URLUtils = require('dw/web/URLUtils');
    var CustomerMgr = require('dw/customer/CustomerMgr');
    var Transaction = require('dw/system/Transaction');
    var Site = require('dw/system/Site');
    var Logger = require('dw/system/Logger');

    var appleHelpers = require('*/cartridge/scripts/helpers/appleHelpers');

    var httpMap = request.httpParameterMap;
    var idToken = httpMap.id_token.stringValue;
    var stateFromApple = httpMap.state.stringValue;
    var code = httpMap.code.stringValue;

    // Only returned for 1st time sign-in with apple account
    // Calling client is responsible for persisting this data for future
    var userData = httpMap.user.stringValue;
    var firstName = '';
    var lastName = '';
    if (userData) {
        appleUser = JSON.parse(userData);
        if (appleUser) {
            firstName = appleUser.name.firstName;
            lastName = appleUser.name.lastName;
        }
    }

    var redirectUrl = URLUtils.url('Login-Show');
    if (!idToken || !state || !code) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : One of the mandatory value id_token, state or code is missing');
        return next();
    }

    var existingState = req.session.privacyCache.get('appleSignInState');
    // CSRF mismatch
    if (existingState !== stateFromApple) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : OAuth2 state did not matched');
        req.session.privacyCache.set('appleSignInState', null);
        return next();
    }
    req.session.privacyCache.set('appleSignInState', null);

    // Decode JWT token
    var decodedToken = jwt.decode(idToken);
    if(!decodedToken) {
        Logger.error('Unable to decode JWT token');
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        return next();
    }

    var isValidToken = appleHelpers.verifyJWT(idToken);
    // JWT token signature invalid
    if (!isValidToken) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : Invalid jwt token, signature did not matched');
        return next();
    }

    // subject identifer - customer - unique for customer in apple DB
    var userID = decodedToken.payload.sub;
    var email = decodedToken.payload.email;

    var authenticatedCustomerProfile = CustomerMgr.getExternallyAuthenticatedCustomerProfile(
        oauthProviderID,
        userID
    );

    if (!authenticatedCustomerProfile) {
        // Create new profile
        Transaction.wrap(function () {
            var newCustomer = CustomerMgr.createExternallyAuthenticatedCustomer(
                oauthProviderID,
                userID
            );
            authenticatedCustomerProfile = newCustomer.getProfile();

            authenticatedCustomerProfile.setFirstName(firstName);
            authenticatedCustomerProfile.setLastName(lastName);
            authenticatedCustomerProfile.setEmail(email);
        });
    }

    var credentials = authenticatedCustomerProfile.getCredentials();
    if (credentials.isEnabled()) {
        Transaction.wrap(function () {
            CustomerMgr.loginExternallyAuthenticatedCustomer(oauthProviderID, userID, false);
        });
    } else {
        res.redirect(redirectUrl.append('errorcode', 'error.oauth.login.failure').toString());
        return next();
    }
    res.redirect(URLUtils.url('Account-Show').toString());
    next();
});

module.exports = server.exports();



