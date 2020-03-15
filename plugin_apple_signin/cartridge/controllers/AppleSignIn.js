var server = require('server');

var oauthProviderID = 'AppleWebSignIn';

server.post('Redirect', function (req, res, next) {
    var URLUtils = require('dw/web/URLUtils');
    var CustomerMgr = require('dw/customer/CustomerMgr');
    var Transaction = require('dw/system/Transaction');
    var Site = require('dw/system/Site');
    var Logger = require('dw/system/Logger');

    var appleHelpers = require('*/cartridge/scripts/helpers/appleHelpers');

    var httpMap = request.httpParameterMap; // no other way to get this data req.body & req.querystring both doesn't work
    var idToken = httpMap.id_token.stringValue;
    var state = httpMap.state.stringValue;
    var code = httpMap.code.stringValue;

    // Only returned for 1st time sign-in with apple account
    // Calling client is responsible for persisting this data for future
    var userData = httpMap.user.stringValue;
    var firstName = '';
    var lastName = '';
    var userEmail = '';
    if (userData) {
        appleUser = JSON.parse(userData);
        firstName = appleUser.name.firstName;
        lastName = appleUser.name.lastName;
        userEmail = appleUser.email;
    }

    var redirectUrl = URLUtils.url('Login-Show');
    if (!idToken || !state || !code) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : One of the mandatory value id_token, state or code is missing');
        return next();
    }

    var existingState = req.session.privacyCache.get('appleSignInState');
    // CSRF mismatch
    if (existingState !== state) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : OAuth2 state did not matched');
        req.session.privacyCache.set('appleSignInState', null);
        return next();
    }
    req.session.privacyCache.set('appleSignInState', null);

    var isValidToken = appleHelpers.verifyJWT(idToken);
    // JWT token signature invalid
    if (!isValidToken) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : Invalid jwt token, signature did not matched');
        return next();
    }

    var options = {};
    options.configuredIssuer = Site.getCurrent().getCustomPreferenceValue('appleSignInJWTIssuerId');
    options.configuredClientId = Site.getCurrent().getCustomPreferenceValue('appleSignInClientId');

    var isJWTDataValid = appleHelpers.validateJWTData(idToken, options);
    // payload data inside JWT is not correct
    if (!isJWTDataValid) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.error('Apple Web Sign-In : JWT claim, issuer or expiration mis-match');
        return next();
    }

    var parsedJWTPayload = appleHelpers.parseJwt(idToken, 1);

    // subject identifer - customer - unique for customer in apple DB
    var userID = parsedJWTPayload.sub;
    var email = parsedJWTPayload.email;

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
            authenticatedCustomerProfile.setEmail(userEmail);
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



