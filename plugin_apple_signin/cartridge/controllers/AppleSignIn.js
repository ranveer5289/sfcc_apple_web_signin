var server = require('server');

var oauthProviderID = 'AppleWebSignIn';

server.post('Redirect', function (req, res, next) {
    var URLUtils = require('dw/web/URLUtils');
    var CustomerMgr = require('dw/customer/CustomerMgr');
    var Transaction = require('dw/system/Transaction');
    var Site = require('dw/system/Site');
    var Logger = require('dw/system/Logger');

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
        Logger.debug('Apple Web Sign-In : One of the mandatory value id_token, state or code is missing');
        return next();
    }

    var existingState = req.session.privacyCache.get('appleSignInState');
    // CSRF mismatch
    if (existingState !== state) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.debug('Apple Web Sign-In : OAuth2 state did not matched');
        return next();
    }
    req.session.privacyCache.set('appleSignInState', '');

    var parsedAppleToken = parseJwt(idToken);

    var tokenIssuer = parsedAppleToken.iss;
    var clientId = parsedAppleToken.aud;
    // subject identifer - customer - unique for customer in apple DB
    var userID = parsedAppleToken.sub;
    var email = parsedAppleToken.email;

    var configuredIssuer = Site.getCurrent().getCustomPreferenceValue('appleSignInJWTIssuerId');
    var configuredClientId = Site.getCurrent().getCustomPreferenceValue('appleSignInClientId');

    if (!tokenIssuer || tokenIssuer !== configuredIssuer ||
            !clientId || clientId !== configuredClientId ||
            !email || userEmail !== email) {
        res.redirect(redirectUrl.append('errorcode', 'apple.signin.error').toString());
        Logger.debug('Apple Web Sign-In : token, issuer or client-id mis-match');
        return next();
    }

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

function parseJwt (token) {
    var StringUtils = require('dw/util/StringUtils');
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(StringUtils.decodeBase64(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));

    return JSON.parse(jsonPayload);
};

module.exports = server.exports();
