var server = require('server');

server.extend(module.superModule);

server.append('Show', function(req, res, next) {
    var URLUtils = require('dw/web/URLUtils');
    var UUIDUtils = require('dw/util/UUIDUtils');
    var Site = require('dw/system/Site');

    var appleSignIn = {};
    appleSignIn.enabled = Site.getCurrent().getCustomPreferenceValue('isAppleSignInEnabled');
    if (appleSignIn.enabled) {
        appleSignIn.jsURL = Site.getCurrent().getCustomPreferenceValue('appleSignInJSURL');
        appleSignIn.clientId = Site.getCurrent().getCustomPreferenceValue('appleSignInClientId');
        appleSignIn.scope = Site.getCurrent().getCustomPreferenceValue('appleSignInRequestScopes') || 'name email';
        appleSignIn.state = UUIDUtils.createUUID();

        appleSignIn.redirectURI = URLUtils.https('AppleSignIn-Redirect');
        req.session.privacyCache.set('appleSignInState', appleSignIn.state);
    }

    res.setViewData({appleSignIn: appleSignIn});
    next()
});

module.exports = server.exports();
