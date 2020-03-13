## Salesforce Commerce Cloud Apple Web Sign-In plugin

This cartridge adds support for Apple Web Sign-In in SFRA.

## Apple Configuration

Before using this cartridge for SFCC some configuration are required.
Follow this [blog post](https://auth0.com/blog/what-is-sign-in-with-apple-a-new-identity-provider/) on how to do configuration in apple developer account.

Note: Use controller endpoint "AppleSignIn-Redirect" as return/callback url in apple developer account.

## SFCC Configuration

1. Install the cartridge on server & update the cartridge path accordingly.
2. Upload the plugin_apple_signin/metadata/apple-web-signin-system-object-definition.xml file in your sandbox.
3. Update site preference values.

## Resources

1. https://developer.apple.com/documentation/signinwithapplejs
2. https://stackoverflow.com/questions/58018184/how-to-revoke-sign-in-with-apple-credentials-for-a-specific-app


Note: I'm not a security expert, if you find any mistake in this repo, please create an issue
