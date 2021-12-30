## Salesforce Commerce Cloud Apple Web Sign-In plugin

This cartridge adds support for Apple Web Sign-In in SFRA. 

Note: This cartridge includes extra functionality to verify the identity of the user by validating the `id_token` received from apple servers. This is implemented to follow apple's guidelines on [security](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_a_user).

## Apple Configuration

Before using this cartridge for SFCC some configuration are required.
Follow this [blog post](https://auth0.com/blog/what-is-sign-in-with-apple-a-new-identity-provider/) on how to do configuration in apple developer account.

Note: Use controller endpoint "AppleSignIn-Redirect" as return/callback url in apple developer account.

## Dependency

This cartidge has a dependency on [plugin_jwt](https://github.com/ranveer5289/sfcc_jwt) cartridge. **plugin_jwt** is used for JWT encoding/decoding.

## SFCC Configuration

1. Install the cartridge on server & update the cartridge path accordingly.
2. Upload the plugin_apple_signin/metadata/system-object-defintions/apple-web-signin-system-object-definition.xml file in your sandbox.
2. Upload the plugin_apple_signin/metadata/services/apple-web-sign-in-jwks.xml file in your sandbox.
3. Update site preference values.

## Resources

1. https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js
2. https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature
3. https://stackoverflow.com/questions/58018184/how-to-revoke-sign-in-with-apple-credentials-for-a-specific-app
4. https://jwt.io/
5. https://sarunw.com/posts/sign-in-with-apple-4/


## Note

1. This cartridge currently does not handle the scenario where a regular SFCC account with same email address exists.
2. This cartridge currently only supports SFRA but it can be easily used with SiteGenesis as well.

PS: I'm not a security expert, if you find any mistake in this repo, please create an issue
