#  Request Context Based and Multi Tenant Sign in with Apple for Passport.js 

This strategy integrates Apple login. Is useful specially when you're trying to use it with NestJS Passaport Module, where you don't have so much control of passport instances and uses.

## Installation

```bash
npm install --save passport-apple-multi-tenant
```

## Usage

### Strategy Options

- `clientInfoGenerator`: Function/Async Function which will return the following properties: 
    - `clientID`: Apple OAuth2.0 Client ID
    - `teamID`: Apple Developer Team ID
    - `keyID`: Apple Key ID
    - `key`: Contents of the Apple Key. If you want the library to load the contents, use `keyFilePath` instead.
    - `keyFilePath`: File path to Apple Key; library will load content using `fs.readFileSync`
    - `scope`: An array of scopes, e.g., `['email', 'name']`
    - `callbackURL`: Callback URL configured and authorized on your apple service provider
    - `queryMode`: Boolean true if you want to use code query param redirect auth flow or false otherwise
- `authorizationURL`: (Optional) Authorization URL; default is `https://appleid.apple.com/auth/authorize`
- `tokenURL`: (Optional) Token URL; default is `https://appleid.apple.com/auth/token`
- `sessionKey`: (Optional) Session Key
- `state`: (Optional) Should state parameter be used
- `passReqToCallback`: (Optional) Should request be passed to the `validate` callback; default is `false`
    

### Validate Callback

The `validate` callback is called after successful authentication and contains the `accessToken`, `refreshToken`, and `profile`.

## License

Licensed under [MIT](./LICENSE).