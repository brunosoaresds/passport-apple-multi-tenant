const fs = require('fs');
const url = require('url');
const querystring = require('querystring');

const passport = require('passport-strategy');
const OAuth2 = require('oauth').OAuth2;
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');

const jwks_client = jwksClient({
    strictSsl: true,
    rateLimit: true,
    cache: true,
    cacheMaxEntries: 100,
    cacheMaxAge: 1000 * 60 * 60 * 24,
    jwksUri: 'https://appleid.apple.com/auth/keys'
});

const getAppleJWKSKey = (header, callback) => {
    jwks_client
        .getSigningKey(header.kid)
        .then((key) => {
            callback(null, key && (key.publicKey || key.rsaPublicKey));
        })
        .catch((err) => callback(err));
};

// the client secret for a given key is a signed JWT which is allowed to live
// for a relatively long time, so cache and re-use these to avoid unnecessary
// signature operations:
const clientSecretCache = new Map();

class AppleStrategy extends passport.Strategy {
    /**
     * @param {object} options
     * @param {function} options.clientInfoGenerator
     * @param {string} [options.authorizationURL=https://appleid.apple.com/auth/authorize]
     * @param {string} [options.tokenURL=https://appleid.apple.com/auth/token]
     * @param {string} [options.sessionKey]
     * @param {boolean} [options.state]
     * @param {boolean} [options.passReqToCallback=false]
     * @param {function} [options.clientSecretExpiry='5 minutes']
     * @param {function} [options.verifyNonce]
     * @param {function} verify
     */
    constructor(options = {}, verify) {
        if (!verify) throw new TypeError('AppleStrategy requires a verify callback');
        if (!options.clientInfoGenerator || typeof options.clientInfoGenerator !== 'function') throw new TypeError(`AppleStrategy requires a clientInfoGenerator function`)

        super();
        this.name = 'apple';
        this._verify = verify;
        this._clientInfoGenerator = options.clientInfoGenerator;

        this._authorizationURL = options.authorizationURL || 'https://appleid.apple.com/auth/authorize';
        this._tokenURL = options.tokenURL || 'https://appleid.apple.com/auth/token';
        this._sessionKey = options.sessionKey || 'apple:' + url.parse(this._authorizationURL).hostname;
        this._clientSecretExpiry = options.clientSecretExpiry || '5 minutes';
        this._verifyNonce = options.verifyNonce;

        if (options.state) {
            this._stateStore = new SessionStateStore({ key: this._sessionKey });
        } else {
            this._stateStore = new NullStateStore();
        }

        this._passReqToCallback = options.passReqToCallback;
    }

    verifyNonce(req, nonce_supported, nonce, callback) {
        if (this._verifyNonce && nonce_supported) {
            return this._verifyNonce(req, nonce_supported, nonce, callback);
        } else {
            return callback(null, true);
        }
    }

    authenticate(req, options = {}) {
        if (req.body && req.body.error) {
            if (req.body.error === 'user_cancelled_authorize') {
                return this.fail({ message: 'User cancelled authorize' });
            } else {
                return this.error(new AuthorizationError(req.body.error, req.body.error));
            }
        }
        let authClientInfo = this._clientInfoGenerator(req);
        const authClientInfoPromise = (authClientInfo instanceof Promise) ? authClientInfo : Promise.resolve(authClientInfo);

        return authClientInfoPromise.then((clientInfo) => {
            if (!clientInfo.clientID) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires a clientID on its return' });
            if (!clientInfo.teamID) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires a teamID2 on its return' });
            if (!clientInfo.keyID) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires a keyID on its return' });
            if (!clientInfo.callbackURL) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires a callbackURL on its return' });
            if (!clientInfo.scope) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires a scope on its return' });
            if (!clientInfo.key && !clientInfo.keyFilePath) return this.fail({ message: 'AppleStrategy clientInfoGenerator requires either the key or keyFilePath on its return' });

            const key = (clientInfo.keyFilePath) ? fs.readFileSync(clientInfo.keyFilePath) : clientInfo.key;

            if (req.body && req.body.code) {
                const state = req.body.state;
                try {
                    this._stateStore.verify(req, state, (err, ok, state) => {
                        if (err) return this.error(err);
                        if (!ok) return this.fail(state, 403);

                        const code = req.body.code;

                        const params = { grant_type: 'authorization_code', redirect_uri: clientInfo.callbackURL };
                        const oauth2 = this._getOAuth2Client({ keyId: clientInfo.keyID, key, teamId: clientInfo.teamID, clientId: clientInfo.clientID });

                        oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, params) => {
                            if (err) return this.error(this._createOAuthError('Failed to obtain access token', err));

                            const idToken = params['id_token'];
                            if (!idToken) return this.error(new Error('ID Token not present in token response'));

                            const verifyOpts = {
                                audience: clientInfo.clientID,
                                issuer: 'https://appleid.apple.com',
                                algorithms: ['RS256']
                            };
                            jwt.verify(idToken, getAppleJWKSKey, verifyOpts, (err, jwtClaims) => {
                                if (err) {
                                    return this.error(err);
                                }

                                this.verifyNonce(req, jwtClaims.nonce_supported, jwtClaims.nonce, (err, ok) => {
                                    if (err) return this.error(err);
                                    if (!ok) return this.fail({ message: 'invalid nonce' });

                                    const profile = { id: jwtClaims.sub, provider: 'apple' };

                                    if (jwtClaims.email) {
                                        profile.email = jwtClaims.email;
                                    }

                                    if (jwtClaims.email_verified !== undefined) {
                                        profile.emailVerified = Boolean(jwtClaims.email_verified === 'true') || jwtClaims.email_verified === true;
                                    }

                                    if (jwtClaims.is_private_email !== undefined) {
                                        profile.isPrivateEmail = Boolean(jwtClaims.is_private_email === 'true') || jwtClaims.is_private_email === true
                                    }

                                    if (req.body.user) {
                                        if (typeof req.body.user === 'object' && req.body.user.name) {
                                            profile.name = req.body.user.name;
                                        } else {
                                            try {
                                                const user = JSON.parse(req.body.user);
                                                if (user && user.name) profile.name = user.name;
                                            } catch (ex) {
                                                return this.error(ex);
                                            }
                                        }
                                    }

                                    const verified = (err, user, info) => {
                                        if (err) return this.error(err);
                                        if (!user) return this.fail(info);

                                        info = info || {};
                                        if (state) info.state = state;
                                        this.success(user, info);
                                    };

                                    try {
                                        if (this._passReqToCallback) {
                                            this._verify(req, accessToken, refreshToken, profile, verified);
                                        } else {
                                            this._verify(accessToken, refreshToken, profile, verified);
                                        }
                                    } catch (ex) {
                                        return this.error(ex);
                                    }
                                });
                            });
                        });
                    });
                } catch (ex) {
                    return this.error(ex);
                }
            } else {
                const params = {
                    client_id: clientInfo.clientID,
                    response_type: clientInfo.queryMode === true ? 'code' : 'code id_token',
                    response_mode: clientInfo.queryMode === true ? 'query' : 'form_post',
                    redirect_uri: clientInfo.callbackURL,
                };
                let scope = clientInfo.scope;
                if (scope && clientInfo.queryMode !== true) {
                    params.scope = scope.join(' ');
                }

                if (options.nonce) {
                    params.nonce = options.nonce;
                }

                const state = options.state;
                if (state) {
                    params.state = state;
                    this.redirect(this._authorizationURL + '?' + querystring.stringify(params));
                } else {
                    this._stateStore.store(req, (err, state) => {
                        if (err) return this.error(err);

                        if (state) params.state = state;
                        this.redirect(this._authorizationURL + '?' + querystring.stringify(params));
                    });
                }
            }
        }).catch((e) => {
            return this.error(e);
        })
    }

    parseErrorResponse(body) {
        const json = JSON.parse(body);
        if (json.error) {
            return new TokenError(json.error_description, json.error, json.error_uri);
        }
        return null;
    }

    _getClientSecret({keyId, key, teamId, clientId}) {
        const existing = clientSecretCache.get(keyId);
        if (!existing || jwt.decode(existing).exp < Date.now() / 1000 + 5) {
            clientSecretCache.set(
                keyId,
                jwt.sign({}, key, {
                    algorithm: 'ES256',
                    keyid: keyId,
                    expiresIn: this._clientSecretExpiry,
                    issuer: teamId,
                    audience: 'https://appleid.apple.com',
                    subject: clientId
                })
            );
        }
        return clientSecretCache.get(keyId);
    }

    _getOAuth2Client({ keyId, key, teamId, clientId }) {
        return new OAuth2(clientId, this._getClientSecret({keyId, key, teamId, clientId}), '',
            this._authorizationURL, this._tokenURL);
    }

    _createOAuthError(message, err) {
        let e;
        if (err.statusCode && err.data) {
            try {
                e = this.parseErrorResponse(err.data);
            } catch (_) {
                // ignore
            }
        }
        if (!e) e = new InternalOAuthError(message, err);
        return e;
    }
}

module.exports = AppleStrategy;