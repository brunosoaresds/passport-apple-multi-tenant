class TokenError extends Error {
    constructor(message, code, uri, status) {
        super(message);
        Error.captureStackTrace(this, this.constructor);
        this.name = 'TokenError';
        this.message = message;
        this.code = code || 'invalid_request';
        this.uri = uri;
        this.status = status || 400;
    }
}

module.exports = TokenError;