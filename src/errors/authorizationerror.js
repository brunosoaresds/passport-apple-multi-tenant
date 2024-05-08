class AuthorizationError extends Error {
    constructor(meesage, code, uri, status) {
        if (!status) {
            switch (code) {
                case 'access_denied':
                    status = 403;
                    break;
                case 'server_error':
                    status = 502;
                    break;
                case 'temporarily_unavailable':
                    status = 503;
                    break;
            }
        }

        super(message);
        Error.captureStackTrace(this, this.constructor);
        this.name = 'AuthorizationError';
        this.message = message;
        this.code = code || 'server_error';
        this.uri = uri;
        this.status = status || 403;
    }
}

module.exports = AuthorizationError;