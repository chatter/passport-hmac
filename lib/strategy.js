var passport = require('passport-strategy');
var util = require('util');

var crypto = require('crypto');

function signedString(request, privateKey) {
  var jsonTypes = [
    'application/json',
    'application/json-patch+json',
    'application/vnd.api+json',
    'application/csp-report',
  ];

  var type = request.headers['content-type'] || '';
  type = type.split(';')[0];

  // support parsing of json; otherwise, new string from request.body
  var body = (jsonTypes.indexOf(type) > -1) ? JSON.stringify(request.body) : '';

  return crypto.createHmac('sha1', privateKey)
    .update(
      new Buffer(
        request.method + '\n' +
        (request.body ? crypto.createHash('md5').update(body, 'utf8').digest('hex') : '') + '\n' +
        type + '\n' + request.headers.date,
        'utf-8'
      )
    ).digest('hex');
}

/**
 * `Strategy` constructor.
 *
 * The HMAC authentication strategy authenticates requests based on a public key
 * and signature passed in the request's `Authorization` header.
 *
 * @constructor
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!verify)  {
    throw new TypeError('HMAC Strategy requires a verify callback');
  }

  passport.Strategy.call(this);
  this.name = 'hmac';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};

  var authString = req.headers.authorization;

  // if authString is undefined fail fast
  if (!authString) return this.fail(new Error('Authorization header not present'));

  // everything up the first space is the scheme, then everything up the colon
  // is the public key, followed by the base64 encoded hmac-sha1 encrypted data
  var matches = authString.match(/^([^ ]+) ([^:]+):((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/);

  if (!matches) {
    return this.fail({message: options.badRequestMessage || 'Bad authorization header'}, 401);
  }

  // var scheme = matches[1]; // not currently used
  var publicKey = matches[2];
  var signature = new Buffer(matches[3] || '', 'base64').toString('hex');

  var _this = this;

  function verified(err, user, privateKey, info) {
    if (err) { return _this.error(err); }

    // TODO: make use of info object
    if (!user) {
      return _this.fail({message: options.badRequestMessage || 'Bad credentials'});
    }

    // TODO: make use of info object
    if (signedString(req, privateKey) !== signature) {
      return _this.fail({message: options.badRequestMessage || 'Bad signature'});
    }

    _this.success(user, info);
  }

  try {
    if (_this._passReqToCallback) {
      this._verify(req, publicKey, verified);
    } else {
      this._verify(publicKey, verified);
    }
  } catch (e) {
    return _this.error(e);
  }
};

/**
 * Expose `Strategy`
 */
module.exports = Strategy;
