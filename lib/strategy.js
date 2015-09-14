var CryptoJS = require('crypto-js');
var passport = require('passport-strategy');
var util = require('util');

var crypto = require('crypto');

function signedString(request, privateKey) {
  function encodeUtf8(s) {
    return unescape(encodeURIComponent(s));
  }


  return t2 = crypto.createHmac('sha1', privateKey)
    .update(
      request.method + '\n' +
      (request.body ? crypto.createHash('md5').update(request.body, 'utf8').digest('hex') : '') + '\n' +
      (request.headers['content-type'] ? request.headers['content-type'] : '') + '\n' +
      request.headers.date
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

  // everything up the first space is the scheme, then everything up the colon
  // is the public key, followed by the base64 encoded hmac-sha1 encrypted data
  var matches = authString.match(/^([^ ]+) ([^:]+):((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/);

  if (!matches) {
    return this.fail({message: options.badRequestMessage || 'Bad authorization header'}, 400);
  }

  // var scheme = matches[1]; // not currently used
  var publicKey = matches[2];
  var base64 = CryptoJS.enc.Base64.parse(matches[3]).toString();

  var _this = this;

  function verified(err, user, privateKey, info) {
    if (err) { return _this.error(err); }

    // TODO: make use of info object
    if (!user) {
      return _this.fail({message: options.badRequestMessage || 'Bad credentials'});
    }

    // TODO: make use of info object
    if (signedString(req, privateKey) !== base64) {
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
