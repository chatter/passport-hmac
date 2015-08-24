var passport = require('passport-strategy');
var util = require('util');
var crypto = require('crypto');

/**
 * `Strategy` constructor.
 *
 * @constructor
 * @api public
 */
function Strategy() {
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
  throw new Error('Strategy#authenticate must be implemented');
};

/**
 * Expose `Strategy`
 */
module.exports = Strategy;
