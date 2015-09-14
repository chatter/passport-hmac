var chai = require('chai');
var HmacStrategy = require('../lib/strategy');
var CryptoJS = require('crypto-js');

describe('Strategy', function() {
  var strategy = new HmacStrategy(function() {});

  it('should be named hmac', function() {
    expect(strategy.name).to.equal('hmac');
  });

  it('should throw if constructed without a verify callback', function() {
    expect(function() {
      var s = new HmacStrategy();
    }).to.throw(TypeError, 'HMAC Strategy requires a verify callback');
  });
});
