var chai = require('chai');
var HmacStrategy = require('../lib/strategy');

describe('Strategy', function() {
  var strategy = new HmacStrategy({}, function() {});

  it('should be named hmac', function() {
    expect(strategy.name).to.equal('hmac');
  });
});
