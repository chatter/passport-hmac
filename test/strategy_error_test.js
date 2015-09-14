var chai = require('chai');
var Strategy = require('../lib/strategy');

describe('Strategy', function() {
  describe('that encounters an error during verification', function() {
    var strategy = new Strategy(function(token, done) {
      return done(new Error('something went wrong'));
    });

    describe('handling a request', function() {
      var err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            req.headers.authorization = 'Hmac bad_public_key:dGhpcyBpcyBhIHRlc3Q=';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceOf(Error);
        expect(err.message).to.equal('something went wrong');
      });
    });
  });
});
