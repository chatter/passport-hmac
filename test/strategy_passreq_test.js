var chai = require('chai');
var Strategy = require('../lib/strategy');
var CryptoJS = require('crypto-js');

describe('Strategy', function() {
  var keys = { publicKey: 'public-key', privateKey: 'private-key' };

  describe('passing request to verify callback', function() {
    var strategy = new Strategy({passReqToCallback: true}, function(req, publicKey, done) {
      if (publicKey == keys.publicKey) {
        return done(null, {id: '1234'}, keys.privateKey, {scope: 'read', foo: req.headers['x-foo']});
      }

      return done(null, false);
    });

    describe('handling a request with valid authorization header', function() {
      var user;
      var info;

      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.body = {name: 'Test', body: 'Include UTF8 data: 🐶🐮'};
            req.headers['content-type'] = 'application/json';
            req.headers.date = new Date().toUTCString();
            req.headers['x-foo'] = 'hello';

            var encString = CryptoJS.enc.Base64.stringify(
              CryptoJS.HmacSHA1(
                unescape(encodeURIComponent(
                  req.method + '\n' +
                  CryptoJS.MD5(JSON.stringify(req.body)) + '\n' +
                  req.headers['content-type'] + '\n' +
                  req.headers.date
                )),
                keys.privateKey
            ));

            req.headers.authorization = 'Hmac ' + keys.publicKey + ':' + encString;
          })
          .authenticate();
      });

      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.scope).to.equal('read');
      });

      it('should supply request header in info', function() {
        expect(info.foo).to.equal('hello');
      });
    });
  });
});
