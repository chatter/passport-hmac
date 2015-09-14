var chai = require('chai');
var Strategy = require('../lib/strategy');
var CryptoJS = require ('crypto-js');

describe('Strategy', function() {
  describe('handling a request with valid credentials', function() {
    var keys = { publicKey: 'public-key', privateKey: 'private-key' };

    var strategy = new Strategy(function(publicKey, done) {
      if (publicKey === keys.publicKey) {
        return done(null, {id: '1234', name: 'Test'}, keys.privateKey, { scope: 'read'});
      }

      return done(null, false);
    });

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
          req.body = JSON.stringify({name: 'Test', body: 'Include UTF8 data: 🐶🐮'});
          req.headers['content-type'] = 'application/json';
          req.headers.date = new Date().toUTCString();

          var encString = CryptoJS.enc.Base64.stringify(
            CryptoJS.HmacSHA1(
              unescape(encodeURIComponent(
                req.method + '\n' +
                CryptoJS.MD5(req.body) + '\n' + // MD5 of req.body
                req.headers['content-type'] + '\n' + // Content-Type header
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
  });
});
