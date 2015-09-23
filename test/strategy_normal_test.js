var chai = require('chai');
var Strategy = require('../lib/strategy');
var CryptoJS = require('crypto-js');

describe('Strategy', function() {
  var keys = { publicKey: 'public-key', privateKey: 'private-key' };

  var strategy = new Strategy(function(publicKey, done) {
    if (publicKey === keys.publicKey) {
      return done(null, {id: '1234', name: 'Test'}, keys.privateKey, { scope: 'read'});
    }

    return done(null, false);
  });

  describe('handling a request with valid credentials', function() {
    var user;
    var info;

    describe('with json content', function() {
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
    });

    describe('without json content', function() {
      before(function(done) {
        chai.passport.use(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.headers.date = new Date().toUTCString();

            var encString = CryptoJS.enc.Base64.stringify(
              CryptoJS.HmacSHA1(
                unescape(encodeURIComponent(
                  req.method + '\n' +
                  '' + '\n' +
                  '' + '\n' +
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

  describe('handling a request with malformed authorization header', function() {
    var info;

    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'Hmac bad_public_key';
        })
        .authenticate();
    });

    it('should fail with bad authorization message', function() {
      expect(info).to.be.a.string;
      expect(info.message).to.equal('Bad authorization header');
    });
  });

  describe('handling a request with bad public key in authorization header', function() {
    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.authorization = 'Hmac bad_public_key:dGhpcyBpcyBhIHRlc3Q=';
        })
        .authenticate();
    });

    it('should fail with bad credentials message', function() {
      expect(info).to.be.a.string;
      expect(info.message).to.equal('Bad credentials');
    });
  });

  describe('handling a request with bad signature', function() {
    var info;

    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.date = new Date().toUTCString();
          req.headers.authorization = 'Hmac ' + keys.publicKey + ':dGhpcyBpcyBhIHRlc3Q=';
        })
        .authenticate();
    });

    it('should fail with bad signature message in authorization header', function() {
      expect(info).to.be.a.string;
      expect(info.message).to.equal('Bad signature');
    });
  });

  describe('handling a request with a missing authorization header', function() {
    it('should fail with a missing authorization header message', function(done) {
      chai.passport.use(strategy)
        .fail(function(i) {
          info = i;
          done();
        })
        .req(function(req) {
          req.headers.date = new Date().toUTCString();
        })
        .authenticate();
    });
  });
});
