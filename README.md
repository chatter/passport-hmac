![Codeship](https://img.shields.io/codeship/fcf8b260-3d6a-0133-c3bb-22d459b325ce.svg)
![Code Climate](https://img.shields.io/codeclimate/github/chatter/passport-hmac.svg)
![Coveralls](https://img.shields.io/coveralls/chatter/passport-hmac.svg)
![Dependencies](https://img.shields.io/david/chatter/passport-hmac.svg)
![devDependencies](https://img.shields.io/david/dev/chatter/passport-hmac.svg)
![License](https://img.shields.io/npm/l/passport-hmac.svg)

# passport-hmac
HMAC authentication strategy for [Passport](http://passportjs.org).

This module lets you authenticate HTTP requests using [AWS Signature 2 style
HMAC encryption](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html)
in your [Node.js](http://nodejs.org) application. This authentication method is
typically used to protect RESTful API endpoints.

By plugging into Passport, HMAC authentication support can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/) and [Koa](http://koajs.com).

## Authentication Header
The HMAC authentication strategy authenticates users using an [HTTP authorization
header](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.8) with 3
pieces: The _identifier_, the _public key_, and the _signature_.

The _identifier_ can be anything you like, for example in AWS the _identifier_
is 'AWS'. This value is not currently used, but in the future it is intended to
be made available as another source of validating the request -- if needed.

The second piece is the _public key_, that typically is provided by the
_identifier_ of the service being authenticated against.

The _signature_ is the final piece and is a
[RFC 2104 HMAC-SHA1](https://www.ietf.org/rfc/rfc2104.txt) of selected parts of
the request. If the request signature calculated by the service matches the
_signature_ provided in the _authentication_ header, the requester will have
shown they have possession of the _identifier_'s secret access key.

Following is psuedogrammer adapted from AWS Signature 2 documentation.
```
Authorization = "identifier" + " " + publicKey + ":" + signature;

signature = Base64( HMAC-SHA1( YourSecretAccessKeyID, UTF-8-Encoding-Of( StringToSign ) ) );

StringToSign = HTTP-Verb + "\n" +
	Content-MD5 + "\n" +
	Content-Type + "\n" +
	Date + "\n";
```

The elements in `StrinToSign` are positional in nature. The names of the headers
are not included, only their values. If a positional header is not present in
the request (for example, `Content-Type` or `Content-MD5` are meaningless in a
GET request), substitute an empty string for that position.

TODO: implement Time Stamp Requirement

## Install

```bash
$ npm install passport-hmac
```

## Usage

#### Configure Strategy

This strategy requires a `verify` callback, which accepts three parameters: The
`request`, `publicKey`, and a `done` callback.

The `verify` callback can be supplied with the `request` the `passReqToCallback`
option to true, this sets the request as the first parameter instead of the
`publicKey`.

The `publicKey` is used to lookup a user within the system to find their private
key to compare the _signature_.

The `done` callback *MUST* be called at some point and should contain an error,
`false` if a user is not found, or the user and private key if the user was
found.

```js
passport.use(new HmacStrategy(
  function(publicKey, done) {
    User.findOne({ publicKey: publicKey }, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      return done(null, user, privateKey);
    });
  }
));
```

#### Available options

This strategy takes an optional options hash before the function, e.g.,
`new HmacStrategy({/* options */}, callback)`.

The available options are:

* `passReqToCallback` - Optional, defaults to `false`. Setting this to true will
return the request as the first parameter to the supplied callback.
* `badRequestMessage` - Optional, defaults to `null`. If set, will be used in
place of the default error messages returned when an error occurs.

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'hmac'` strategy, to authenticate
requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.post('/profile',
  passport.authenticate('hmac'),
  function(req, res) {
    res.json(req.user);
  }
});
```

## Examples

TODO: write some Examples

## Tests

```bash
$ npm install
$ npm test
```

## Credits

  - [Curtis Hatter](http://github.com/curtishatter)

## License

[The MIT License](http://opensource.org/licenses/MIT)
