/**
 * Tracks third-party logins and profiles.
 *
 * @param {String} provider   Auth provider name, such as facebook, google, twitter, linkedin.
 * @param {String} authScheme Auth scheme, such as oAuth, oAuth 2.0, OpenID, OpenID Connect.
 * @param {String} externalId Provider specific user ID.
 * @param {Object} profile User profile, see http://passportjs.org/guide/profile.
 * @param {Object} credentials Credentials.  Actual properties depend on the auth scheme being used:
 *
 * - oAuth: token, tokenSecret
 * - oAuth 2.0: accessToken, refreshToken
 * - OpenID: openId
 * - OpenID: Connect: accessToken, refreshToken, profile
 * @param {*} userId The LoopBack user ID.
 * @param {Date} created The created date
 * @param {Date} modified The last modified date
 *
 * @class
 * @inherits {DataModel}
 */
module.exports = function (UserIdentity) {
  var loopback = require('loopback');
  var utils = require('./utils');

  /*!
   * Create an access token for the given user
   * @param {User} user The user instance
   * @param {Number} [ttl] The ttl in millisenconds
   * @callback {Function} cb The callback function
   * @param {Error|String} err The error object
    * param {AccessToken} The access token
   */
  function createAccessToken(user, callContext, ttl, cb) {
    if (arguments.length === 3 && typeof ttl === 'function') {
      cb = ttl;
      ttl = 0;
    }
    if (user.createAccessToken) {
        return user.createAccessToken(ttl, callContext, cb);
    }
    user.accessTokens.create({
      created: new Date(),
      ttl: Math.min(ttl || user.constructor.settings.ttl,
        user.constructor.settings.maxTTL)
    }, callContext, cb);
  }

  function profileToUser(provider, profile, options) {

    var userObj = {}
    if (options.userProfileMap) {
      Object.keys(options.userProfileMap).forEach(function(e){
        userObj[e] = profile[options.userProfileMap[e]];
      });
    }
    if (!userObj.email) {
      userObj.email = profile.email;
      if (!userObj.email) {
          userObj.email = profile.emails && profile.emails[0] && profile.emails[0].value;
      }
    }
    if (!userObj.username) {
        userObj.username =  profile[options.userNameAttribute || 'username'] || profile.id;
    }
    if (!userObj.email && !options.emailOptional) {
      // Fake an e-mail
      userObj.email =  userObj.username + '@' + (profile.provider || provider) + '.oecloud.io';
    }
    userObj.password = utils.generateKey('password');
    return userObj;
  }

  /**
   * Log in with a third-party provider such as Facebook or Google.
   *
   * @param {String} provider The provider name.
   * @param {String} authScheme The authentication scheme.
   * @param {Object} profile The profile.
   * @param {Object} credentials The credentials.
   * @param {Object} [options] The options.
   * @callback {Function} cb The callback function.
   * @param {Error|String} err The error object or string.
   * @param {Object} user The user object.
   * @param {Object} [info] The auth info object.
   *
   * -  identity: UserIdentity object
   * -  accessToken: AccessToken object
   */
  UserIdentity.login = function (provider, authScheme, profile, callContext, userModel, credentials,
    options, cb) {
    options = options || {};
    if (typeof options === 'function' && cb === undefined) {
      cb = options;
      options = {};
    }
    var autoLogin = options.autoLogin || options.autoLogin === undefined;
    var userIdentityModel = utils.getModel(this, UserIdentity);
    var externalId = profile.id;
    if (!externalId) {
      externalId = profile[options.profileIdAttribute || 'id'];
      profile.id = externalId;
    }
    if (!externalId) {
        return cb('profile id is missing');
    }
    userIdentityModel.findOne({
      where: {
        provider: provider,
        externalId: externalId
      }
    }, callContext, function (err, identity) {
      if (err) {
        return cb(err);
      }
      if (identity) {
        identity.credentials = credentials;
        return identity.updateAttributes({
          profile: profile,
          credentials: credentials, modified: new Date()
        }, callContext, function (err, i) {
          // Find the user for the given identity
          return userModel.findById(identity.userId, callContext, function (err, user) {
            //return userModel.findById(identity.userId, callContext, function (err, user) {
            // Create access token if the autoLogin flag is set to true
            if (!err && user && autoLogin) {
              return (options.createAccessToken || createAccessToken)(user, callContext, function (err, token) {
                cb(err, user, identity, token);
              });
            }
            cb(err, user, identity);
          });
        });
      }
      // Find the user model
      //var userModel = loopback.getModelByType(loopback.User);
      var userObj = (userModel.profileToUser || options.profileToUser || profileToUser)(provider, profile, options);
      if (!userObj.email && !options.emailOptional) {
        process.nextTick(function () {
          return cb('email is missing from the user profile');
        });
      }

      var query;
      if (userObj.email) {
        query = {
          or: [
            { username: userObj.username },
            { email: userObj.email }
          ]
        };
      } else {
        query = { username: userObj.username };
      }
      userModel.findOrCreate({ where: query }, userObj, callContext, function (err, user) {
        if (err) {
          return cb(err);
        }
        var date = new Date();
        userIdentityModel.create({
          provider: provider,
          externalId: externalId,
          authScheme: authScheme,
          profile: profile,
          credentials: credentials,
          userId: user.id,
          created: date,
          modified: date
        }, callContext, function (err, identity) {
          if (!err && user && autoLogin) {
            return (options.createAccessToken || createAccessToken)(user, callContext, function (err, token) {
              cb(err, user, identity, token);
            });
          }
          cb(err, user, identity);
        });
      });
    });
  };
  return UserIdentity;
};
