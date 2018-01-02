/**
 * 
 * ©2016-2017 EdgeVerve Systems Limited (a fully owned Infosys subsidiary),
 * Bangalore, India. All Rights Reserved.
 * 
 */
var loopback = require('loopback');
var passport = require('passport');
var _ = require('underscore');

module.exports = PassportConfigurator;

/**
 * The passport configurator
 * @param {Object} app The LoopBack app instance
 * @returns {PassportConfigurator}
 * @constructor
 * @class
 */
function PassportConfigurator(app) {
  if (!(this instanceof PassportConfigurator)) {
    return new PassportConfigurator(app);
  }
  this.app = app;
}

/**
 * Set up data models for user identity/credential and application credential
 * @options {Object} options Options for models
 * @property {Model} [userModel] The user model class
 * @property {Model} [userCredentialModel] The user credential model class
 * @property {Model} [userIdentityModel] The user identity model class
 * @end
 */
PassportConfigurator.prototype.setupModels = function(options) {
  options = options || {};
  // Set up relations
  this.userModel = options.userModel || loopback.getModelByType(this.app.models.User);
  this.userCredentialModel = options.userCredentialModel ||
      loopback.getModelByType(this.app.models.UserCredential);
  this.userIdentityModel = options.userIdentityModel ||
      loopback.getModelByType(this.app.models.UserIdentity);

  if (!this.userModel.relations.identities) {
    this.userModel.hasMany(this.userIdentityModel, {as: 'identities'});
  } else {
    this.userIdentityModel = this.userModel.relations.identities.modelTo;
  }

  if (!this.userModel.relations.credentials) {
    this.userModel.hasMany(this.userCredentialModel, {as: 'credentials'});
  } else {
    this.userCredentialModel = this.userModel.relations.credentials.modelTo;
  }

  if (!this.userIdentityModel.relations.user) {
    this.userIdentityModel.belongsTo(this.userModel, {as: 'user'});
  }

  if (!this.userCredentialModel.relations.user) {
    this.userCredentialModel.belongsTo(this.userModel, {as: 'user'});
  }
};

/**
 * Initialize the passport configurator
 * @param {Boolean} noSession Set to true if no session is required
 * @returns {Passport}
 */
PassportConfigurator.prototype.init = function(noSession) {
  var self = this;
  self.app.middleware('session:after', passport.initialize());

  if (!noSession) {
    self.app.middleware('session:after', passport.session());

    // Serialization and deserialization is only required if passport session is
    // enabled

    passport.serializeUser(function(user, options, done) {
      if (!user) {
        user = options;
        options = null;
      }
      done(null, user.id);
    });

    passport.deserializeUser(function(id, options, done) {
      if (!id) {
        id = options;
        options = null;
      }
      // Look up the user instance by id
      self.userModel.findById(id, function(err, user) {
        if (err || !user) {
          return done(err, user);
        }
        user.identities(function(err, identities) {
          user.profiles = identities;
          user.credentials(function(err, accounts) {
            user.accounts = accounts;
            done(err, user);
          });
        });
      });
    });
  }

  return passport;
};

/**
 * Configure a Passport strategy provider.
 * @param {String} name The provider name
 * @options {Object} General&nbsp;Options Options for the auth provider.
 * There are general options that apply to all providers, and provider-specific
 * options, as described below.
 * @property {Boolean} link Set to true if the provider is for third-party
 * account linking.
 * @property {Object} module The passport strategy module from require.
 * @property {String} authScheme The authentication scheme, such as 'local',
 * 'oAuth 2.0'.
 * @property {Boolean} [session] Set to true if session is required.  Valid
 * for any auth scheme.
 * @property {String} [authPath] Authentication route.
 *
 * @options {Object} oAuth2&nbsp;Options Options for oAuth 2.0.
 * @property {String} [clientID] oAuth 2.0 client ID.
 * @property {String} [clientSecret] oAuth 2.0 client secret.
 * @property {String} [callbackURL] oAuth 2.0 callback URL.
 * @property {String} [callbackPath] oAuth 2.0 callback route.
 * @property {String} [scope] oAuth 2.0 scopes.
 * @property {String} [successRedirect] The redirect route if login succeeds.
 * For both oAuth 1 and 2.
 * @property {String} [failureRedirect] The redirect route if login fails.
 * For both oAuth 1 and 2.
 *
 * @options {Object} Local&nbsp;Strategy&nbsp;Options Options for local
 * strategy.
 * @property {String} [usernameField] The field name for username on the form
 * for local strategy.
 * @property {String} [passwordField] The field name for password on the form
 * for local strategy.
 *
 * @options {Object} oAuth1&nbsp;Options Options for oAuth 1.0.
 * @property {String} [consumerKey] oAuth 1 consumer key.
 * @property {String} [consumerSecret] oAuth 1 consumer secret.
 * @property {String} [successRedirect] The redirect route if login succeeds.
 * For both oAuth 1 and 2.
 * @property {String} [failureRedirect] The redirect route if login fails.
 * For both oAuth 1 and 2.
 *
 * @options {Object} OpenID&nbsp;Options Options for OpenID.
 * @property {String} [returnURL] OpenID return URL.
 * @property {String} [realm] OpenID realm.
 * @end
 */
PassportConfigurator.prototype.configureProvider = function(name, options) {
  var self = this;
  options = options || {};
  var link = options.link;
  var AuthStrategy = require(options.module)[options.strategy || 'Strategy'];

  var authScheme = options.authScheme;
  if (!authScheme) {
    // Guess the authentication scheme
    if (options.consumerKey) {
      authScheme = 'oAuth1';
    } else if (options.realm) {
      authScheme = 'OpenID';
    } else if (options.clientID) {
      authScheme = 'oAuth 2.0';
    } else if (options.usernameField) {
      authScheme = 'local';
    } else {
      authScheme = 'local';
    }
  }

  /**
   *
   * @param req
   * @param res
   * @param user_id
   * @param access_token
   * @param ttl
   */
  function addCookies(req, res, userId, accessToken, ttl, secure) {
    res.cookie('access_token', accessToken,
      {
        signed: req.signedCookies ? true : false,
        // maxAge is in ms
        maxAge: 1000 * ttl,
        secure: secure ? true : false,
        httpOnly: true
      });
    res.cookie('userId', userId.toString(), {
      signed: req.signedCookies ? true : false,
      maxAge: 1000 * ttl,
      secure: secure ? true : false,
      httpOnly: true
    });
  }
  /**
   * @auther lior.schindler@edgeverve.com (Lior Schindler)
   * Create a "portable contact" profile from ldap authentication data using supplied attribute names or rfc standard.
   * @param {object} user user object received from an ldap passport strategy.
   * @param {object} options contains all relevant ldap attribute names.
   * @param {string} options.LdapAttributeForUsername ldap username attribute name.
   * @param {string} options.LdapAttributeForMail ldap mail attribute name.
   * @param {string} options.LdapAttributeForLogin ldap user id attribute name.
   * @param {string} options.LdapAttributeForSurname ldap surname attribute name.
   * @param {string} options.LdapAttributeForGivenName ldap first name attribute name.
   * @param {string} options.LdapAttributeForDisplayName ldap display name attribute name.
   * @param {string} options.LdapAttributeForEmail ldap email attribute name.
   * @return {object} the generated profile.
   */
  function createLdapProfile(user, callContext, options) {
    var profile = {};
    profile.provider = 'ldap';
    profile.id = user[options.LdapAttributeForLogin || 'uid'];
    profile.username = [].concat(user[options.LdapAttributeForUsername || 'cn'])[0]; //get only the first username
    profile.name = {
      familyName: user[options.LdapAttributeForSurname || 'sn'],
      givenName: user[options.LdapAttributeForGivenName || 'givenName'],
    };
    profile.displayName = user[options.LdapAttributeForDisplayName || 'displayName'] ||
                          (profile.name.givenName + profile.name.familyName);
    var email = user[options.LdapAttributeForEmail || 'mail'];
    profile.email = email;
    if (!!email) {
      profile.emails = [{ value: email }];
    }
      
    profile.data = {};
    _.extendOwn(profile.data, user); //
    return profile;
  }

  var clientID = options.clientID;
  var clientSecret = options.clientSecret;
  var callbackURL = options.callbackURL;
  var authPath = options.authPath || ((link ? '/link/' : '/auth/') + name);
  var callbackPath = options.callbackPath || ((link ? '/link/' : '/auth/') +
      name + '/callback');
  var successRedirect = options.successRedirect ||
      (link ? '/link/account' : '/auth/account');
  var failureRedirect = options.failureRedirect ||
      (link ? '/link.html' : '/login.html');
  var scope = options.scope;
  var authType = authScheme.toLowerCase();

  var session = !!options.session;

  var loginCallback = options.loginCallback || function(req, done) {
    return function(err, user, identity, token) {
      var authInfo = {
        identity: identity,
      };
      if (token) {
        authInfo.accessToken = token;
      }
      if (user && typeof user.id === 'object') {
          user.id = user.id.toString();
      }
      done(err, user, authInfo);
    };
  };

  switch (authType) {
    case 'ldap':
      passport.use(name, new AuthStrategy(_.defaults({
        usernameField: options.usernameField || 'username',
        passwordField: options.passwordField || 'password',
        session: options.session, authInfo: true,
        passReqToCallback: true,
      }, options),
          function(req, user, done) {
            if (user) {
              var profile = createLdapProfile(user, req.callContext, options); //Lior: create ldap profile according to portable contacts schema
              var OptionsForCreation = _.defaults({
                autoLogin: true,
              }, options);
              
              self.userIdentityModel.login(name, authScheme, profile, req.callContext, self.userModel, {},
                  OptionsForCreation, loginCallback(req, done));
            } else {
              done(null);
            }
          }
      ));
      break;
    case 'local':
      passport.use(name, new AuthStrategy(_.defaults({
        usernameField: options.usernameField || 'username',
        passwordField: options.passwordField || 'password',
        session: options.session, authInfo: true,
          passReqToCallback : true,
      }, options),
      function(req, username, password, done) {
        var query = {
          where: {
            or: [
              {username: username},
              {email: username},
            ],
          },
        };
        self.userModel.findOne(query, req.callContext, function(err, user) {
          if (err) {
            return done(err);
          }
          if (user) {
            var u = user.toJSON();
            delete u.password;
            var userProfile = {
              provider: 'local',
              id: u.id,
              username: u.username,
              emails: [
                {
                  value: u.email,
                },
              ],
              status: u.status,
              accessToken: null,
            };

            // If we need a token as well, authenticate using Loopbacks
            // own login system, else defer to a simple password check
            //will grab user info from providers.json file.  Right now
            //this only can use email and username, which are the 2 most common
            if (options.setAccessToken) {
              switch (options.usernameField) {
                case  'email':
                  login({email: username, password: password});
                  break;
                case 'username':
                  login({username: username, password: password});
                  break;
              }

              function login(creds) {
                self.userModel.login(creds,
                    req.callContext, function(err, accessToken) {
                      if (err) {
                        return done(null, false, {message: 'Incorrect username or password.'});
                      }
                      if (accessToken) {
                        userProfile.accessToken = accessToken;
                        done(null, user, {accessToken: accessToken});
                      } else {
                        done(null, false, {message: 'Failed to create token.'});
                      }
                    });
              }
            } else {
              user.hasPassword(password, function(err, ok) {
                if (ok) {
                  done(null, userProfile);
                } else {
                  return done(null, false, {message: 'Incorrect username or password.'});
                }
              });
            }
          } else {
            return done(null, false, {message: 'Incorrect username or password.'});
          }
        });
      }
      ));
      break;
    case 'oauth':
    case 'oauth1':
    case 'oauth 1.0':
      passport.use(name, new AuthStrategy(_.defaults({
        consumerKey: options.consumerKey,
        consumerSecret: options.consumerSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
          function(req, token, tokenSecret, profile, done) {
            if (link) {
              if (req.user) {
                self.userCredentialModel.link(
                    req.user.id, name, authScheme, profile,
                    {token: token, tokenSecret: tokenSecret}, options, done);
              } else {
                done('No user is logged in');
              }
            } else {
              self.userIdentityModel.login(name, authScheme, profile,
                req.callContext, self.userModel, {
                  token: token,
                  tokenSecret: tokenSecret,
                }, options, loginCallback(req, done));
            }
          }
      ));
      break;
    case 'openid':
      passport.use(name, new AuthStrategy(_.defaults({
        returnURL: options.returnURL,
        realm: options.realm,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
          function(req, identifier, profile, done) {
            if (link) {
              if (req.user) {
                self.userCredentialModel.link(
                    req.user.id, name, authScheme, profile,
                    {identifier: identifier}, options, done);
              } else {
                done('No user is logged in');
              }
            } else {
              self.userIdentityModel.login(name, authScheme, profile,
                  req.callContext, self.userModel, {identifier: identifier}, options, loginCallback(req, done));
            }
          }
      ));
      break;
    case 'openid connect':
      passport.use(name, new AuthStrategy(_.defaults({
        clientID: clientID,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
          function(req, accessToken, refreshToken, profile, done) {
            if (link) {
              if (req.user) {
                self.userCredentialModel.link(
                    req.user.id, name, authScheme, profile,
                  {
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                  }, options, done);
              } else {
                done('No user is logged in');
              }
            } else {
              self.userIdentityModel.login(name, authScheme, profile,
                  req.callContext, self.userModel, {accessToken: accessToken, refreshToken: refreshToken},
                  options, loginCallback(req, done));
            }
          }
      ));
      break;
    case 'saml':
        passport.use(name, new AuthStrategy(_.defaults({
          clientID: clientID,
          clientSecret: clientSecret,
          callbackURL: callbackURL,
          passReqToCallback: true,
        }, options),
           function(req, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(
                  req.user.id, name, authScheme, profile,
                {}, options, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile,
                req.callContext, self.userModel, {},
                options, loginCallback(req, done));
          }
        }
      ));
      break;
    default:
      passport.use(name, new AuthStrategy(_.defaults({
        clientID: clientID,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
          function(req, accessToken, refreshToken, profile, done) {
            if (link) {
              if (req.user) {
                self.userCredentialModel.link(
                    req.user.id, name, authScheme, profile,
                  {
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                  }, options, done);
              } else {
                done('No user is logged in');
              }
            } else {
              self.userIdentityModel.login(name, authScheme, profile,
                  req.callContext, self.userModel, {accessToken: accessToken, refreshToken: refreshToken},
                  options, loginCallback(req, done));
            }
          }
      ));
  }

  var defaultCallback = function(req, res, next) {
    // The default callback
    passport.authenticate(name, _.defaults({session: session},
        options.authOptions), function(err, user, info) {
          if (err) {
            return next(err);
          }
          if (!user) {
            if (!!options.json) {
              return res.status(401).json(info);
            }
            return res.redirect(failureRedirect);
          }

          if (session) {
            req.logIn(user, function(err) {
              if (err) {
                return next(err);
              }
            });
          }
          if (info && info.accessToken) {
            /*
             * using flash so that we can have the client app running in
             * diffrent server to get the flash message. ususally usefull for
             * oauth callback. since oauth servers sends credentials to this server,
             * but if client need to get the access token this will be better.
             * we need to make success redirect make call to some route
             * and return this flash message to get the token which only
             * stays for one request.
             */
            if (!!options.flashResponse) {
              req.flash('access_token', {'access_token': info.accessToken.id});
            }
            if (!!options.cookie) {
              var isSecure = (process.env.PROTOCOL && process.env.PROTOCOL == 'https' ? true : false) || info.accessToken.constructor.app.get('https');
              addCookies(req, res, user.id, info.accessToken.id, info.accessToken.ttl, isSecure);
            }
            if (!!options.json) {
              return res.json({
                'access_token': info.accessToken.id,
                userId: user.id,
              });
            }
          }
          successRedirect = function(req, accessToken, profile) {
            if (!!req && req.session && req.session.returnTo) {
              var returnTo = req.session.returnTo;
              delete req.session.returnTo;
              return appendAccessToken(returnTo, accessToken, profile);
            }
            return appendAccessToken(options.successRedirect, accessToken, profile) ||
              (link ? '/link/account' : '/auth/account');
          };
        
          var appendAccessToken = function(url, accessToken, profile) {
            if (!accessToken) {
              return url;
            }
            return url + '?access_token=' + accessToken.id + '&userId=' + accessToken.userId + '&username=' + profile.name.givenName;
          };
          console.log('redirect to ', successRedirect);
          return res.redirect(successRedirect(req, info.accessToken, info.identity.profile));
        })(req, res, next);
  };
  console.log('config ', name, authPath, callbackPath);
  /*
   * Redirect the user to Facebook for authentication.  When complete,
   * Facebook will redirect the user back to the application at
   * /auth/facebook/callback with the authorization code
   */
  if (authType === 'local' || authType === 'ldap') {
    var authCallback = options.customCallback || defaultCallback;
    self.app.post(authPath, authCallback);
  } else if (link) {
    self.app.get(authPath, passport.authorize(name, _.defaults({
      scope: scope,
      session: session,
    }, options.authOptions)));
  } else {
    self.app.get(authPath, passport.authenticate(name, _.defaults({
      scope: scope,
      session: session,
    }, options.authOptions)));
  }

  /*
   * Facebook will redirect the user to this URL after approval. Finish the
   * authentication process by attempting to obtain an access token using the
   * authorization code. If access was granted, the user will be logged in.
   * Otherwise, authentication has failed.
   */
  if (link) {
    self.app.get(callbackPath, passport.authorize(name, _.defaults({
      session: session,
      // successReturnToOrRedirect: successRedirect,
      successRedirect: successRedirect,
      failureRedirect: failureRedirect,
    }, options.authOptions)),
        // passport.authorize doesn't handle redirect
        function(req, res, next) {
          res.redirect(successRedirect);
        }, function(err, req, res, next) {
          res.redirect(failureRedirect);
        });
  } else {
    if (authType === 'saml') {
        var customCallback = options.customCallback || defaultCallback;
        // Register the path and the callback.
        self.app.post(callbackPath, customCallback);
    } else {
      var customCallback = options.customCallback || defaultCallback;
      // Register the path and the callback.
      self.app.get(callbackPath, customCallback);
    }
  }
};
