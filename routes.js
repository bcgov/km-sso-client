import { passport, keycloakClient, tokenset } from './server.js';

export const setRoutes = (router) => {

  /**
   * Authorize user session
   * 
   */

  router.get('/', (req, res) => {
      // DEBUG
      console.log('Authenticated?', req.isAuthenticated())
      return res.sendStatus(req.isAuthenticated() ? 200 : 401);
  });

  // app.get('/protected', function(req, res, next) {
  //   passport.authenticate('local', function(err, user, info, status) {
  //     if (err) { return next(err) }
  //     if (!user) { return res.redirect('/signin') }
  //     res.redirect('/account');
  //   })(req, res, next);
  // });

  /**
   * Authentication (Keycloak SSO-CSS)
   */

  router.get('/authn', passport.authenticate('oidc'));

  /**
   * Callback for authentication redirection
   */

  router.get('/authn/callback', passport.authenticate('oidc', {
      successRedirect: `https://${req.headers.host}?confirmed=true`,
      failureRedirect: '/',
    })
    );

  /**
   * Return response status of application
   */
  
  router.get('/health', (req, res, next) => {
    return res.sendStatus(200);
  });

  /**
   * Logout user from Keycloak session
   */

  router.get('/logout', (req, res, next) => {
    req.session.destroy();
    const retUrl = `${process.env.SSO_AUTH_SERVER_URL}/auth/realms/${
      process.env.SSO_REALM
    }/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(
      process.env.SSO_LOGOUT_REDIRECT_URI,
    )}&id_token_hint=${tokenset.id_token}`;
    res.redirect(`https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(retUrl)}`);
  });
};
