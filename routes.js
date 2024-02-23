import { passport, keycloakClient, tokenset } from './server.js';

/**
   * Check user authentication
   */

const isAuthenticated = (req, res, next) => {
  passport.authenticate('oidc', function(err, user, info, status) {
    // DEBUG
    console.log('Is authenticated?', user, info, status)
    if (err) return next(err);
    if (!user) return res.sendStatus(401);
    res.sendStatus(200);
  })(req, res, next);
}

export const setRoutes = (router) => {

  /**
   * Authorize user session
   */
  
  router.get('/', isAuthenticated);

  /**
   * Authentication (Keycloak SSO-CSS)
   */

  router.get('/authn', passport.authenticate('oidc'));

  /**
   * Callback for authentication redirection
   */

  router.get('/authn/callback', (req, res, next) => {
    console.log('Auth callback:', req.headers)
    passport.authenticate('oidc', {
      successRedirect: `https://${req.headers.host}?confirmed=true`,
      failureRedirect: '/noauth',
    })
  });

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
