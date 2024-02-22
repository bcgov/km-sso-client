import { passport, keycloakClient, tokenset } from './server.js';

export const setRoutes = (router) => {

  /**
   * Return status of user session
   */
  
  router.get('/', (req, res, next) => {

    // DEBUG
    // const {name} = req?.session?.passport?.user || {};
    // console.log('\n\n<<< Authenticate >>>\n\nUser:', name);

    if (req?.session?.passport?.user) {
      res.status(200).json({
        message: {},
        result: true,
      });
    }
    else {
      res.status(401).json({
        message: {},
        result: false,
      });
    }
  });

  /**
   * Return response status of application
   */
  
  router.get('/health', (req, res, next) => {
    res.status(200).json({
        message: {},
        result: true,
      });
    }
  );

  /**
   * Authentication redirect (Keycloak SSO)
   */

  router.get('/authn', (req, res, next) => {
    passport.authenticate('oidc')(req, res, next);
  });

  /**
   * Callback for authentication redirection
   */

  router.get('/authn/callback', (req, res, next) => {
    passport.authenticate('oidc', {
      successRedirect: `https://${req.headers.host}`,
      failureRedirect: '/',
    })(req, res, next);
  });

  router.get('/logout', (req, res, next) => {
    req.session.destroy();
    const retUrl = `${process.env.SSO_AUTH_SERVER_URL}/realms/${
      process.env.SSO_REALM
    }/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(
      process.env.SSO_LOGOUT_REDIRECT_URI,
    )}&id_token_hint=${tokenset.id_token}`;
    res.redirect(`https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(retUrl)}`);
  });
};
