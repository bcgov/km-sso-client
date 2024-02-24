/** 
 * Keycloak Client: Authorization Code Flow with OIDC
 * The Authorization Code Flow is used by server-side applications that 
 * are capable of securely storing secrets, or by native applications 
 * through Authorization Code Flow with PKCE.
 * 
 * The OIDC-conformant pipeline affects the Authorization Code Flow in 
 * the following areas:
 *  - Authentication request
 *  - Authentication response
 *  - Code exchange request
 *  - Code exchange response
 *  - ID token structure
 *  - Access token structure
 *  - Authentication
 * 
 * MIT Licensed 2024
 */

import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Issuer, Strategy } from 'openid-client';
import * as dotenv from 'dotenv';
import redis from 'redis';
import RedisStore from "connect-redis";
import cors from "cors";
import logger from "morgan";
import cookieParser from "cookie-parser";

// optional load of .env
dotenv.config();

/**
 * Loads OpenID Connect 1.0 documents. When the issuer 
 * argument contains '.well-known' only that document is loaded, 
 * otherwise performs both openid-configuration and 
 * oauth-authorization-server requests.
 * 
 * This is the recommended method of getting yourself an Issuer instance.
 * - issuer: <string> Issuer Identifier or metadata URL
 * - Returns: Promise<Issuer>
 */

const keycloakIssuer = await Issuer.discover(
  `${process.env.SSO_AUTH_SERVER_URL}/auth/realms/${process.env.SSO_REALM}/.well-known/openid-configuration`,
);

/**
 * Returns the <Client> class tied to the Keycloak issuer.
 */

const keycloakClient = new keycloakIssuer.Client({
  client_id: process.env.SSO_CLIENT_ID,
  client_secret: process.env.SSO_CLIENT_SECRET,
  redirect_uris: [process.env.SSO_REDIRECT_URL],
  response_types: ['code'],
});

// Initialize redis client for session store
let redisClient = redis.createClient({
  url: process.env.SSO_REDIS_SESSION_STORE_URL,
  password: process.env.SSO_REDIS_CONNECT_PASSWORD
});
redisClient.on('error', function (err) {
  console.log('Could not establish a connection with redis. ' + err);
});
redisClient.on('connect', function (err) {
  console.log('Connected to redis session store successfully');
});
redisClient.connect().catch(console.error);

// configure CORS allowed hostnames
const allowedOrigins = [
  process.env.SSO_BASE_URL,
  process.env.SSO_REDIS_SESSION_STORE_URL, 
  process.env.SSO_AUTH_SERVER_URL
];

// CORS configuration settings
const corsConfig = {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
    optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
};

// create express application
const app = express();

// init utility middleware
// app.use(cors(corsConfig));
app.use(logger('dev'));
// app.use(helmet({contentSecurityPolicy: false}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.disable("x-powered-by");
app.use(cookieParser());

// 'trust proxy' = truthy to handle undefined forwarded proxy
// ref: https://expressjs.com/en/guide/behind-proxies.html
app.set("trust proxy", 1);

// Configure session middleware
// - connects to Redis store for sessions
app.use(session({
  store: new RedisStore({
    client: redisClient,
  }),
  secret: process.env.SSO_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
      sameSite: 'strict',
      secure: false, 
      httpOnly: true, 
      maxAge: 1000 * 60 * 10
  }
}));

// init Passport
app.use(passport.initialize());
app.use(passport.session());

/**
 * Configure passport
 * Returns the <Client> class tied to the Keycloak issuer.
 */

let tokenset = {};

passport.use(
  'oidc',
  new Strategy({ client: keycloakClient}, (tokenSet, userinfo, done) => {
    console.log("tokenSet",tokenSet);
    console.log("userinfo",userinfo);
    tokenset = tokenSet
    return done(null, tokenSet.claims());
  }),
);
passport.serializeUser((user, done) => {
  console.log('Serialize:', user)
  done(null, user);
});
passport.deserializeUser((user, done) => {
  console.log('Deserialize:', user)
  done(null, user);
});

/**
   * Authorize user session
   * 
   */

app.get('/', (req, res) => {
  console.log(req.session)
  // DEBUG
  console.log('Authenticated?', req.isAuthenticated())
  return res.sendStatus(req.isAuthenticated() ? 200 : 401);
});

/**
* Authentication (Keycloak SSO-CSS)
*/

app.get('/authn', passport.authenticate('oidc'));

/**
* Callback for authentication redirection
*/

app.get('/authn/callback', (req, res, next) => {
  console.log('Callback', req.session, req.headers.host)
  passport.authenticate('oidc', {
    successRedirect: `https://${req.headers.host}`,
    failureRedirect: '/',
  })(req, res, next);
});

/**
* Return response status of application
*/

app.get('/health', (req, res) => {
return res.sendStatus(200);
});

/**
* Logout user from Keycloak session
*/

app.get('/logout', (req, res, next) => {
  req.session.destroy();
  const retUrl = `${process.env.SSO_AUTH_SERVER_URL}/auth/realms/${
    process.env.SSO_REALM
  }/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(
    process.env.SSO_LOGOUT_REDIRECT_URI,
  )}&id_token_hint=${tokenset.id_token}`;
  res.redirect(`https://logon7.gov.bc.ca/clp-cgi/logoff.cgi?retnow=1&returl=${encodeURIComponent(retUrl)}`);
});

/**
* Show connection listener status
*/

app.listen(3000, function () {
  console.log('Listening on port 3000');
  console.log('Allowed origins:', allowedOrigins.join(', '));
});

export { passport, keycloakClient, tokenset };
