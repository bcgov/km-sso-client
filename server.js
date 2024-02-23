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
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';
import { Issuer, Strategy } from 'openid-client';
import * as dotenv from 'dotenv';
import { setRoutes } from './routes.js';
import redis from 'redis';
import RedisStore from "connect-redis";
import cors from "cors";

// optional load of .env
dotenv.config();

// create express application
const app = express();

// app.use(helmet({contentSecurityPolicy: false}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.disable("x-powered-by");

// init user sessions
// 'trust proxy' = true, the client’s IP address is understood as the
// left-most entry in the X-Forwarded-For header.
// ref: https://expressjs.com/en/guide/behind-proxies.html
app.set("trust proxy", 1);

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

// Initialize store.
let redisStore = new RedisStore({
  client: redisClient,
});

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

// init CORS middleware
app.use(cors(corsConfig));

// Configure session middleware
// - connects to Redis store for sessions
app.use(session({
  store: redisStore,
  secret: process.env.SSO_SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
      sameSite: 'strict',
      secure: true, 
      httpOnly: true, 
      maxAge: 1000 * 60 * 10
  }
}));

// parse cookies to store session data
// app.use(cookieParser(process.env.SSO_SESSION_SECRET));

// init Passport
app.use(passport.initialize());
app.use(passport.session());

// init Express router
const router = express.Router();
setRoutes(router);
app.use('/', router);

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

console.log(keycloakClient.metadata)

/**
 * Returns the <Client> class tied to the Keycloak issuer.
 */

let tokenset = {};

passport.use(
  'oidc',
  new Strategy({ client: keycloakClient, passReqToCallback: true}, (tokenSet, userinfo, done) => {
    console.log("tokenSet",tokenSet);
    console.log("userinfo",userinfo);
    tokenset = tokenSet
    return done(null, tokenSet.claims());
  }),
);

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

app.listen(3000, function () {
  console.log('Listening on port 3000');
  console.log('Allowed origins:', allowedOrigins.join(', '));
});

export { passport, keycloakClient, tokenset };
