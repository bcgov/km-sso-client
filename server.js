import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import passport from 'passport';
import { Issuer, Strategy } from 'openid-client';
import * as dotenv from 'dotenv';
import { setRoutes } from './routes.js';
import redis from 'redis';
import RedisStore from "connect-redis";

dotenv.config();

const app = express();

// api.use(helmet({contentSecurityPolicy: false}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.disable("x-powered-by");

// init user sessions
// 'trust proxy' = true, the client’s IP address is understood as the
// left-most entry in the X-Forwarded-For header.
// ref: https://expressjs.com/en/guide/behind-proxies.html
app.set("trust proxy", 1);

// Initialize redis client
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
redisClient.connect().catch(console.error)

// Initialize store.
let redisStore = new RedisStore({
  client: redisClient,
});

//Configure session middleware
app.use(session({
  store: redisStore,
  secret: process.env.SSO_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
      secure: false, // if true only transmit cookie over https
      httpOnly: false, // if true prevent client side JS from reading the cookie 
      maxAge: 1000 * 60 * 10 // session max age in miliseconds
  }
}));

// parse cookies to store session data
app.use(cookieParser(process.env.SSO_SESSION_SECRET));

// init Passport
app.use(passport.initialize());
app.use(passport.session());

const router = express.Router();

setRoutes(router);

app.use('/', router);

const keycloakIssuer = await Issuer.discover(
  `${process.env.SSO_AUTH_SERVER_URL}/realms/${process.env.SSO_REALM}/.well-known/openid-configuration`,
);

const keycloakClient = new keycloakIssuer.Client({
  client_id: process.env.SSO_CLIENT_ID,
  client_secret: process.env.SSO_CLIENT_SECRET,
  redirect_uris: [process.env.SSO_REDIRECT_URL],
  response_types: ['code'],
});

let tokenset = {};

passport.use(
  'oidc',
  new Strategy({ client: keycloakClient }, (tokenSet, userinfo, done) => {
    tokenset = tokenSet;
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
});

export { passport, keycloakClient, tokenset };