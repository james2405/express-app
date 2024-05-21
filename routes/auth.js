require('dotenv').config();
const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const jwt = require('jsonwebtoken');
const { deriveKey, generateSalt } = require('../helpers/auth-utils');
const base64 = require('base64-arraybuffer');
const jwtSecret = Buffer.from(process.env.JWT_SECRET, 'base64');
const sqlite3 = require('better-sqlite3');

const router = express.Router();
const db = new sqlite3('database/credentials.db', { fileMustExist: true });

const createUserDB = (username, password, salt) => {
  const stmt = db.prepare('INSERT INTO credentials (username, password, salt) VALUES (?, ?, ?)');
  stmt.run(username, password, salt);
};

const getUserDB = (username) => {
  const stmt = db.prepare('SELECT * FROM credentials WHERE username = ?');
  return stmt.get(username);
};

const userExistsDB = (username) => {
  const stmt = db.prepare('SELECT COUNT(*) AS count FROM credentials WHERE username = ?');
  const row = stmt.get(username);
  return row.count > 0;
};

passport.use('signup-username-password', new LocalStrategy(
  async (username, password, done) => {
    if (userExistsDB(username)) {
      return done(null, false, { message: 'User already exists' });
    }

    const salt = generateSalt();
    const hash = await deriveKey(password, salt, true);
    createUserDB(username, hash, salt);

    return done(null, { username });
  }
));

passport.use('login-username-password', new LocalStrategy(
  async (username, password, done) => {
    const user = getUserDB(username);
    if (!user) {
      return done(null, false, { message: 'Incorrect username or password' });
    }

    const hash = await deriveKey(password, user.salt, true);
    if (user.password !== hash) {
      return done(null, false, { message: 'Incorrect username or password' });
    }

    return done(null, { username });
  }
));

passport.use('jwtCookie', new JwtStrategy({
  jwtFromRequest: req => req && req.cookies ? req.cookies.jwt : null,
  secretOrKey: jwtSecret
}, (jwtPayload, done) => {
  if (jwtPayload && jwtPayload.sub) {
    return done(null, { username: jwtPayload.sub });
  }
  return done(null, false);
}));

router.post('/signup', passport.authenticate('signup-username-password', { failureRedirect: '/signup', failureFlash: true }), (req, res) => {
  const token = jwt.sign({ sub: req.user.username }, jwtSecret, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true, secure: false });
  res.redirect('/');
});

router.post('/login', passport.authenticate('login-username-password', { failureRedirect: '/login', failureFlash: true }), (req, res) => {
  const token = jwt.sign({ sub: req.user.username }, jwtSecret, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true, secure: false });
  res.redirect('/');
});

router.get('/logout', (req, res) => {
  res.cookie('jwt', '', { expires: new Date(0) });
  res.redirect('/login');
});

module.exports = router;
