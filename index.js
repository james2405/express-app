const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser');
const session = require('express-session');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
require('dotenv').config();
const morgan = require('morgan');
const sqlite3 = require('better-sqlite3');
const { deriveKey, generateSalt, fastParams } = require('./helpers/auth-utils');

const app = express();
const port = process.env.SERVER_PORT || 3000;
const jwtSecret = require('crypto').randomBytes(16);

// Middleware
const loggerMiddleware = (req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
};

app.use(morgan('dev'));
app.use(express.static('public'));
app.use(cookieParser());
app.use(loggerMiddleware);
app.use(flash());

app.use(session({
  secret: 'tu secreto muy secreto',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuración de Passport
const db = new sqlite3('database/credentials.db', { fileMustExist: true });

passport.use('signup-username-password', new LocalStrategy(
  async (username, password, done) => {
    const userExists = db.prepare('SELECT COUNT(*) AS count FROM credentials WHERE username = ?').get(username).count > 0;
    if (userExists) {
      return done(null, false, { message: 'User already exists' });
    }
    
    const salt = generateSalt();
    const hash = await deriveKey(password, salt, fastParams);
    
    try {
      db.prepare('INSERT INTO credentials (username, password, salt) VALUES (?, ?, ?)').run(username, hash, salt);
      return done(null, { username });
    } catch (error) {
      return done(error);
    }
  }
));

passport.use('login-username-password', new LocalStrategy(
  async (username, password, done) => {
    const user = db.prepare('SELECT * FROM credentials WHERE username = ?').get(username);
    if (!user) {
      return done(null, false, { message: 'Incorrect username or password' });
    }
    
    const hash = await deriveKey(password, user.salt, fastParams);
    if (user.password !== hash) {
      return done(null, false, { message: 'Incorrect username or password' });
    }
    
    return done(null, { username });
  }
));

passport.use('jwtCookie', new JwtStrategy({
  jwtFromRequest: ExtractJwt.fromExtractors([(req) => req.cookies.jwt]),
  secretOrKey: jwtSecret
}, (jwtPayload, done) => {
  const user = db.prepare('SELECT * FROM credentials WHERE username = ?').get(jwtPayload.sub);
  if (!user) return done(null, false);
  return done(null, { username: jwtPayload.sub });
}));

// // Elimina la serialización del usuario
// passport.serializeUser((user, done) => {
//   done(null, user.username);
// });

// passport.deserializeUser((username, done) => {
//   const user = db.prepare('SELECT * FROM credentials WHERE username = ?').get(username);
//   done(null, user);
// });

// Rutas
app.get('/', passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }), (req, res) => {
  res.send(`Welcome to your private page, ${req.user.username}!`);
});

app.get('/login', (req, res) => {
  const messages = req.flash('error');
  res.send(`
    <h1>Login</h1>
    <form action="/login" method="post">
      <div>
        <label>Username:</label>
        <input type="text" name="username" />
      </div>
      <div>
        <label>Password:</label>
        <input type="password" name="password" />
      </div>
      <div>
        <button type="submit">Login</button>
      </div>
    </form>
    ${messages.length > 0 ? `<p>${messages[0]}</p>` : ''}
  `);
});

app.get('/signup', (req, res) => {
  const messages = req.flash('error');
  res.send(`
    <h1>Signup</h1>
    <form action="/signup" method="post">
      <div>
        <label>Username:</label>
        <input type="text" name="username" />
      </div>
      <div>
        <label>Password:</label>
        <input type="password" name="password" />
      </div>
      <div>
        <button type="submit">Signup</button>
      </div>
    </form>
    ${messages.length > 0 ? `<p>${messages[0]}</p>` : ''}
  `);
});

app.post('/signup', passport.authenticate('signup-username-password', { session: false, failureRedirect: '/signup', failureFlash: true }), (req, res) => {
  const token = jwt.sign({ sub: req.user.username }, jwtSecret, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true, secure: false });
  
  // Log link to jwt.io debugger for easy checking/verifying
  console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
  console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
  
  console.log('User registered successfully');
  res.redirect('/');
});

app.post('/login', passport.authenticate('login-username-password', { session: false, failureRedirect: '/login', failureFlash: true }), (req, res) => {
  const token = jwt.sign({ sub: req.user.username }, jwtSecret, { expiresIn: '1h' });
  res.cookie('jwt', token, { httpOnly: true, secure: false });
  
  // Log link to jwt.io debugger for easy checking/verifying
  console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
  console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`);
  
  console.log('User logged in successfully');
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  res.cookie('jwt', '', { expires: new Date(0) });
  res.redirect('/login');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('¡Algo salió mal!');
});

app.listen(port, () => {
  console.log(`Aplicación de ejemplo escuchando en http://localhost:${port}`);
});
