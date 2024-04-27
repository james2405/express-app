const express = require('express');
const jwt = require('jsonwebtoken')
const path = require('path');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const cookieParser = require('cookie-parser')

const morgan = require('morgan');
const app = express();
const port = 3000;
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random
//console.log(`Clave secreta JWT actual: ${jwtSecret}`);

app.use(morgan('dev'));

app.use(express.static('public'));

/*app.get('/', (req, res) => {
  res.send('Hola Mundo');
});*/

// Ruta para el login
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(port, () => {
  console.log(`Aplicación de ejemplo escuchando en http://localhost:${port}`);
});

app.get('/user', (req, res) => {
  const user = {
    name: 'alanis',
    description: 'examen'
  }
  res.json(user)
})

const loggerMiddleware = (req, res, next) => {
    console.log(`${req.method} ${req.path}`);
    next(); // Llama al siguiente middleware o ruta
};

app.use(loggerMiddleware);

app.use(express.static('public')); // para servir archivos estáticos desde la carpeta 'public'

app.use(express.json()); // para analizar cuerpos de solicitud JSON
app.use(express.urlencoded({ extended: true })); // para analizar cuerpos de solicitud con codificación URL

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('¡Algo salió mal!');
});


app.get('/', (req, res) => {
  res.send('Welcome to your private page, user!')
})


passport.use('username-password', new LocalStrategy(
  function(username, password, done) {
    // Aquí es donde verificarías contra tu base de datos, en este ejemplo, usamos datos codificados
    const user = { username: 'alanis', password: 'alanis' }; // No hagas esto en producción
    
    if (username === user.username && password === user.password) {
      return done(null, user);
    } else {
      return done(null, false, { message: 'Nombre de usuario o contraseña incorrectos' });
    }
  }
));

//SERIALIZACION

passport.serializeUser(function(user, done) {
  done(null, user.username);
});

passport.deserializeUser(function(username, done) {
  // En un caso real, aquí buscarías al usuario en tu base de datos
  const user = { username: 'walrus', password: 'walrus' }; // No hagas esto en producción
  done(null, user);
});

//INTEGRACION CON EXPRESS

app.use(require('express-session')({ secret: 'un secreto muy secreto', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

//CREACION DE RUTA 

//app.post('/login', passport.authenticate('username-password', {
 // successRedirect: '/', // Redirecciona a la ruta protegida si el inicio de sesión es exitoso
//  failureRedirect: '/login', // Redirecciona de nuevo al formulario de inicio de sesión si falla
 // failureFlash: true // Opcional, para mensajes de error
//}));

app.post('/login', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => { 
    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)
    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    res.json(token)
    
    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)
