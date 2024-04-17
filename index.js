const express = require('express');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;


const morgan = require('morgan');
const app = express();
const port = 3000;

app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send('Hola Mundo');
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

app.post('/login', passport.authenticate('username-password', {
  successRedirect: '/', // Redirecciona a la ruta protegida si el inicio de sesión es exitoso
  failureRedirect: '/login', // Redirecciona de nuevo al formulario de inicio de sesión si falla
  failureFlash: true // Opcional, para mensajes de error
}));

