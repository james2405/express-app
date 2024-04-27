const express = require ('express');
const app = express();
app.use (express.json());
app.use(express.urlencoded({extended: false}));
const jwt = require('jsonwebtoken');
require('dotenv').config();

/*
app.get('/', (req, res) => {
    res.send('hola mundo');




});*/

app.get('/login', (req, res) => {
    res.send(`<html>
              <head>
                    <title>Login</title>
                </head>
                <body>
                <form method= "POST" action= "/auth">
                Nombre de usuario: <input type="text" name= "text"><br>
                Contraseña: <input type= "password" name= "password"> <br>
                <input type= "submit" value="Iniciar sesión" />
                </form>
            </body>
            </html>`
)});


app.post ('/auth', (req, res) => {
    const {username, password} = req.body;

    const user= {username: username};

    const accessToken = generateAccessToken(user);

});

app.listen(3000,() => {
    console.log('sevidor iniciado...')


});

app.get('/api', (req, res) => {
    res.json({
        tuits: [
    
    {
    id: 0,
    text: 'Este es mi primer tuit',
    username: 'vidamrr'
    },
    {
    id: 0,
    text: 'El mejor lenguaje es HTML!',
    username: 'patito_feliz'
    }
    ]
    });



});

function generateAccessToken(user){
    return jwt.sign(user, process.env.SECRET, {expiresIn: '5m'})


    

}