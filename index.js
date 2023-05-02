
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = (60 * 60 * 1000); //expires after 1 hour (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set ('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        var html = `<button onclick="window.location.href='/signup'">Sign Up</button>
        <br><button onclick="window.location.href='/login'">Log in</button>`;
        res.render("landingPage");
    } else {
        var html = `
        <h1>Hello, ${req.session.name}!</h1>
        <button onclick="window.location.href='/members'"> Go to Members Area </button>
        <br><button onclick="window.location.href='/logout'"> Logout </button>
        `;
        res.send(html);
    }
});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
    <input name='name' type ='text' placeholder='name'>
    <br><input name='email' type='email' placeholder='email'>
    <br><input name='password' type='password' placeholder='password'>
    <br><button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });
    
    if (validationResult.error != null) {
        let errorMsg = validationResult.error.message;
        console.log(validationResult.error);
        var html = `
        ${errorMsg}.
        <br> <a href="/signup">Try Again</a>`;
        res.send(html);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });
    console.log("Inserted user");
    req.session.name = name;
    req.session.authenticated = true;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1, _id: 1 }).toArray();

    if (result.length != 1) {
        console.log("user not found");
        var html = `Invalid email/password combination.
        <br><a href='/login'>Try Again </a>`
        res.send(html);
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/');
        return;
    }
    else {
        var html = `Invalid email/password combination.
        <br><a href='/login'>Try Again </a>`
        res.send(html);
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect("/login");
    }
    var imageID = Math.floor(Math.random() * 3);
    var imageRef;
    if (imageID === 0) {
        imageRef = 'catJAM.gif';
    } else if (imageID === 1) {
        imageRef = 'computerdog.gif';
    } else {
        imageRef = 'cheese.gif';
    }
    console.log(imageID);
    var html = `
    <h1> Hello, ${req.session.name}</h1>
    <br><img src='/${imageRef}' style='width:250px;'>
    <br><button onclick='window.location.href="/logout"'>Logout</button>`;
    res.send(html);
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');

});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 