const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const bodyParser = require("body-parser");

const app = express();
const db = new sqlite3.Database("./brogang.db");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static("public"));

app.use(session({
    secret: "brogang-secret",
    resave: false,
    saveUninitialized: true
}));

// Create tables
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'normal'
)
`);

// Register
app.post("/register", async (req, res) => {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hashed],
        (err) => {
            if (err) return res.send("User exists");
            res.redirect("/login.html");
        }
    );
});

// Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (!user) return res.send("User not found");

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.send("Wrong password");

        req.session.user = user;
        res.redirect("/dashboard");
    });
});

// Dashboard
app.get("/dashboard", (req, res) => {
    if (!req.session.user) return res.redirect("/login.html");

    res.send(`
        <h1>Welcome ${req.session.user.email}</h1>
        <a href="/logout">Logout</a>
    `);
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login.html");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
