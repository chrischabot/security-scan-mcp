// Vulnerable JavaScript application for testing the scanner

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();
app.use(express.json());

// CWE-89: SQL Injection via template literal
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // VULNERABLE: SQL injection
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, results) => {
        res.json(results);
    });
});

// CWE-89: SQL Injection via string concatenation
app.post('/search', (req, res) => {
    const searchTerm = req.body.search;
    // VULNERABLE: SQL injection
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    db.query(query, (err, results) => {
        res.json(results);
    });
});

// CWE-78: Command Injection via exec
app.post('/ping', (req, res) => {
    const host = req.body.host;
    // VULNERABLE: Command injection
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// CWE-79: XSS via innerHTML
app.get('/render', (req, res) => {
    const userContent = req.query.content;
    res.send(`
        <html>
        <body>
            <div id="content"></div>
            <script>
                document.getElementById('content').innerHTML = "${userContent}";
            </script>
        </body>
        </html>
    `);
});

// CWE-79: XSS via document.write
app.get('/legacy', (req, res) => {
    const name = req.query.name;
    res.send(`
        <html>
        <body>
            <script>
                document.write("<h1>Hello, ${name}!</h1>");
            </script>
        </body>
        </html>
    `);
});

// CWE-22: Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    // VULNERABLE: Path traversal
    fs.readFileSync('/uploads/' + filename, (err, data) => {
        res.send(data);
    });
});

// CWE-798: Hardcoded credentials
const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'SuperSecretPassword123!',  // VULNERABLE: Hardcoded password
    database: 'myapp'
};

const jwt_secret = 'my-super-secret-jwt-key-12345';  // VULNERABLE: Hardcoded JWT secret

// CWE-94: Code Injection via eval
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    // VULNERABLE: Code injection
    const result = eval(expression);
    res.json({ result });
});

// CWE-94: Code Injection via Function constructor
app.post('/run', (req, res) => {
    const code = req.body.code;
    // VULNERABLE: Code injection
    const fn = new Function('data', code);
    const result = fn({ user: 'test' });
    res.json({ result });
});

// CWE-918: SSRF via fetch
app.post('/proxy', async (req, res) => {
    const url = req.body.url;
    // VULNERABLE: SSRF
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

app.listen(3000);
