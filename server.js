const express = require('express');
const { Pool } = require('pg');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

const cors = require('cors');
app.use(cors());

app.use(express.json());

app.use(express.static('public'));


// ----------Authentication-----------

// User Registration
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await argon2.hash(password);

    try {
        const result = await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *', [username, hashedPassword, role]);
        res.status(201).send({ user: result.rows[0] });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {

        const user = (await pool.query('SELECT * FROM users WHERE username = $1', [username])).rows[0];
        if (user && await argon2.verify(user.password, password)) {
            const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.send({ token, role: user.role }); 
        } else {
            res.status(401).send('Username or password is incorrect');
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
});


// -----------Authorization Middleware-------

const authorize = roles => (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).send('Token is invalid or expired');
        if (!roles.includes(decoded.role)) return res.status(401).send('Unauthorized');
        req.user = decoded; // Add user payload to request
        next();
    });
};

// -------Routes--------
app.get('/some-admin-route', authorize(['admin']), (req, res) => {
    res.send('Admin content');
});

app.get('/some-student-route', authorize(['student']), (req, res) => {
    res.send('Student content');
});

// Fetch Student Profile
app.get('/profile', authorize(['student']), async (req, res) => {
    const userId = req.user.id; // Assuming the user's ID is included in the JWT payload

    try {
        const result = await pool.query('SELECT username, role FROM users WHERE id = $1', [userId]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        res.status(500).send(error.message);
    }
});


// Update Student Profile
app.put('/profile', authorize(['student']), async (req, res) => {
    const userId = req.user.id;
    const { username, password } = req.body;
    const hashedPassword = await argon2.hash(password);

    try {
        await pool.query('UPDATE users SET username = $1, password = $2 WHERE id = $3', [username, hashedPassword, userId]);
        res.send('Profile updated successfully.');
    } catch (error) {
        res.status(500).send(error.message);
    }
});


// ---------Admin panel FETCH USER -------
app.get('/users', authorize(['admin']), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role FROM users');
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// ------- ADD USER ---------
app.post('/users', authorize(['admin']), async (req, res) => {
    const { username, password, role } = req.body;
    // Hash the password before storing it in the database
    const hashedPassword = await argon2.hash(password);

    try {
        // Insert the new user into the database
        const newUser = await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *',
            [username, hashedPassword, role]
        );

        // Respond with the created user (excluding the password for security)
        res.status(201).json({ user: { id: newUser.rows[0].id, username: newUser.rows[0].username, role: newUser.rows[0].role } });
    } catch (error) {
        // Handle potential errors, such as a username that already exists
        res.status(500).json({ error: error.message });
    }
});

// --------UDATE USER ROLE ADMIN ---------
app.put('/user/:id/role', authorize(['admin']), async (req, res) => {
    const { id } = req.params;
    const { role } = req.body;

    try {
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);
        res.send('User role updated successfully.');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// --------DELETE USER -------
app.delete('/user/:id', authorize(['admin']), async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query('DELETE FROM users WHERE id = $1', [id]);
        res.send('User deleted successfully.');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Snippet Creation
app.post('/snippets', authorize(['student', 'admin']), async (req, res) => {
    const { content } = req.body;
    const userId = req.user.id;

    try {
        const result = await pool.query(
            'INSERT INTO snippets (author_id, content) VALUES ($1, $2) RETURNING *',
            [userId, content]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Fetching Snippets
app.get('/snippets', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM snippets ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Updating Snippets
app.put('/snippets/:id', authorize(['student', 'admin']), async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const userId = req.user.id;

    try {
        const snippet = (await pool.query('SELECT * FROM snippets WHERE id = $1', [id])).rows[0];

        if (!snippet) {
            return res.status(404).send('Snippet not found');
        }

        if (snippet.author_id !== userId && req.user.role !== 'admin') {
            return res.status(403).send('Unauthorized');
        }

        await pool.query(
            'UPDATE snippets SET content = $1, updated_at = NOW() WHERE id = $2',
            [content, id]
        );
        res.send('Snippet updated successfully.');
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Deleting Snippets
app.delete('/snippets/:id', authorize(['student', 'admin']), async (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;

    try {
        const snippet = (await pool.query('SELECT * FROM snippets WHERE id = $1', [id])).rows[0];

        if (!snippet) {
            return res.status(404).send('Snippet not found');
        }

        if (snippet.author_id !== userId && req.user.role !== 'admin') {
            return res.status(403).send('Unauthorized');
        }

        await pool.query('DELETE FROM snippets WHERE id = $1', [id]);
        res.send('Snippet deleted successfully.');
    } catch (error) {
        res.status(500).send(error.message);
    }
});


app.listen(port, () => { 
    console.log(`Server is running on http://localhost:${port}`);
  }); 
