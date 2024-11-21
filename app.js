require('dotenv').config(); // Load environment variables
const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { Pool } = require('pg');
const authenticateToken = require('./middleware/authenticateToken')
const app = express();
const PORT = process.env.PORT || 5000;
const ORIGIN = 'https://wave-frontend-liart.vercel.app'
// const ORIGIN = 'http://localhost:3000'

// Initialize database
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

// Middleware
app.use(cors({
    origin: ORIGIN,
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
    credentials: true,
}));
app.use(express.json());

// Get Spofity access token
async function getSpotifyAccessToken() {
    const clientId = process.env.SPOTIFY_CLIENT_ID;
    const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const response = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: {
            'Authorization': `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
    });

    const data = await response.json();
    return data.access_token;
}

// Route to get Spotify access token
app.get('/api/spotify-token', async (req, res) => {
    const clientId = process.env.SPOTIFY_CLIENT_ID;
    const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;
    
    const tokenUrl = 'https://accounts.spotify.com/api/token';
    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    
    try {
      const response = await axios.post(
        tokenUrl,
        'grant_type=client_credentials',
        {
          headers: {
            Authorization: `Basic ${authString}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );
      
      res.json({ accessToken: response.data.access_token });
    } catch (error) {
      console.error('Error getting Spotify token:', error);
      res.status(500).json({ error: 'Failed to obtain Spotify token' });
    }
  });

// USER

// Login route
app.post('/api/login', 
    [
      // validation logic
      body('email').isEmail().withMessage('Please provide a valid email'),
      body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
      // Validate request body
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
  
      const { email, password } = req.body;
  
      try {
        // Check if the user exists
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }
  
        const user = result.rows[0];
  
        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
          return res.status(400).json({ error: 'Invalid credentials' });
        }
  
        // Generate token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
        // Send back user information and token
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
      } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  );
  
// Registration route
app.post('/api/register',
    // Input validation
    [
        body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters'),
        body('email').isEmail().withMessage('Enter a valid email'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            // Check if user already exists
            const existingUser = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
            if (existingUser.rows.length > 0) {
                return res.status(400).json({ error: 'User already exists' });
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Insert user into database
            const result = await pool.query(
                'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
                [username, email, hashedPassword]
            );

            const user = result.rows[0];

            // Generate token
            const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.status(201).json({ token, user });
        } catch (error) {
            console.error('Error registering user:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// COMMENTS

// Add a Comment to a Post
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
    const { postId } = req.params;
    const { comment } = req.body;

    if (!comment || comment.trim() === "") {
        return res.status(400).json({ error: 'Comment cannot be empty' });
    }

    try {
        // Insert the new comment into the comments table
        const result = await pool.query(
            'INSERT INTO comments (post_id, user_id, comment, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
            [postId, req.user.userId, comment]
        );

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Retrieve all comments for a Post
app.get('/api/posts/:postId/comments', async (req, res) => {
    const { postId } = req.params;

    try {
        // Fetch all comments for a specific post, including the username of the commenter
        const result = await pool.query(
            `SELECT comments.*, users.username 
             FROM comments 
             JOIN users ON comments.user_id = users.id 
             WHERE comments.post_id = $1 
             ORDER BY comments.created_at ASC`,
            [postId]
        );

        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching comments:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Delete a comment
app.delete('/api/comments/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        // Check if the comment exists and if the logged-in user is the owner
        const commentResult = await pool.query('SELECT * FROM comments WHERE id = $1', [id]);

        if (commentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Comment not found' });
        }

        const comment = commentResult.rows[0];
        if (comment.user_id !== req.user.userId) {
            return res.status(403).json({ error: 'You are not authorized to delete this comment' });
        }

        // Delete the comment
        await pool.query('DELETE FROM comments WHERE id = $1', [id]);

        res.json({ message: 'Comment deleted successfully' });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// SONGS

// Endpoint to fetch song data from Spotify API
app.get('/api/song/:songId', async (req, res) => {
    try {
        const { songId } = req.params;
        const token = await getSpotifyAccessToken();

        const response = await fetch(`https://api.spotify.com/v1/tracks/${songId}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            return res.status(response.status).json({ error: 'Failed to fetch song data from Spotify' });
        }

        const songData = await response.json();
        res.json(songData);
    } catch (error) {
        console.error("Error fetching song data:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// POSTS

// Endpoint to create a new post
app.post('/api/posts', authenticateToken, async (req, res) => {
    const { songId, caption } = req.body;
  
    try {
      // Insert the new post into the database with the correct userId
      const result = await pool.query(
        'INSERT INTO posts (user_id, song_id, caption) VALUES ($1, $2, $3) RETURNING *',
        [req.user.userId, songId, caption]
      );
  
      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error('Error creating post:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });

// Endpoint to retrieve all posts
app.get('/api/posts', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT posts.*, users.username 
             FROM posts 
             JOIN users ON posts.user_id = users.id 
             ORDER BY posts.created_at DESC`
          );
        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching posts:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Endpoint to retrieve a specific post by ID
app.get('/api/posts/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query(
            `SELECT posts.*, users.username 
             FROM posts 
             JOIN users ON posts.user_id = users.id 
             WHERE posts.id = $1`, [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error("Error fetching post:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Endpoint to delete a post
app.delete('/api/posts/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const result = await pool.query('DELETE FROM posts WHERE id = $1 RETURNING *', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.json({ message: 'Post deleted successfully', post: result.rows[0] });
    } catch (error) {
        console.error("Error deleting post:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;