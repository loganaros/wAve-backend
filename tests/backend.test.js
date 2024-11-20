const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../app');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

jest.mock('pg');
const mockedPool = Pool.prototype;

beforeEach(() => {
  jest.clearAllMocks();
});

afterAll(async () => {
  await mockedPool.end();
});

describe('User Authentication Tests', () => {
  describe('POST /api/register', () => {
    it('should register a new user and return a token', async () => {
      mockedPool.query
        .mockResolvedValueOnce({ rows: [] }) // No existing user
        .mockResolvedValueOnce({ rows: [{ id: 1, username: 'testuser', email: 'test@example.com' }] }); // Inserting new user

      const res = await request(app)
        .post('/api/register')
        .send({ username: 'testuser', email: 'test@example.com', password: 'password123' });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('username', 'testuser');
    });

    it('should return an error if the user already exists', async () => {
      mockedPool.query.mockResolvedValueOnce({ rows: [{ id: 1 }] }); // User already exists

      const res = await request(app)
        .post('/api/register')
        .send({ username: 'testuser', email: 'test@example.com', password: 'password123' });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty('error', 'User already exists');
    });
  });

  describe('POST /api/login', () => {
    it('should log in a user and return a token', async () => {
      const hashedPassword = await bcrypt.hash('password123', 10);
      mockedPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 1,
            username: 'testuser',
            email: 'test@example.com',
            password_hash: hashedPassword,
          },
        ],
      });

      const res = await request(app)
        .post('/api/login')
        .send({ email: 'test@example.com', password: 'password123' });

      expect(res.statusCode).toEqual(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('username', 'testuser');
    });

    it('should return an error for invalid credentials', async () => {
      const hashedPassword = await bcrypt.hash('wrongpassword', 10);
      mockedPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 1,
            password_hash: hashedPassword,
          },
        ],
      });

      const res = await request(app)
        .post('/api/login')
        .send({ email: 'test@example.com', password: 'incorrectpassword' });

      expect(res.statusCode).toEqual(400);
      expect(res.body).toHaveProperty('error', 'Invalid credentials');
    });
  });
});

describe('Post and Comment Tests', () => {
  describe('POST /api/posts', () => {
    it('should create a new post', async () => {
      const token = jwt.sign({ userId: 1 }, process.env.JWT_SECRET, { expiresIn: '1h' });
      mockedPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 1,
            user_id: 1,
            song_id: '123',
            caption: 'Test Caption',
          },
        ],
      });

      const res = await request(app)
        .post('/api/posts')
        .set('Authorization', `Bearer ${token}`)
        .send({ songId: '123', caption: 'Test Caption' });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('caption', 'Test Caption');
    });
  });

  describe('POST /api/posts/:postId/comments', () => {
    it('should add a comment to a post', async () => {
      const token = jwt.sign({ userId: 1 }, process.env.JWT_SECRET, { expiresIn: '1h' });
      mockedPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 1,
            post_id: 1,
            user_id: 1,
            comment: 'Test Comment',
          },
        ],
      });

      const res = await request(app)
        .post('/api/posts/1/comments')
        .set('Authorization', `Bearer ${token}`)
        .send({ comment: 'Test Comment' });

      expect(res.statusCode).toEqual(201);
      expect(res.body).toHaveProperty('comment', 'Test Comment');
    });
  });

  describe('GET /api/posts/:postId/comments', () => {
    it('should retrieve all comments for a post', async () => {
      mockedPool.query.mockResolvedValueOnce({
        rows: [
          {
            id: 1,
            post_id: 1,
            user_id: 1,
            comment: 'Test Comment',
            username: 'testuser',
          },
        ],
      });

      const res = await request(app).get('/api/posts/1/comments');

      expect(res.statusCode).toEqual(200);
      expect(res.body.length).toBeGreaterThan(0);
      expect(res.body[0]).toHaveProperty('comment', 'Test Comment');
    });
  });
});
