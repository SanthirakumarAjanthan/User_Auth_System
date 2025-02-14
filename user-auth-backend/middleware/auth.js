const jwt = require('jsonwebtoken');
const db = require('../db');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [user] = await db.execute('SELECT * FROM users WHERE id = ?', [decoded.id]);

    if (user.length === 0) {
      throw new Error('User not found');
    }

    req.user = user[0];
    next();
  } catch (err) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

module.exports = auth;