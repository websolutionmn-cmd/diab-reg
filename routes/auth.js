// routes/auth.js
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const Company = require('../models/Company');

const router = express.Router();
const SECRET = 'мојтајнаклуч123';

// Middleware за аутх
function auth(requiredRole) {
  return (req, res, next) => {
    try {
      const header = req.headers.authorization || '';
      const token  = header.split(' ')[1];
      if (!token) throw new Error('Нема токен');
      const payload = jwt.verify(token, SECRET);
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

// Регистрација
router.post('/register', async (req, res) => {
  try {
    const { matichen_broj, name, email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const comp = new Company({ matichen_broj, name, email, password_hash: hash });
    await comp.save();
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Логин
router.post('/login', async (req, res) => {
  try {
    const { matichen_broj, password } = req.body;
    const comp = await Company.findOne({ matichen_broj });
    if (!comp) throw new Error('Непознат матичен број');
    const valid = await bcrypt.compare(password, comp.password_hash);
    if (!valid) throw new Error('Грешна лозинка');
    const token = jwt.sign({ companyId: comp._id, role: comp.role }, SECRET, { expiresIn: '8h' });
    res.json({ token });
  } catch (e) {
    res.status(401).json({ error: e.message });
  }
});

module.exports = { router, auth };
