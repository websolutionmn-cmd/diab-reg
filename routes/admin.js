// routes/admin.js
const express     = require('express');
const nodemailer  = require('nodemailer');
const Application = require('../models/Application');
// const { auth } = require('./auth');  // Ако сакате да вратите аутх

const router = express.Router();

// SMTP конфигурација за дев (MailHog на localhost:1025)
const transporter = nodemailer.createTransport({
  host: 'localhost',
  port: 1025,
  secure: false,
  tls: { rejectUnauthorized: false }
});

// Листа апликации
router.get('/applications', /* auth('admin'), */ async (req, res) => {
  try {
    const apps = await Application.find()
      .populate('company','name matichen_broj')
      .sort('-applied_at');
    res.json(apps);
  } catch (e) {
    console.error('Грешка при вчитување апликации:', e);
    res.status(500).json({ error: 'Внатрешна грешка' });
  }
});

// Промена статус + (опционално) email
router.patch('/applications/:id/status', /* auth('admin'), */ async (req, res) => {
  try {
    const { status: newStatus, notify } = req.body;
    const app = await Application.findById(req.params.id).populate('company');
    if (!app) return res.status(404).json({ error: 'Не постои апликација' });

    const oldStatus = app.status;
    app.status     = newStatus;
    app.updated_at = new Date();
    await app.save();

    if (notify) {
      try {
        await transporter.sendMail({
          from: '"DIAB-REG"<no-reply@diabreg.mk>',
          to: app.email,
          subject: `Статус апликација ${app._id}`,
          text: `Статусот е сменет од "${oldStatus}" во "${newStatus}".`
        });
      } catch (mailErr) {
        console.error('Грешка при праќање мејл:', mailErr);
      }
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Грешка во PATCH статус:', e);
    res.status(500).json({ error: 'Внатрешна грешка' });
  }
});

module.exports = router;
