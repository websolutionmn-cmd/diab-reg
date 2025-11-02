// routes/company.js
const express     = require('express');
const multer      = require('multer');
const Application = require('../models/Application');
const { auth }    = require('./auth');

const router = express.Router();
const upload = multer({ dest: 'public/uploads/' });

// Поднеси апликација (треба да се најави)
router.post('/apply', auth('company'), (req, res) => {
  upload.array('docs', 5)(req, res, async err => {
    if (err) return res.status(400).json({ error: err.message });
    try {
      const docs = req.files.map(f => f.filename);
      const app  = new Application({
        company:   req.user.companyId,
        contact:   req.body.contact,
        email:     req.body.email,
        product:   req.body.product,
        documents: docs
      });
      await app.save();
      res.json({ success: true, id: app._id });
    } catch (e) {
      console.error('Грешка при save апликација:', e);
      res.status(400).json({ error: e.message });
    }
  });
});

// Проверка на статус (јавна)
router.get('/status/:id', async (req, res) => {
  try {
    let id = req.params.id.replace(/^"+|"+$/g, '');
    const app = await Application.findById(id).populate('company','name');
    if (!app) return res.json({ found: false });
    res.json({
      found: true,
      application: {
        status:  app.status,
        company: app.company.name
      }
    });
  } catch (e) {
    console.error('Грешка при провера статус:', e);
    res.status(500).json({ error: 'Внатрешна грешка' });
  }
});

module.exports = router;
