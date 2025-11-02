// routes/certificate.js  (or add to routes/admin.js, with require paths adjusted)
const express     = require('express');
const fs          = require('fs');
const path        = require('path');
const PDFDocument = require('pdfkit');
const Application = require('../models/Application');

const router = express.Router();

// GET /api/certificate/:id
router.get('/certificate/:id', async (req, res) => {
  try {
    // strip leading/trailing quotes just in case
    const rawId = req.params.id.replace(/^"+|"+$/g, '');
    // find the application
    const app = await Application.findById(rawId).populate('company','name');
    if (!app) return res.status(404).json({ error: 'Апликација не е пронајдена' });

    // generate a unique cert number if you haven't already
    const certNum = app.cert_number || `DIAB-${Date.now()}`;
    // save it back if this is first issue
    if (!app.cert_number) {
      app.cert_number = certNum;
      app.status      = 'Completed';
      app.updated_at  = new Date();
      await app.save();
    }

    // build PDF
    const pdfPath = path.join(__dirname, '../public/certificates', `${certNum}.pdf`);
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(pdfPath));
    doc.fontSize(25).text('DIAB-REG CERTIFICATE', { align: 'center' });
    doc.moveDown();
    doc.fontSize(16).text(`Certified Company: ${app.company.name}`);
    doc.text(`Product: ${app.product}`);
    doc.text(`Issued to: ${app.contact}`);
    doc.text(`Date: ${new Date().toLocaleDateString()}`);
    doc.text(`Certificate No: ${certNum}`);
    doc.end();

    // when PDF is finished, send it
    doc.on('finish', () => {
      res.download(pdfPath, err => {
        // cleanup after
        if (!err) fs.unlinkSync(pdfPath);
      });
    });

  } catch (e) {
    console.error('Грешка во /api/certificate/:id:', e);
    res.status(500).json({ error: 'Грешка при издавање сертификат' });
  }
});

module.exports = router;
