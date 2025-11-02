const express     = require('express');
const fs          = require('fs');
const path        = require('path');
const PDFDocument = require('pdfkit');
const Application = require('../models/Application');

const router = express.Router();

// Generate or retrieve certificate PDF
async function generateCertificate(req, res) {
  try {
    const rawId = req.params.id.replace(/^"+|"+$/g, '');
    const app = await Application.findById(rawId).populate('company', 'name');
    if (!app) return res.status(404).json({ error: 'Апликацијата не постои' });

    const certNum = app.cert_number || `DIAB-${Date.now()}`;
    if (!app.cert_number) {
      app.cert_number = certNum;
      app.status      = 'Completed';
      app.updated_at  = new Date();
      await app.save();
    }

    // Ensure correct path to certificates folder
    const pdfPath = path.join(__dirname, '..', 'public', 'certificates', `${certNum}.pdf`);
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(pdfPath));

    // Certificate content
    doc.fontSize(25).text('DIAB-REG CERTIFICATE', { align: 'center' });
    doc.moveDown();
    doc.fontSize(16).text(`Certified Company: ${app.company.name}`);
    doc.text(`Product: ${app.product}`);
    doc.text(`Issued to: ${app.contact}`);
    doc.text(`Date: ${new Date().toLocaleDateString()}`);
    doc.text(`Certificate No: ${certNum}`);
    doc.end();

    doc.on('finish', () => {
      res.download(pdfPath, err => {
        if (!err) fs.unlinkSync(pdfPath);
      });
    });

  } catch (e) {
    console.error('Грешка во /api/certificate/:id:', e);
    res.status(500).json({ error: 'Грешка при издавање сертификат' });
  }
}

// Admin and public aliases
router.get('/certificate/:id', generateCertificate);
router.get('/pdf/:id', generateCertificate);
router.get('/view/:id', generateCertificate);

module.exports = router;
module.exports.handler = generateCertificate;
