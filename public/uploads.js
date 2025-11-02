const multer = require('multer');
const upload = multer({ dest: path.join(__dirname, '..', 'uploads') });
// Рутa за пријава со документи
app.post('/api/apply', auth('company'), upload.array('docs', 5), async (req, res) => {
  // req.files -> низата прикачени фајлови
  const docs = req.files.map(f => f.filename);
  // Insert во applications табела со documents = JSON.stringify(docs)
  res.json({ success: true, id: newAppId });

});