// server.js

const express     = require('express');
const session     = require('express-session');
const bcrypt      = require('bcryptjs');
const morgan      = require('morgan');
const fs          = require('fs');
const bodyParser  = require('body-parser');
const mongoose    = require('mongoose');
const jwt         = require('jsonwebtoken');
const multer      = require('multer');
const PDFDocument = require('pdfkit');
const bwipjs      = require('bwip-js');
const path        = require('path');
const FONT_PATH = path.join(__dirname, 'fonts', 'DejaVuSansMono.ttf');
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_env_secret';
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const CERT_DIR   = path.join(__dirname, 'public', 'certificates');
const PORT       = process.env.PORT || 5050;

// Ensure directories exist
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(CERT_DIR))   fs.mkdirSync(CERT_DIR,   { recursive: true });

// File upload config
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename:    (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

const app = express();

// Connect to MongoDB
// Во врвот на server.js
mongoose.connect(
  'mongodb://127.0.0.1:27017/diab_reg',
  { useNewUrlParser:true, useUnifiedTopology:true }
)
.then(() => console.log('✅ MongoDB connected'))
.catch(e => console.error('❌ MongoDB error:', e));



// Define schemas and models
const companySchema = new mongoose.Schema({
  matichen_broj: { type: String, unique: true },
  name:          String,
  email:         String,
  passwordHash:  String
});
const statusHistorySchema = new mongoose.Schema({
  status:    String,
  message:   String,
  user:      String,
  timestamp: { type: Date, default: Date.now }
});
const applicationSchema = new mongoose.Schema({
  company:       { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  contact:       String,
  email:         String,
  product:       String,
  docs:          [String],
  status:        { type: String, default: 'Pending' },
  cert_number:   String,
  completedBy:   String,
  statusHistory: [statusHistorySchema]     // ← ново
}, { timestamps: true });

const logSchema = new mongoose.Schema({
  user:      String,
  action:    String,
  itemId:    String,
  timestamp: { type: Date, default: Date.now }
});

const Company     = mongoose.model('Company', companySchema);
const Application = mongoose.model('Application', applicationSchema);
const Log         = mongoose.model('Log', logSchema);

// Middleware setup
app.use(morgan('combined', { stream: fs.createWriteStream('access.log', { flags:'a' }) }));
app.use(session({ secret:'diabreg-session-key', resave:false, saveUninitialized:false }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:true }));
app.use('/uploads',     express.static(UPLOAD_DIR));
app.use('/certificates', express.static(CERT_DIR));
app.use(express.static(path.join(__dirname,'public')));
// Serve logo and documents statically
app.use('/logo.jpg',    express.static(path.join(__dirname,'public','logo.jpg')));
app.use('/documents',   express.static(path.join(__dirname,'public','documents')));

// Audit logging
app.use(async (req, res, next) => {
  if (req.session?.user) {
    await Log.create({
      user:     req.session.user.username,
      action:   `${req.method} ${req.originalUrl}`,
      itemId:   req.params.id || ''
    });
  }
  next();
});
// PATCH /api/admin/applications/:id/status
app.patch('/api/admin/applications/:id/status', requireAdmin, async (req, res) => {
  const { status, message } = req.body;
  if (!message || message.length < 180) {
    return res.status(400).json({ error: 'Пораката мора да има минимум 180 карактери.' });
  }
  try {
    const appDoc = await Application.findById(req.params.id);
    if (!appDoc) return res.status(404).json({ error:'Не постои апликација' });

    // Додај во статусната историја
    appDoc.statusHistory.push({
      status,
      message,
      user: req.session.user.username
    });

    // Промени го статусот
    appDoc.status = status;
    await appDoc.save();
    res.json({ success:true });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error:'Внатрешна грешка при менување статус' });
  }
});

// Authentication middleware
function requireAdmin(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}
function authGuard(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error:'Missing token' });
  }
  try {
    req.companyId = jwt.verify(auth.slice(7), JWT_SECRET).id;
    next();
  } catch {
    return res.status(401).json({ error:'Invalid token' });
  }
}

// User login/logout routes
app.get('/login', (req, res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = require('./config/users');
  const user  = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).send('Невалиден корисник/лозинка');
  }
  req.session.user = { username };
  res.redirect('/admin');
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// Certificate generation and download
const router = express.Router();

async function generateCertificate(req, res) {
  try {
    let param = req.params.id.replace(/^"+|"+$/g, '');
    let query = mongoose.Types.ObjectId.isValid(param)
              ? { _id: param }
              : { cert_number: param };

    const appDoc = await Application.findOne(query).populate('company','name');
    if (!appDoc) return res.status(404).json({ error:'Не постои апликација/сертификат' });

    // Assign certificate number and completedBy if first time
    const certNum = appDoc.cert_number || `DIAB-${Date.now()}`;
    if (!appDoc.cert_number) {
      appDoc.cert_number = certNum;
      appDoc.status      = 'Completed';
      appDoc.completedBy = req.session.user.username;
      await appDoc.save();
    }

    // Compute validity date (1 year from today)
    const issueDate = new Date();
    const validTo   = new Date(issueDate);
    validTo.setFullYear(validTo.getFullYear()+1);

    const pdfPath = path.join(CERT_DIR, `${certNum}.pdf`);
const doc = new PDFDocument();

// Регистрирање на фонтот
doc.registerFont('DejaVuMono', FONT_PATH);

// Селектирање на тој фонт за текст
doc.font('DejaVuMono');

// Сега можеш да печатиш кириличен текст:
 doc.moveDown(); doc.moveDown();doc.moveDown();doc.moveDown();doc.moveDown(); doc.moveDown(); doc.moveDown();
doc.fontSize(25).text(`Стандарнизирана потврда за компанија: ${appDoc.company.name}`, { align: 'center' });
    const stream  = fs.createWriteStream(pdfPath);
    doc.pipe(stream);

    // PDF content
  
    doc.moveDown();

    doc.text(`Продукт: ${appDoc.product}`);
    doc.text(`Лице за контакт: ${appDoc.contact}`);
    doc.text(`Датум: ${issueDate.toLocaleDateString()}`);
    doc.text(`Важи до: ${validTo.toLocaleDateString()}`);
    doc.text(`Потврда број: ${certNum}`);
  doc.moveDown();
  doc.fontSize(12)
     .text(`Потпишан од: ${req.session.user.username}`)                   // кој потпишал
     .text(`Креиран на: ${issueDate.toLocaleString()}`)                  // timestamp
     .text(`Важност до: ${validTo.toLocaleDateString()}`);               // валиден до
    // Generate QR code embedding confirmation URL
    // Хардкодирана адреса за QR-код, наместо localhost
 const BASE_URL = 'http://10.10.40.107:3000';
const link     = `${BASE_URL}/confirm/${certNum}`;
    const qrPng    = await bwipjs.toBuffer({
      bcid: 'qrcode', text: link, scale: 5, includetext: false
    });
    doc.image(qrPng, doc.page.width - 150, 50, { width: 100 });
if (appDoc.statusHistory.length) {
  doc.addPage();
  doc.fontSize(18).text('Историја на статуси', { underline:true });
  doc.moveDown();
  appDoc.statusHistory.forEach(h => {
    doc
      .fontSize(12)
      .text(`${h.timestamp.toLocaleString()} — ${h.user}`)
      .moveDown(0.2)
      .text(`Статус: ${h.status}`)
      .moveDown(0.2)
      .text(`Порака: ${h.message}`, { indent: 20 })
      .moveDown();
  });
}

doc.end();
    stream.on('finish', () => {
      res.download(pdfPath, err => { if (!err) fs.unlinkSync(pdfPath); });
    });

  } catch (e) {
    console.error('Грешка при генерирање на сертификат:', e);
    res.status(500).json({ error:'Грешка при издавање сертификат' });
  }
}

// Certificate routes
router.get('/certificate/:id', generateCertificate);
router.get('/pdf/:id',         generateCertificate);
router.get('/view/:id',        generateCertificate);
router.get('/scan/:certNum', async (req, res) => {
  try {
    const appDoc = await Application.findOne({ cert_number: req.params.certNum });
    if (!appDoc) return res.status(404).json({ error:'Сертификатот не постои' });
    res.json({ status:'Confirmed', assignedBy:appDoc.completedBy||'Unknown' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'Внатрешна грешка' });
  }
});

// Mount certificate routes
app.use('/api/certificate', requireAdmin, router);
app.get('/api/certificate/public/pdf/:id', authGuard, generateCertificate);

// Human-readable confirmation page
app.get('/confirm/:certNum', async (req, res) => {
  const certNum = req.params.certNum;
  const appDoc  = await Application.findOne({ cert_number: certNum })
                                   .populate('company','name');
  if (!appDoc) {
    return res.status(404).send('<h1>404: Сертификат не постои</h1>');
  }

  // Пресметај ги датумите исто како во generateCertificate
  const issuedAt = new Date(appDoc.updatedAt || appDoc.createdAt);
  const validTo  = new Date(issuedAt);
  validTo.setFullYear(validTo.getFullYear()+1);

  res.send(`
    <!DOCTYPE html>
    <html lang="mk">
    <head>
      <meta charset="UTF-8">
      <title>Стандарнизирана Потврда</title>
      <style>
        body { font-family: Arial, sans-serif; margin:20px; text-align:center; }
        .info { margin:10px 0; }
        .label { font-weight:bold; }
      </style>
    </head>
    <body>
      <h1>Сертификат ${appDoc.cert_number}</h1>
      <p class="info"><span class="label">Компанија:</span> ${appDoc.company.name}</p>
      <p class="info"><span class="label">Продукт:</span> ${appDoc.product}</p><BR><BR>
      <p class="info" style="color:green; font-weight:bold;">ОДОБРЕНО</p><BR><BR>
      <p class="info"><span class="label">Потпишано од:</span> ${appDoc.completedBy}</p>
      <p class="info"><span class="label">Потпишано на:</span> ${issuedAt.toLocaleString()}</p>
      <p class="info"><span class="label">Важност до:</span> ${validTo.toLocaleDateString()}</p>
    <BR><BR>Поддржано од <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTbBMbxYIyarbBG_HV1F3IABrK05X1i3zJHUA&s" alt="Logo" style="margin-top:20px; max-width:200px;">
	 <BR><BR> <BR>Потврдено од <img src="/logo.jpg" alt="Logo" style="margin-top:20px; max-width:200px;">
    </body>
    </html>
  `);
});
const translations = {
      mk: {
        "lang.select.label": "Глуha:",
        "lang.mk": "Македонски",
        "lang.en": "English",
        "lang.sq": "Shqip",
        "header.title": "Систем за сертификација и регулација",
        "header.subtitle": "на производи наменети за сите лица со дијабетес",
        "btn.myApps": "Мои апликации",
        "card.certified.title": "Сертифицирани",
        "card.certified.subtitle": "од DIAB-REG",
        "card.login.title": "Најави се",
        "card.login.subtitle": "Имате профил?",
        "card.register.title": "Регистрирај се",
        "card.register.subtitle": "Нов корисник?",
        "card.docs.title": "Документи",
        "card.docs.subtitle": "и регулативи",
        "card.price.title": "Ценовник",
        "gdpr.title": "DIAB-REG собира, обработува и чува само податоци кои се однесуваат на правни субјекти:",
        "gdpr.item.company": "Назив на компанија",
        "gdpr.item.embs": "ЕМБС",
        "gdpr.item.product": "Назив на производ",
        "gdpr.item.category": "Категорија",
        "gdpr.item.date": "Датум",
        "gdpr.footer": "Без лични податоци. Нема колачиња за следење.",
        "section.certified.title": "Сертифицирани барања",
        "filter.id": "ID:",
        "filter.date": "Created At:",
        "filter.company": "Company:",
        "filter.product": "Product:",
        "filter.status": "Status:",
        "filter.id.placeholder": "Filter по ID",
        "filter.date.placeholder": "Filter по Датум",
        "filter.company.placeholder": "Filter по Компанија",
        "filter.product.placeholder": "Filter по Продукт",
        "cert.table.id": "ID",
        "cert.table.createdAt": "Created At",
        "cert.table.company": "Company",
        "cert.table.product": "Product",
        "cert.table.contact": "Contact",
        "cert.table.email": "Email",
        "cert.table.status": "Status",
        "cert.table.certNo": "Cert. No.",
        "login.title": "Најава",
        "login.label.id": "Матичен број (ЕМБС)",
        "login.placeholder.id": "Внесете го матичен број",
        "login.label.password": "Лозинка",
        "login.placeholder.password": "Внесете ја лозинката",
        "btn.submit.login": "Најави се",
        "register.title": "Регистрација",
        "register.label.id": "Матичен број (ЕМБС)",
        "register.label.company": "Име на компанија",
        "register.label.email": "Е-пошта",
        "register.label.password": "Лозинка",
        "btn.submit.register": "Регистрирај се",
        "btn.back": "Назад",
        "btn.logout": "Одјави се",
        "afterlogin.welcome": "Добредојдовте!",
        "afterlogin.info": "Можете да поднесувате апликации и да ги проверувате сертификатите.",
        "apply.title": "Поднеси нова апликација",
        "apply.label.contact": "Контакт лице",
        "apply.label.email": "Контакт е-пошта",
        "apply.label.category": "Категорија",
        "apply.select.category.placeholder": "– Избери –",
        "apply.label.product": "Име на продукт",
        "apply.label.docs": "Прикачете документи",
        "btn.submit.apply": "Поднеси апликација",
        "status.title": "Проверка статус",
        "status.input.placeholder": "Внесете ID на апликација",
        "btn.check.status": "Провери",
        "statusResult.notFound": "Не пронајдено.",
        "myapps.title": "Мои апликации",
        "myapps.table.id": "ID",
        "myapps.table.date": "Датум",
        "myapps.table.product": "Продукт",
        "myapps.table.status": "Статус",
        "myapps.table.certNo": "Cert No.",
        "myapps.table.view": "Преглед",
        "footer.text": "© 2025 DIAB-REG Систем за сертификација. Сите права се задржани."
      },
      en: {
        "lang.select.label": "Language:",
        "lang.mk": "Macedonian",
        "lang.en": "English",
        "lang.sq": "Albanian",
        "header.title": "Certification & Regulation System",
        "header.subtitle": "for products intended for all people with diabetes",
        "btn.myApps": "My Applications",
        "card.certified.title": "Certified",
        "card.certified.subtitle": "by DIAB-REG",
        "card.login.title": "Log In",
        "card.login.subtitle": "Have an account?",
        "card.register.title": "Register",
        "card.register.subtitle": "New user?",
        "card.docs.title": "Documents",
        "card.docs.subtitle": "and regulations",
        "card.price.title": "Pricing",
        "gdpr.title": "DIAB-REG collects, processes, and stores only data related to legal entities:",
        "gdpr.item.company": "Company Name",
        "gdpr.item.embs": "EMBS",
        "gdpr.item.product": "Product Name",
        "gdpr.item.category": "Category",
        "gdpr.item.date": "Date",
        "gdpr.footer": "No personal data. No tracking cookies.",
        "section.certified.title": "Certified Applications",
        "filter.id": "ID:",
        "filter.date": "Created At:",
        "filter.company": "Company:",
        "filter.product": "Product:",
        "filter.status": "Status:",
        "filter.id.placeholder": "Filter by ID",
        "filter.date.placeholder": "Filter by Date",
        "filter.company.placeholder": "Filter by Company",
        "filter.product.placeholder": "Filter by Product",
        "cert.table.id": "ID",
        "cert.table.createdAt": "Created At",
        "cert.table.company": "Company",
        "cert.table.product": "Product",
        "cert.table.contact": "Contact",
        "cert.table.email": "Email",
        "cert.table.status": "Status",
        "cert.table.certNo": "Cert. No.",
        "login.title": "Login",
        "login.label.id": "National ID (EMBS)",
        "login.placeholder.id": "Enter your ID",
        "login.label.password": "Password",
        "login.placeholder.password": "Enter your password",
        "btn.submit.login": "Log In",
        "register.title": "Registration",
        "register.label.id": "National ID (EMBS)",
        "register.label.company": "Company Name",
        "register.label.email": "Email",
        "register.label.password": "Password",
        "btn.submit.register": "Register",
        "btn.back": "Back",
        "btn.logout": "Log Out",
        "afterlogin.welcome": "Welcome!",
        "afterlogin.info": "You can submit applications and check certificates.",
        "apply.title": "Submit New Application",
        "apply.label.contact": "Contact Person",
        "apply.label.email": "Contact Email",
        "apply.label.category": "Category",
        "apply.select.category.placeholder": "– Select –",
        "apply.label.product": "Product Name",
        "apply.label.docs": "Upload Documents",
        "btn.submit.apply": "Submit Application",
        "status.title": "Check Status",
        "status.input.placeholder": "Enter application ID",
        "btn.check.status": "Check",
        "statusResult.notFound": "Not found.",
        "myapps.title": "My Applications",
        "myapps.table.id": "ID",
        "myapps.table.date": "Date",
        "myapps.table.product": "Product",
        "myapps.table.status": "Status",
        "myapps.table.certNo": "Cert No.",
        "myapps.table.view": "View",
        "footer.text": "© 2025 DIAB-REG Certification System. All rights reserved."
      },
      sq: {
        "lang.select.label": "Gjuha:",
        "lang.mk": "Maqedonisht",
        "lang.en": "Anglisht",
        "lang.sq": "Shqip",
        "header.title": "Sistemi i Certifikimit dhe Rregullimit",
        "header.subtitle": "për produktet e destinuara për të gjithë personat me diabet",
        "btn.myApps": "Aplikimet e Mia",
        "card.certified.title": "Certifikuar",
        "card.certified.subtitle": "nga DIAB-REG",
        "card.login.title": "Hyr",
        "card.login.subtitle": "Keni llogari?",
        "card.register.title": "Regjistrohu",
        "card.register.subtitle": "Përdorues i ri?",
        "card.docs.title": "Dokumente",
        "card.docs.subtitle": "dhe rregullore",
        "card.price.title": "Çmimet",
        "gdpr.title": "DIAB-REG mbledh, përpunon dhe ruan vetëm të dhëna që lidhen me subjekte juridike:",
        "gdpr.item.company": "Emri i kompanisë",
        "gdpr.item.embs": "EMBS",
        "gdpr.item.product": "Emri i produktit",
        "gdpr.item.category": "Kategoria",
        "gdpr.item.date": "Data",
        "gdpr.footer": "Pa të dhëna personale. Pa cookies për gjurmim.",
        "section.certified.title": "Aplikime Certifikuara",
        "filter.id": "ID:",
        "filter.date": "Krijuar më:",
        "filter.company": "Kompania:",
        "filter.product": "Produkti:",
        "filter.status": "Statusi:",
        "filter.id.placeholder": "Filtro sipas ID",
        "filter.date.placeholder": "Filtro sipas Datës",
        "filter.company.placeholder": "Filtro sipas Kompanisë",
        "filter.product.placeholder": "Filtro sipas Produktit",
        "cert.table.id": "ID",
        "cert.table.createdAt": "Krijuar më",
        "cert.table.company": "Kompania",
        "cert.table.product": "Produkti",
        "cert.table.contact": "Kontakti",
        "cert.table.email": "Email",
        "cert.table.status": "Statusi",
        "cert.table.certNo": "Nr. Cert.",
        "login.title": "Hyrje",
        "login.label.id": "Numri i Identifikimit Kombëtar (EMBS)",
        "login.placeholder.id": "Shkruani ID tuaj",
        "login.label.password": "Fjalëkalimi",
        "login.placeholder.password": "Shkruani fjalëkalimin tuaj",
        "btn.submit.login": "Hyr",
        "register.title": "Regjistrimi",
        "register.label.id": "Numri i Identifikimit Kombëtar (EMBS)",
        "register.label.company": "Emri i kompanisë",
        "register.label.email": "Email",
        "register.label.password": "Fjalëkalimi",
        "btn.submit.register": "Regjistrohu",
        "btn.back": "Kthehu",
        "btn.logout": "Dil",
        "afterlogin.welcome": "Mirë se vini!",
        "afterlogin.info": "Mund të dërgoni aplikime dhe të kontrolloni certifikatat.",
        "apply.title": "Dërgo Aplikim të Ri",
        "apply.label.contact": "Persona Kontakti",
        "apply.label.email": "Email Kontakti",
        "apply.label.category": "Kategoria",
        "apply.select.category.placeholder": "– Zgjidh –",
        "apply.label.product": "Emri i Produktit",
        "apply.label.docs": "Ngarko Dokumentet",
        "btn.submit.apply": "Dërgo Aplikimin",
        "status.title": "Kontrollo Statusin",
        "status.input.placeholder": "Shkruani ID të aplikimit",
        "btn.check.status": "Kontrollo",
        "statusResult.notFound": "Nuk u gjet.",
        "myapps.title": "Aplikimet e Mia",
        "myapps.table.id": "ID",
        "myapps.table.date": "Data",
        "myapps.table.product": "Produkti",
        "myapps.table.status": "Statusi",
        "myapps.table.certNo": "Nr. Cert.",
        "myapps.table.view": "Shiko",
        "footer.text": "© 2025 DIAB-REG Sistemi i Certifikimit. Të gjitha të drejtat e rezervuara."
      }
    };

// API: list documents
app.get('/api/documents', async (req, res) => {
     try {
       const docsDir = path.join(__dirname,'public','documents');
       const files   = await fs.promises.readdir(docsDir);
       res.json({ files });
     } catch (e) {
       console.error('Грешка при читање документи:', e);
       res.status(500).json({ error:'Cannot list documents' });
     }
   });

// Admin UI & API
app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname,'public','admin.html'));
});
app.use('/api/admin', requireAdmin, require('./routes/admin'));
// Admin UI & API — отсега со најновите горе
// GET /api/admin/applications
app.get('/api/admin/applications', requireAdmin, async (req, res) => {
  // Дозволени статуси според улога
  const byRole = {
    super:     ['Pending','In Process','Certifying','Completed'],
    processor: ['Pending','In Process'],
    certifier: ['Certifying','Completed'],
  };
  const allowed = byRole[req.session.user.role] || [];

  const apps = await Application
    .find({ status: { $in: allowed } })
    .populate('company')
    .sort({ createdAt: -1 });    // најновите први

  res.json(apps);
});


app.get('/api/admin/logs', requireAdmin, async (req, res) => {
  res.json(await Log.find().sort({ timestamp:-1 }).limit(200));
});

// Public JWT-based API: auth
app.post('/api/auth/register', async (req, res) => {
  const { matichen_broj, name, email, password } = req.body;
  if (!matichen_broj || !name || !email || !password) {
    return res.status(400).json({ success:false, error:'Missing fields' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    await Company.create({ matichen_broj, name, email, passwordHash:hash });
    res.json({ success:true });
  } catch (e) {
    res.status(400).json({ success:false, error:e.message });
  }
});
app.post('/api/auth/login', async (req, res) => {
  const { matichen_broj, password } = req.body;
  const comp = await Company.findOne({ matichen_broj });
  if (!comp || !bcrypt.compareSync(password, comp.passwordHash)) {
    return res.status(401).json({ error:'Invalid credentials' });
  }
  const token = jwt.sign({ id:comp._id }, JWT_SECRET, { expiresIn:'8h' });
  res.json({ token });
});

// Application endpoints
app.post('/api/apply', upload.array('docs'), authGuard, async (req, res) => {
  const { contact, email, product } = req.body;
  const files = (req.files||[]).map(f => f.originalname);
  const doc   = await Application.create({
    company:   req.companyId,
    contact, email, product, docs: files
  });
  res.json({ id: doc._id });
});
app.get('/api/status/:id', async (req, res) => {
  const doc = await Application.findById(req.params.id).populate('company');
  if (!doc) return res.json({ found:false });
  res.json({
    found: true,
    application: {
      status:      doc.status,
      company:     doc.company.name,
      cert_number: doc.cert_number || null
    }
  });
});
const axios = require('axios');

// Price map (EUR)
const PRICE_MAP = {
  'Додатоци и потрошен материјал':                  45_00,
  'Потрошен материјал за мерење/инјекцијање':       65_00,
  'Уреди за мерење':                                125_00,
  'Уреди за апликација на инсулин':                 170_00,
  'Автоматизирани системи':                         260_00
};

// Create Payoneer checkout session
app.post('/api/payment/session', authGuard, express.json(), async (req, res) => {
  const { category } = req.body;
  const amountCents  = PRICE_MAP[category];
  if (!amountCents) return res.status(400).json({ error:'Невалидна категорија' });

  // build your LIST request payload
  const payload = {
    amount: {
      value: amountCents,
      currency: 'EUR'
    },
    reference: `PAY_REF_${Date.now()}`,       // you can also use your own ref
    returnUrl: `${req.protocol}://${req.get('host')}/payment/success`,
    cancelUrl: `${req.protocol}://${req.get('host')}/payment/cancel`
  };

  const env = process.env.PAYONEER_ENV === 'live'
    ? 'https://api.live.oscato.com/api/lists'
    : 'https://api.sandbox.oscato.com/api/lists';

  try {
    const auth = {
      username: process.env.PAYONEER_MERCHANT_CODE,
      password: process.env.PAYONEER_PAYMENT_TOKEN
    };
    const { data } = await axios.post(env, payload, { auth });
    // data.identification.longId is what you pass to the front-end
    res.json({ longId: data.identification.longId });
  } catch (e) {
    console.error('Payoneer session error', e.response?.data||e);
    res.status(500).json({ error:'Не може да се отвори плаќање' });
  }
});

// DELETE апликација заедно со фајловите и логовите
app.delete('/api/admin/applications/:id', requireAdmin, async (req, res) => {
  try {
    const appDoc = await Application.findById(req.params.id);
    if (!appDoc) return res.status(404).json({ error: 'Не постои апликација' });

    // 1) Бришење прикачените документи
    appDoc.docs.forEach(f => {
      const p = path.join(UPLOAD_DIR, f);
      if (fs.existsSync(p)) fs.unlinkSync(p);
    });

    // 2) Бришење на PDF сертификат (ако постои)
    if (appDoc.cert_number) {
      const certPath = path.join(CERT_DIR, `${appDoc.cert_number}.pdf`);
      if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
    }

    // 3) Бришење на audit логови за оваа апликација
    await Log.deleteMany({ itemId: req.params.id });

    // 4) Крајно бришење на самата апликација
    await Application.deleteOne({ _id: req.params.id });

    res.json({ success: true });
  } catch (e) {
    console.error('Грешка при бришење на апликацијата:', e);
    res.status(500).json({ error: 'Грешка при бришење на апликацијата' });
  }
});

app.get('/api/my/applications', authGuard, async (req, res) => {
  res.json(
    await Application.find({ company: req.companyId })
      .sort({ createdAt:-1 })
      .populate('company')
      .exec()
  );
});

// Start server
app.listen(PORT, () => console.log(`🚀 Listening on http://localhost:${PORT}`));
