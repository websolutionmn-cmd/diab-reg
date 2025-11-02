// config/users.js
const bcrypt = require('bcryptjs');

const users = [
  { username: 'Administrator', passwordHash: bcrypt.hashSync('Admin#2025', 10), role: 'super' },       // гледа сѐ
  { username: 'Pat_Diab1',     passwordHash: bcrypt.hashSync('PassPat1!', 10),   role: 'processor' },  // гледа Pending + In Process
  { username: 'Pat_Diab2',     passwordHash: bcrypt.hashSync('PassPat2@', 10),   role: 'processor' },
  { username: 'Doc_diab',      passwordHash: bcrypt.hashSync('PassDoc123', 10),  role: 'certifier' },  // гледа Certifying + може Complete
  { username: 'Exp_Diab',      passwordHash: bcrypt.hashSync('ExpDiab$$', 10),   role: 'processor' },
];

module.exports = users;
