// models/Company.js
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const companySchema = new mongoose.Schema({
  matichen_broj: { type: String, unique: true, required: true },
  name:          { type: String, required: true },
  email:         { type: String, required: true },
  password_hash: { type: String, required: true },
  role:          { type: String, enum: ['company','admin'], default: 'company' },
  created_at:    { type: Date, default: Date.now },
});

companySchema.methods.verifyPassword = function(password) {
  return bcrypt.compare(password, this.password_hash);
};

module.exports = mongoose.model('Company', companySchema);
