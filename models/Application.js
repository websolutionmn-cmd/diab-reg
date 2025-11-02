// models/Application.js
const mongoose = require('mongoose');

const applicationSchema = new mongoose.Schema({
  company:     { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
  product:     { type: String, required: true },
  contact:     { type: String, required: true },
  email:       { type: String, required: true },
  documents:   { type: [String], default: [] },
  status:      { type: String, enum: ['Pending','In Process','Certifying','Completed'], default: 'Pending' },
  cert_number: { type: String },
  applied_at:  { type: Date, default: Date.now },
  updated_at:  { type: Date },
});

// If model is already compiled, use it. Otherwise, compile a new one.
module.exports = mongoose.models.Application ||
                 mongoose.model('Application', applicationSchema);
