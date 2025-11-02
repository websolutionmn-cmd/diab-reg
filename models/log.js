const mongoose = require('mongoose');
const logSchema = new mongoose.Schema({
  user:       String,
  action:     String,
  itemId:     String,
  timestamp:  { type: Date, default: Date.now },
});
module.exports = mongoose.models.Log ||
  mongoose.model('Log', logSchema);
