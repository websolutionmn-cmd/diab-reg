// utils/logger.js
const fs = require('fs');
const LOG_PATH = "C:\\Users\\mnikolov\\Desktop\\diabreg-app\\log_doctors.txt";

function logAction(admin, action, details) {
  const line = [
    new Date().toISOString(),
    admin,
    action,
    JSON.stringify(details)
  ].join(' | ') + '\n';
  fs.appendFileSync(LOG_PATH, line, 'utf8');
}

function readLogs() {
  if (!fs.existsSync(LOG_PATH)) return [];
  return fs.readFileSync(LOG_PATH, 'utf8')
    .split('\n')
    .filter(l => l.trim())
    .map(line => {
      const [ time, admin, action, json ] = line.split(' | ');
      let details = {};
      try { details = JSON.parse(json); } catch {}
      return { time, admin, action, details };
    });
}

module.exports = { logAction, readLogs };
