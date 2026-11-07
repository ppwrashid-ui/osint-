const bcrypt = require('bcryptjs'), db = require('../db');
const [n, p] = process.argv.slice(2);
if (!/^[\w.-]{3,24}$/.test(n || '') || !p || p.length < 8 || p.length > 72) { console.error('Usage: npm run create-admin -- <username 3-24> <password 8-72>'); process.exit(1); }
const h = bcrypt.hashSync(p, 12);
db.prepare("INSERT INTO users(username,pass_hash,role) VALUES(?,?, 'admin') ON CONFLICT(username) DO UPDATE SET pass_hash=excluded.pass_hash, role='admin'").run(n, h);
console.log('Admin ready: ' + n);
