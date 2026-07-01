// Usage: node scripts/hash-admin-password.mjs "MySecretPassword123"
// Copy the printed hash into ADMIN_PASSWORD_HASH in your .env / Railway vars.
import bcrypt from 'bcryptjs';

const pw = process.argv[2];
if (!pw) {
  console.error('İstifadə: node scripts/hash-admin-password.mjs "parolun"');
  process.exit(1);
}
const hash = bcrypt.hashSync(pw, 10);
console.log('\nADMIN_PASSWORD_HASH=' + hash + '\n');
