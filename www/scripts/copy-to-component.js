const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, '..', 'dist');
const targetDir = path.join(__dirname, '..', '..', 'components', 'webserver', 'www');

// Create target directory if it doesn't exist
if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

const files = fs.readdirSync(distDir).filter(f => f.endsWith('.gz.h'));

console.log('\n=== Copying Headers to Component ===\n');

for (const file of files) {
  const src = path.join(distDir, file);
  const dest = path.join(targetDir, file);

  fs.copyFileSync(src, dest);
  console.log(`✓ Copied ${file} → components/webserver/www/`);
}

console.log('\n=== Copy Complete ===\n');
console.log('Headers are ready to be included in your ESP32 firmware.\n');
