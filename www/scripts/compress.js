const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const distDir = path.join(__dirname, '..', 'dist');
const files = ['index.html', 'setup.html', 'app.js'];

function toHexArray(buffer) {
  const bytes = [];
  for (let i = 0; i < buffer.length; i++) {
    bytes.push(`0x${buffer[i].toString(16).padStart(2, '0')}`);
  }
  return bytes;
}

function generateHeaderFile(filename, gzData) {
  const varName = filename.replace(/[^a-zA-Z0-9]/g, '_');
  const hexArray = toHexArray(gzData);

  // Format as C header file
  let header = `// Auto-generated gzipped ${filename}\n`;
  header += `// Original size: ${fs.statSync(path.join(distDir, filename)).size} bytes\n`;
  header += `// Compressed size: ${gzData.length} bytes\n`;
  header += `\n`;
  header += `#ifndef ${varName.toUpperCase()}_H\n`;
  header += `#define ${varName.toUpperCase()}_H\n`;
  header += `\n`;
  header += `#include <stdint.h>\n`;
  header += `\n`;
  header += `static const uint8_t ${varName}_gz[] = {\n`;

  // Split into lines of 12 bytes each for readability
  for (let i = 0; i < hexArray.length; i += 12) {
    const line = hexArray.slice(i, i + 12).join(', ');
    header += `    ${line}${i + 12 < hexArray.length ? ',' : ''}\n`;
  }

  header += `};\n`;
  header += `\n`;
  header += `static const size_t ${varName}_gz_len = ${gzData.length};\n`;
  header += `\n`;
  header += `#endif // ${varName.toUpperCase()}_H\n`;

  return header;
}

async function compressFiles() {
  console.log('\n=== Compressing Web UI Files ===\n');

  for (const filename of files) {
    const inputPath = path.join(distDir, filename);

    if (!fs.existsSync(inputPath)) {
      console.warn(`⚠ Skipping ${filename} (not found in dist/)`);
      continue;
    }

    try {
      const content = fs.readFileSync(inputPath);
      const gzipped = zlib.gzipSync(content, { level: 9 });

      // Generate .h file
      const headerContent = generateHeaderFile(filename, gzipped);
      const headerPath = path.join(distDir, `${filename}.gz.h`);
      fs.writeFileSync(headerPath, headerContent);

      const originalSize = content.length;
      const compressedSize = gzipped.length;
      const ratio = ((1 - compressedSize / originalSize) * 100).toFixed(2);

      console.log(`✓ ${filename}`);
      console.log(`  Original:   ${originalSize.toLocaleString()} bytes`);
      console.log(`  Compressed: ${compressedSize.toLocaleString()} bytes`);
      console.log(`  Ratio:      ${ratio}% reduction`);
      console.log(`  Output:     ${path.basename(headerPath)}\n`);
    } catch (error) {
      console.error(`✗ Error compressing ${filename}:`, error.message);
      process.exit(1);
    }
  }

  console.log('=== Compression Complete ===\n');
}

compressFiles();
