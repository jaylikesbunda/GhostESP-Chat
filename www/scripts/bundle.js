const fs = require('fs');
const path = require('path');
const { minify: minifyHTML } = require('html-minifier-terser');
const { minify: minifyJS } = require('terser');

const filename = process.argv[2];
if (!filename) {
  console.error('Usage: node bundle.js <filename>');
  process.exit(1);
}

const inputPath = path.join(__dirname, '..', filename);
const outputDir = path.join(__dirname, '..', 'dist');
const outputPath = path.join(outputDir, filename);

// Create dist directory if it doesn't exist
if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}

async function bundleFile() {
  try {
    const content = fs.readFileSync(inputPath, 'utf8');
    let minified;

    if (filename.endsWith('.html')) {
      // Minify HTML
      minified = await minifyHTML(content, {
        collapseWhitespace: true,
        removeComments: true,
        removeRedundantAttributes: true,
        removeScriptTypeAttributes: true,
        removeStyleLinkTypeAttributes: true,
        useShortDoctype: true,
        minifyCSS: true,
        minifyJS: true
      });
    } else if (filename.endsWith('.js')) {
      // Minify JavaScript
      const result = await minifyJS(content, {
        compress: {
          dead_code: true,
          drop_console: false,
          drop_debugger: true,
          keep_classnames: false,
          keep_fargs: true,
          keep_fnames: false,
          keep_infinity: false
        },
        mangle: {
          toplevel: true
        },
        format: {
          comments: false
        }
      });
      minified = result.code;
    } else {
      // Copy as-is
      minified = content;
    }

    fs.writeFileSync(outputPath, minified);

    const originalSize = Buffer.byteLength(content, 'utf8');
    const minifiedSize = Buffer.byteLength(minified, 'utf8');
    const savings = ((1 - minifiedSize / originalSize) * 100).toFixed(2);

    console.log(`✓ Bundled ${filename}: ${originalSize} → ${minifiedSize} bytes (${savings}% reduction)`);
  } catch (error) {
    console.error(`✗ Error bundling ${filename}:`, error.message);
    process.exit(1);
  }
}

bundleFile();
