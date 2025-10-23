#!/bin/bash
set -e

echo "🔧 Building JSR Documentation Audit..."

echo "📦 Building WASM with wasm-pack..."
wasm-pack build --target web --out-dir dist/pkg --no-default-features --release

echo "✅ Build complete!"
echo ""
echo "📊 Build statistics:"
echo "  WASM size: $(du -h dist/pkg/audit_script_bg.wasm | cut -f1)"
echo ""
echo "📁 Output directory: dist/"
echo "  - index.html"
echo "  - style.css"
echo "  - app.js"
echo "  - pkg/audit_script_bg.wasm"
echo ""
echo "🚀 To test locally, run:"
echo "  python3 -m http.server 8000 --directory dist"
echo "  Then open http://localhost:8000"
