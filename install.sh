#!/usr/bin/env bash
# kx install script
set -e

echo "[*] Installing kx dependencies..."

# Python deps
pip install -r requirements.txt --break-system-packages -q

# Playwright browser
echo "[*] Installing Playwright Chromium..."
playwright install chromium

# Node.js AST worker
echo "[*] Installing Node.js AST worker..."
cd ast_worker && npm install --silent && cd ..

# Make kx executable from PATH
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/kx.py"

# Clean up old wraith symlinks (from previous installs under the old name)
# so the user doesn't accidentally run a stale version when they type `wraith`.
for old in /usr/local/bin/wraith "$HOME/.local/bin/wraith"; do
    if [ -L "$old" ]; then
        rm -f "$old" 2>/dev/null && echo "[-] Removed legacy symlink: $old"
    fi
done

# Symlink to /usr/local/bin/kx if writable, else ~/.local/bin/kx
if [ -w /usr/local/bin ]; then
    ln -sf "$SCRIPT_DIR/kx.py" /usr/local/bin/kx
    echo "[+] Installed to /usr/local/bin/kx"
else
    mkdir -p "$HOME/.local/bin"
    ln -sf "$SCRIPT_DIR/kx.py" "$HOME/.local/bin/kx"
    echo "[+] Installed to ~/.local/bin/kx"
    echo "    Make sure ~/.local/bin is in your PATH"
fi

echo ""
echo "[+] kx ready. Usage:"
echo "    kx -u https://target.com"
echo "    kx -u https://target.com --runtime --diff --burp http://127.0.0.1:1337"
