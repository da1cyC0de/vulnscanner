#!/bin/bash
# ============================================
#   VulnScanner - VPS Deploy Script
#   Jalankan di VPS (Ubuntu/Debian)
# ============================================

set -e

echo "=========================================="
echo "  VulnScanner VPS Deployment"
echo "=========================================="

# --- Detect IP ---
VPS_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo "[*] VPS IP detected: $VPS_IP"

# --- Install dependencies ---
echo ""
echo "[1/6] Installing system dependencies..."
sudo apt update -y
sudo apt install -y python3 python3-pip python3-venv curl git

# Install Node.js 20 LTS
if ! command -v node &> /dev/null; then
    echo "[*] Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
fi

echo "  Python: $(python3 --version)"
echo "  Node:   $(node --version)"
echo "  npm:    $(npm --version)"

# --- Setup backend ---
echo ""
echo "[2/6] Setting up backend..."
cd "$(dirname "$0")"
PROJECT_DIR=$(pwd)

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# --- Setup frontend ---
echo ""
echo "[3/6] Setting up frontend..."
cd frontend

# Create .env.local for VPS
cat > .env.local << EOF
NEXT_PUBLIC_API_URL=http://${VPS_IP}:8000
NEXT_PUBLIC_WS_URL=ws://${VPS_IP}:8000
EOF

npm install
npm run build

cd "$PROJECT_DIR"

# --- Set backend env ---
echo ""
echo "[4/6] Configuring backend..."
export ALLOWED_ORIGINS="http://${VPS_IP}:3000,http://localhost:3000,http://127.0.0.1:3000"
export GEMINI_API_KEY="${GEMINI_API_KEY:-}"

# --- Create systemd services ---
echo ""
echo "[5/6] Creating systemd services..."

# Backend service
sudo tee /etc/systemd/system/vulnscanner-backend.service > /dev/null << EOF
[Unit]
Description=VulnScanner Backend (FastAPI)
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${PROJECT_DIR}
Environment=ALLOWED_ORIGINS=http://${VPS_IP}:3000,http://localhost:3000,http://127.0.0.1:3000
ExecStart=${PROJECT_DIR}/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Frontend service
sudo tee /etc/systemd/system/vulnscanner-frontend.service > /dev/null << EOF
[Unit]
Description=VulnScanner Frontend (Next.js)
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=${PROJECT_DIR}/frontend
ExecStart=$(which npm) run start -- -p 3000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vulnscanner-backend vulnscanner-frontend

# --- Start services ---
echo ""
echo "[6/6] Starting services..."
sudo systemctl start vulnscanner-backend
sleep 3
sudo systemctl start vulnscanner-frontend
sleep 3

# --- Verify ---
echo ""
echo "=========================================="
echo "  Deployment Complete!"
echo "=========================================="
echo ""

# Check status
BACKEND_STATUS=$(systemctl is-active vulnscanner-backend)
FRONTEND_STATUS=$(systemctl is-active vulnscanner-frontend)

echo "  Backend:  $BACKEND_STATUS  -> http://${VPS_IP}:8000"
echo "  Frontend: $FRONTEND_STATUS  -> http://${VPS_IP}:3000"
echo ""
echo "  Buka di browser: http://${VPS_IP}:3000"
echo ""
echo "=========================================="
echo "  Useful Commands:"
echo "=========================================="
echo "  sudo systemctl status vulnscanner-backend"
echo "  sudo systemctl status vulnscanner-frontend"
echo "  sudo systemctl restart vulnscanner-backend"
echo "  sudo systemctl restart vulnscanner-frontend"
echo "  sudo journalctl -u vulnscanner-backend -f"
echo "  sudo journalctl -u vulnscanner-frontend -f"
echo "=========================================="
