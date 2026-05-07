#!/usr/bin/env bash
# SkillLedger VPS Installer
# Installs Docker, clones the repository, generates secrets, and deploys the full stack.
#
# Supported: Ubuntu 22.04+, Debian 12+, RHEL/Rocky 9+
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/skillledger/skillledger/main/deploy/install.sh | bash
#   # Or after cloning:
#   bash deploy/install.sh
set -euo pipefail

# --- Configuration ---
REPO_URL="https://github.com/skillledger/skillledger.git"
INSTALL_DIR="/opt/skillledger"
BRANCH="main"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Helper functions ---
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Input validation (CR-02) ---
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        error "Invalid domain name: '$domain'. Only alphanumerics, hyphens, and dots allowed."
        exit 1
    fi
}

# --- Rollback trap (D-17) ---
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        error "Installation failed (exit code: $exit_code)"
        if [ -d "$INSTALL_DIR" ] && command -v docker &>/dev/null; then
            warn "Stopping any started containers..."
            cd "$INSTALL_DIR" 2>/dev/null && docker compose down 2>/dev/null || true
        fi
        error "Check the output above for details. Re-run the script after fixing the issue."
    fi
}
trap cleanup EXIT

# --- Root check ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (or with sudo)."
        error "Usage: sudo bash deploy/install.sh"
        exit 1
    fi
}

# --- Docker installation (D-14 step 1) ---
install_docker() {
    if command -v docker &>/dev/null; then
        info "Docker already installed: $(docker --version)"
        return 0
    fi

    info "Installing Docker..."
    if command -v apt-get &>/dev/null; then
        # Ubuntu / Debian
        apt-get update -qq
        apt-get install -y -qq curl ca-certificates git openssl
    elif command -v dnf &>/dev/null; then
        # RHEL 9+ / Rocky / Fedora
        dnf install -y -q curl ca-certificates git openssl
    elif command -v yum &>/dev/null; then
        # RHEL 8 / CentOS
        yum install -y -q curl ca-certificates git openssl
    else
        error "Unsupported package manager. Install Docker manually: https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Use the official Docker convenience script (supports all target distros)
    curl -fsSL https://get.docker.com | sh

    # Start and enable Docker
    systemctl start docker
    systemctl enable docker

    info "Docker installed: $(docker --version)"
}

# --- Docker Compose check ---
check_docker_compose() {
    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 not found. It should be bundled with Docker."
        error "Try: apt-get install docker-compose-plugin"
        exit 1
    fi
    info "Docker Compose: $(docker compose version --short)"
}

# --- Clone repository (D-14 step 2) ---
clone_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Repository already exists at $INSTALL_DIR, pulling latest..."
        cd "$INSTALL_DIR"
        git pull origin "$BRANCH"
    else
        info "Cloning SkillLedger to $INSTALL_DIR..."
        git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
}

# --- Generate .env (D-14 step 3, D-15) ---
generate_env() {
    cd "$INSTALL_DIR"

    if [ -f .env ]; then
        warn ".env file already exists at $INSTALL_DIR/.env -- skipping generation."
        warn "Delete it and re-run if you want fresh secrets."
        return 0
    fi

    if [ ! -f .env.example ]; then
        error ".env.example not found in $INSTALL_DIR. Repository may be incomplete."
        exit 1
    fi

    info "Generating .env from .env.example..."
    cp .env.example .env

    # Generate random secrets (D-14: openssl rand for all required env vars)
    local pg_password
    pg_password=$(openssl rand -base64 32 | tr -d '=/+' | head -c 32)
    local admin_key
    admin_key=$(openssl rand -base64 32 | tr -d '=/+' | head -c 32)
    local jwt_secret
    jwt_secret=$(openssl rand -base64 32)
    local auth_secret
    auth_secret=$(openssl rand -base64 32)

    # Replace empty values with generated secrets
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg_password}|" .env
    sed -i "s|^SKILLLEDGER_ADMIN_API_KEY=.*|SKILLLEDGER_ADMIN_API_KEY=${admin_key}|" .env
    sed -i "s|^SKILLLEDGER_JWT_SECRET=.*|SKILLLEDGER_JWT_SECRET=${jwt_secret}|" .env
    sed -i "s|^AUTH_SECRET=.*|AUTH_SECRET=${auth_secret}|" .env

    # Restrict .env file permissions (T-30-08: secrets on disk)
    chmod 600 .env

    # Prompt for domain (D-15)
    echo ""
    info "Domain configuration for TLS (powered by Caddy):"
    echo -e "  Enter your domain name (e.g., skillledger.example.com)"
    echo -e "  Leave empty to use the default values from .env.example."
    echo ""
    read -r -p "  API domain [log.skillledger.dev]: " api_domain
    read -r -p "  Dashboard domain [dashboard.skillledger.dev]: " dash_domain

    if [ -n "$api_domain" ]; then
        validate_domain "$api_domain"
        sed -i "s|^SKILLLEDGER_DOMAIN=.*|SKILLLEDGER_DOMAIN=${api_domain}|" .env
    fi
    if [ -n "$dash_domain" ]; then
        validate_domain "$dash_domain"
        sed -i "s|^DASHBOARD_DOMAIN=.*|DASHBOARD_DOMAIN=${dash_domain}|" .env
        sed -i "s|^SKILLLEDGER_DASHBOARD_URL=.*|SKILLLEDGER_DASHBOARD_URL=https://${dash_domain}|" .env
    fi

    # LOG_PRIVATE_KEY -- prompt user (CR-01: don't deploy with unset key)
    echo ""
    warn "LOG_PRIVATE_KEY is required for transparency log signing."
    warn "Generate: openssl genpkey -algorithm Ed25519 -outform DER | base64 -w0"
    echo ""
    read -r -p "  Enter LOG_PRIVATE_KEY value (or press Enter to skip — log signing disabled): " log_key
    if [ -n "$log_key" ]; then
        sed -i "s|^LOG_PRIVATE_KEY=.*|LOG_PRIVATE_KEY=${log_key}|" .env
        info "LOG_PRIVATE_KEY set."
    else
        warn "LOG_PRIVATE_KEY not set. Transparency log will start without signing capability."
        warn "Set it later in $INSTALL_DIR/.env and restart: docker compose restart skillledger-log"
    fi

    info ".env generated with random secrets."
}

# --- Start the stack (D-14 steps 4-5) ---
start_stack() {
    cd "$INSTALL_DIR"

    info "Starting SkillLedger stack (production mode with Caddy TLS)..."
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

    info "Waiting for services to become healthy..."
    local retries=0
    local max_retries=30
    while [ $retries -lt $max_retries ]; do
        if docker compose -f docker-compose.yml -f docker-compose.prod.yml ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
            break
        fi
        retries=$((retries + 1))
        sleep 2
    done

    echo ""
    if [ $retries -ge $max_retries ]; then
        warn "========================================="
        warn "  Services not fully healthy after $((max_retries * 2))s"
        warn "========================================="
        warn "Check logs: docker compose -f docker-compose.yml -f docker-compose.prod.yml logs"
        echo ""
        docker compose -f docker-compose.yml -f docker-compose.prod.yml ps
        echo ""
        warn "Stack is running but may need attention. Check container status above."
    else
        info "========================================="
        info "  SkillLedger deployed successfully!"
        info "========================================="
    fi
    echo ""

    # Print service URLs
    local api_domain
    api_domain=$(grep "^SKILLLEDGER_DOMAIN=" .env | cut -d= -f2)
    local dash_domain
    dash_domain=$(grep "^DASHBOARD_DOMAIN=" .env | cut -d= -f2)

    info "Services:"
    echo "  API:       https://${api_domain}"
    echo "  Dashboard: https://${dash_domain}"
    echo ""

    # Print container status
    docker compose -f docker-compose.yml -f docker-compose.prod.yml ps

    echo ""
    # Post-install notes (D-16 -- recommend firewall but don't configure)
    warn "Post-install recommendations:"
    echo "  1. Configure firewall: ufw allow 80,443/tcp && ufw enable"
    echo "  2. Set LOG_PRIVATE_KEY in $INSTALL_DIR/.env (required for tlog signing)"
    echo "  3. Verify TLS: curl -I https://${api_domain}/health"
    echo "  4. Restrict .env permissions if not already: chmod 600 $INSTALL_DIR/.env"
    echo ""
    info "Logs: cd $INSTALL_DIR && docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f"
    info "Stop: cd $INSTALL_DIR && docker compose -f docker-compose.yml -f docker-compose.prod.yml down"
}

# --- Main ---
main() {
    echo ""
    info "========================================="
    info "  SkillLedger VPS Installer"
    info "========================================="
    echo ""

    check_root
    install_docker
    check_docker_compose
    clone_repo
    generate_env
    start_stack
}

main "$@"
