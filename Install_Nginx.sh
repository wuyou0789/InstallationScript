#!/bin/bash
#================================================================================
# Nginx WebDAV Ultimate Script (AWUS) - Final Production Release (MODIFIED)
#
# Version: 4.3.2-mod
# Author: wuyou0789 & AI Assistant
# GitHub: https://github.com/wuyou0789/InstallationScript
# License: MIT
#
# INVOCATION: This script MUST be run with root privileges.
#             e.g., sudo ./awus.sh install
#================================================================================

# --- Strict Mode & Environment ---
set -euo pipefail
IFS=$'\n\t'

# --- Global Constants ---
readonly SCRIPT_VERSION="4.3.2-mod"
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# --- Configuration Paths ---
readonly SCRIPT_INSTALL_DIR="/usr/local/etc/awus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_INSTALL_DIR}/awus.sh"
readonly CONFIG_FILE="${SCRIPT_INSTALL_DIR}/config.conf"
readonly DEFAULT_NGINX_PASSWD_FILE="/etc/nginx/webdav.passwd"
readonly ALIAS_FILE="/etc/profile.d/awus-alias.sh"
readonly LOCK_FILE="/var/tmp/awus.lock"
readonly CERTBOT_CMD="/usr/bin/certbot" 

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*"; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*"; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*"; exit 1; }

# --- Prerequisite and Utility Functions ---
check_root() { if [[ $EUID -ne 0 ]]; then _error "此脚本必须以 root 权限运行。请使用 'sudo ./awus.sh'。"; fi; }
_exists() { command -v "$1" >/dev/null 2>&1; }

_os_check() {
    if ! _exists "lsb_release"; then
        _warn "'lsb_release' command not found. Installing 'lsb-core'...";
        apt-get update && apt-get install -y lsb-core
    fi
    local os_id; os_id=$(lsb_release -is)
    if [[ "$os_id" != "Ubuntu" && "$os_id" != "Debian" ]]; then
        _error "此脚本目前仅为 Ubuntu/Debian 系统设计。"
    fi
    _info "检测到兼容的操作系统: $(lsb_release -ds)"
}

_wait_for_apt_lock() {
    local max_wait_seconds=300; local start_time; start_time=$(date +%s)
    _info "正在检查软件包管理器锁..."
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        local current_time; current_time=$(date +%s)
        if (( current_time - start_time > max_wait_seconds )); then _error "等待 dpkg 锁超时 (> ${max_wait_seconds} 秒)。"; fi
        _warn "等待其他软件包管理器进程释放锁... (已等待 $((current_time - start_time)) 秒)"
        sleep 5
    done
    _info "软件包管理器锁已释放。"
}

_install_pkgs() {
    _info "正在更新软件包列表...";
    apt-get update || _warn "apt-get update 失败，但仍将尝试安装。"
    _info "正在安装软件包: $*"
    apt-get install -y "$@" || _error "软件包安装失败: $*。"
}

_nginx_ctl() {
    local action="$1"; _info "正在 ${action} Nginx 服务..."
    if ! systemctl "${action}" nginx; then _warn "执行 systemctl ${action} nginx 失败 (可能服务已不存在)。"; fi
    sleep 1
    if [[ "$action" == "start" || "$action" == "restart" ]]; then
        if ! systemctl is-active --quiet nginx; then _warn "Nginx 服务在 ${action} 后状态为【非活动】！"; fi
    fi
}

load_config() { if [ -f "$CONFIG_FILE" ]; then source "$CONFIG_FILE"; fi; }

# --- MODIFIED setup_script_invocation ---
setup_script_invocation() {
    _info "正在安装/更新脚本以供后续使用..."
    mkdir -p "$SCRIPT_INSTALL_DIR"
    # 只有当执行的脚本和目标位置不是同一个文件时，才执行复制操作
    if [ ! -f "$SCRIPT_SELF_PATH" ] || ! cmp -s "$0" "$SCRIPT_SELF_PATH"; then
        cp -f "$0" "$SCRIPT_SELF_PATH"
        _info "脚本已复制/更新至 ${SCRIPT_SELF_PATH}"
    else
        _info "脚本已在最新位置运行，无需复制。"
    fi
    chmod +x "$SCRIPT_SELF_PATH"
    
    # 创建别名文件
    if ! [ -f "$ALIAS_FILE" ] || ! grep -q "alias webdav=" "$ALIAS_FILE"; then
        echo "alias webdav='bash ${SCRIPT_SELF_PATH}'" > "$ALIAS_FILE"
        _info "别名 'webdav' 已创建。请运行 'source ${ALIAS_FILE}' 或重新登录以使用。"
    fi
}

setup_systemd_service() {
    _info "正在为定制版 Nginx 创建 systemd 服务文件..."
    local service_file_path="/etc/systemd/system/nginx.service"
    cat <<EOF_SYSTEMD | tee "${service_file_path}" > /dev/null
[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=network.target
[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /var/run/nginx.pid
TimeoutStopSec=5
KillMode=mixed
[Install]
WantedBy=multi-user.target
EOF_SYSTEMD
    _info "正在重载 systemd 并启用 Nginx 服务..."; systemctl daemon-reload; systemctl enable nginx
}

install_dependencies() {
    _info "正在检查并安装基础依赖...";
    
    local pkgs_to_install=()
    ! _exists "curl" && pkgs_to_install+=("curl")
    ! _exists "htpasswd" && pkgs_to_install+=("apache2-utils")
    
    if ! ldconfig -p | grep -q "libpcre.so.3"; then
        _info "检测到系统缺少 Nginx 运行所需的 libpcre.so.3 库。"
        pkgs_to_install+=("libpcre3")
    fi

    if [ ${#pkgs_to_install[@]} -gt 0 ]; then
        _info "将要安装以下缺失的依赖: ${pkgs_to_install[*]}"
        _install_pkgs "${pkgs_to_install[@]}"
    else
        _info "所有基础依赖均已存在。"
    fi

    _info "正在检查并安装 Certbot...";
    if ! _exists "${CERTBOT_CMD}" || ! [[ $(readlink -f "${CERTBOT_CMD}") == *"/snap/"* ]]; then
        if ! _exists "certbot"; then _info "未找到 Certbot。将使用 Snap 进行安装..."; else _warn "检测到不推荐的 Certbot 版本。将自动替换为 Snap 版本..."; fi
        if ! _exists "snapd"; then _install_pkgs "snapd"; fi;
        if ! snap list core &>/dev/null; then snap install core; fi; snap refresh core
        if dpkg -s certbot &>/dev/null; then apt-get remove -y certbot* &>/dev/null; fi
        snap install --classic certbot || _error "通过 snap 安装 Certbot 失败。"
        if [ -f /usr/bin/certbot ] && [ ! -L /usr/bin/certbot ]; then rm -f /usr/bin/certbot; fi
        ln -sf /snap/bin/certbot /usr/bin/certbot || _warn "创建 certbot 符号链接失败。"
    else _info "检测到已正确安装的 Certbot (Snap 版本)。"; fi
    if ! "${CERTBOT_CMD}" plugins | grep -q 'nginx'; then _error "Certbot Nginx 插件不可用！"; fi
}

install_custom_nginx() {
    _info "正在安装定制版 Nginx...";
    if dpkg -s nginx-custom-webdav &>/dev/null; then
        _info "检测到已安装的定制版 Nginx。"
        if [ ! -f "/etc/systemd/system/nginx.service" ]; then _warn "但 systemd 服务文件缺失，正在创建..."; setup_systemd_service; fi
        return
    fi
    
    local arch; arch=$(dpkg --print-architecture)
    _info "检测到系统架构为: ${arch}"

    local deb_filename=""
    if [[ "$arch" == "amd64" ]]; then
        deb_filename="nginx-custom-webdav_1.28.0-1_amd64.deb"
    elif [[ "$arch" == "arm64" || "$arch" == "aarch64" ]]; then
        deb_filename="nginx-custom-webdav_1.28.0-1_arm64.deb"
    else
        _error "不支持的系统架构: ${arch}。本脚本只支持 amd64 和 arm64。"
    fi
    
    local release_tag="nginx-custom-webdav"
    local deb_url="https://github.com/wuyou0789/InstallationScript/releases/download/${release_tag}/${deb_filename}"
    local deb_path="/tmp/${deb_filename}"

    _info "正在从 GitHub 下载 [${arch}] 版本的 Nginx 包...";
    if ! curl -L --fail -o "${deb_path}" "${deb_url}"; then
        _error "下载定制 Nginx 包失败！请检查您在脚本中配置的 URL 是否正确，以及 GitHub Release 是否发布。"
    fi
    
    _info "正在卸载任何可能冲突的官方 Nginx...";
    systemctl stop nginx &>/dev/null || true
    _wait_for_apt_lock
    apt-get purge -y nginx nginx-common &>/dev/null || true
    
    _info "正在安装定制的 Nginx 包...";
    _wait_for_apt_lock
    if ! dpkg -i "${deb_path}"; then
        _warn "dpkg 安装失败，正在尝试自动修复依赖 (-f)...";
        _wait_for_apt_lock; apt-get install -f -y || _error "自动修复依赖失败！";
    fi
    rm -f "${deb_path}"; _info "定制版 Nginx 安装成功！"
    setup_systemd_service
}

do_install() {
    local DOMAIN_NAME WEBDEV_DIR NGINX_PASSWD_FILE ADMIN_USER ADMIN_PASS
    local nginx_vhost_path temp_nginx_vhost_path nginx_main_conf="/etc/nginx/nginx.conf"

    trap 'install_cleanup' ERR

    install_cleanup() {
        _warn "\n--- 安装过程中发生错误，正在执行自动清理... ---";
        systemctl stop nginx &>/dev/null || true 
        if [ -f "${nginx_main_conf}.awus.bak" ]; then
            _warn "正在从备份恢复 ${nginx_main_conf}..."
            mv "${nginx_main_conf}.awus.bak" "${nginx_main_conf}" || _warn "恢复 nginx.conf 失败。"
        fi
        if [ -n "${DOMAIN_NAME:-}" ]; then
            _warn "移除为 ${DOMAIN_NAME} 创建的 Nginx 配置...";
            rm -f "/etc/nginx/sites-enabled/${DOMAIN_NAME}" "/etc/nginx/sites-available/${DOMAIN_NAME}"
            if [ -n "${temp_nginx_vhost_path:-}" ]; then rm -f "/etc/nginx/sites-enabled/$(basename "$temp_nginx_vhost_path")" "$temp_nginx_vhost_path"; fi
            if _exists "${CERTBOT_CMD}" && [ -d "/etc/letsencrypt/live/${DOMAIN_NAME}" ]; then _warn "删除为 ${DOMAIN_NAME} 创建的 SSL 证书..."; "${CERTBOT_CMD}" delete --cert-name "$DOMAIN_NAME" --non-interactive; fi
        fi
        _info "--- 清理完成 ---"
    }

    _os_check; install_dependencies; install_custom_nginx

    _info "--- Nginx WebDAV 配置向导 ---"
    while true; do read -r -p "请输入您的域名 (例如: dav.example.com): " DOMAIN_NAME; if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then break; else _warn "域名格式无效。"; fi; done
    local default_dir="/var/www/webdav/${DOMAIN_NAME}"; read -r -p "请输入 WebDAV 数据目录 [${default_dir}]: " WEBDEV_DIR; WEBDEV_DIR=${WEBDEV_DIR:-$default_dir}
    if [[ ! "$WEBDEV_DIR" =~ ^/ ]]; then _error "路径必须是绝对路径。"; fi
    WEBDEV_DIR=$(realpath -m "$WEBDEV_DIR")
    local default_passwd_file="$DEFAULT_NGINX_PASSWD_FILE"; read -r -p "请输入 WebDAV 密码文件路径 [${default_passwd_file}]: " NGINX_PASSWD_FILE; NGINX_PASSWD_FILE=${NGINX_PASSWD_FILE:-$default_passwd_file}
    while true; do read -r -p "请输入管理员用户名: " ADMIN_USER; if [[ "$ADMIN_USER" =~ ^[a-zA-Z0-9._-]+$ ]]; then break; else _warn "用户名包含无效字符。"; fi; done
    local ADMIN_PASS; while true; do read -r -s -p "为 ${ADMIN_USER} 设置密码: " ADMIN_PASS; echo; read -r -s -p "确认密码: " confirm_pass; echo; if [[ "$ADMIN_PASS" == "$confirm_pass" && -n "$ADMIN_PASS" ]]; then break; else _warn "密码为空或不匹配。"; fi; done

    _info "正在准备 Nginx 配置文件...";
    _info "正在创建全新的 Nginx 主配置文件 (${nginx_main_conf})..."
    if [ -f "${nginx_main_conf}" ]; then
        mv "${nginx_main_conf}" "${nginx_main_conf}.awus.bak"
        _info "现有的 ${nginx_main_conf} 已备份到 ${nginx_main_conf}.awus.bak"
    fi
    cat <<EOF_NGINX_CONF | tee "${nginx_main_conf}" > /dev/null
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
events {
    worker_connections 768;
}
http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    dav_ext_lock_zone zone=webdav:10m;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF_NGINX_CONF
    _info "全新的 ${nginx_main_conf} 创建成功。"

    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d /var/log/nginx "/var/cache/nginx/client_temp"

    temp_nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}.certbot-setup.conf"
    cat <<EOF_VHOST_TEMP | tee "${temp_nginx_vhost_path}" > /dev/null
server { listen 80; server_name ${DOMAIN_NAME}; root /var/www/html; location /.well-known/acme-challenge/ { allow all; } location / { return 404; }}
EOF_VHOST_TEMP

    _info "正在执行系统配置...";
    mkdir -p "${WEBDEV_DIR}" && chown www-data:www-data "${WEBDEV_DIR}" && chmod 775 "${WEBDEV_DIR}"
    touch "${NGINX_PASSWD_FILE}" && chown root:www-data "${NGINX_PASSWD_FILE}" && chmod 640 "${NGINX_PASSWD_FILE}"
    htpasswd -cb "${NGINX_PASSWD_FILE}" "${ADMIN_USER}" "${ADMIN_PASS}" || _error "创建管理员用户失败。"

    _info "正在启用临时站点并重启 Nginx (为 Certbot 做准备)...";
    rm -f /etc/nginx/sites-enabled/default || true
    rm -f "/etc/nginx/sites-enabled/${DOMAIN_NAME}" || true 
    ln -sf "$temp_nginx_vhost_path" "/etc/nginx/sites-enabled/"

    nginx -t || _error "Nginx 临时配置测试失败。"; 
    _nginx_ctl "restart" || _error "Nginx 初始重启失败。"

    _info "正在处理 SSL 证书...";
    local cert_email email_option cert_command_array=("${CERTBOT_CMD}" "certonly" "--non-interactive" "--agree-tos" "--nginx" "-d" "${DOMAIN_NAME}")
    read -r -p "请输入用于 Let's Encrypt 的邮箱 (推荐): " cert_email
    if [[ -n "$cert_email" ]]; then cert_command_array+=("--email" "${cert_email}"); else _warn "未提供邮箱！"; cert_command_array+=("--register-unsafely-without-email"); fi

    if [ -d "/etc/letsencrypt/live/${DOMAIN_NAME}" ]; then
        _warn "检测到 ${DOMAIN_NAME} 的证书已存在。"; read -r -p "[1] 更新现有 [2] 强制重申 [0] 中止: " cert_choice
        case "$cert_choice" in
            1) _info "尝试更新现有证书..."; local update_cmd=("${cert_command_array[@]}" "--keep-until-expiring"); "${update_cmd[@]}" || _error "Certbot (更新现有) 失败。";;
            2) _info "强制重新申请证书..."; local renew_cmd=("${cert_command_array[@]}" "--force-renewal"); "${renew_cmd[@]}" || _error "Certbot (强制重新申请) 失败。";;
            *) _error "操作中止。";;
        esac
    else
        _info "正在申请新的 SSL 证书..."; "${cert_command_array[@]}" || _error "Certbot (首次申请) 失败。"
    fi

    _info "SSL 证书已处理。正在生成最终的 Nginx 配置文件..."
    nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}"
    cat <<EOF_VHOST_FINAL | tee "${nginx_vhost_path}" > /dev/null
server {
    listen 80; listen [::]:80; server_name ${DOMAIN_NAME};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$server_name\$request_uri; }
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${DOMAIN_NAME};
    root ${WEBDEV_DIR};
    charset utf-8;
    client_max_body_size 2G; # Increased limit
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    access_log /var/log/nginx/${DOMAIN_NAME}.access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}.error.log warn;
    location ~ /\.(_.*|DS_Store|thumbs\.db)$ { return 403; }
    location / {
        auth_basic "Secure WebDAV"; auth_basic_user_file ${NGINX_PASSWD_FILE};
        dav_ext_methods PROPFIND OPTIONS;
        dav_access user:rw group:r all:r;
        create_full_put_path on;
        autoindex on;
    }
    ssl_certificate /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
EOF_VHOST_FINAL

    _info "正在启用最终站点配置并移除临时配置...";
    rm -f "/etc/nginx/sites-enabled/$(basename "$temp_nginx_vhost_path")" || true
    rm -f "$temp_nginx_vhost_path" || true
    ln -sf "$nginx_vhost_path" "/etc/nginx/sites-enabled/"

    _info "最终测试并重启 Nginx..."; nginx -t || _error "最终配置测试失败！"; _nginx_ctl "restart"

    trap - ERR EXIT
    _info "${GREEN}--- Nginx WebDAV 安装和配置成功！ ---${NC}";

    mkdir -p "$SCRIPT_INSTALL_DIR"
    { echo "AWUS_DOMAIN_NAME=\"${DOMAIN_NAME}\""; echo "AWUS_WEBDEV_DIR=\"${WEBDEV_DIR}\""; echo "AWUS_NGINX_PASSWD_FILE=\"${NGINX_PASSWD_FILE}\""; } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"; setup_script_invocation
}


do_status() {
    load_config; _info "--- Nginx WebDAV 服务状态 ---"
    if ! dpkg -s nginx-custom-webdav &>/dev/null; then _warn "未安装定制版 Nginx。"; return; fi
    if systemctl is-active --quiet nginx; then _info "Nginx 服务状态: ${GREEN}运行中${NC}"; elif systemctl is-failed --quiet nginx; then _info "Nginx 服务状态: ${RED}失败状态 (Failed)！${NC}"; else _info "Nginx 服务状态: ${YELLOW}已停止${NC}"; fi
    _info "Nginx 版本: $(nginx -v 2>&1 | cut -d'/' -f2)"; _info "OpenSSL 版本: $(openssl version)"
    if [ -f "$CONFIG_FILE" ]; then
        _info "--- 保存的配置信息 (${CONFIG_FILE}) ---"
        _info "  WebDAV 访问域名: https://${AWUS_DOMAIN_NAME}"
        _info "  WebDAV 服务器目录: ${AWUS_WEBDEV_DIR}"
        _info "  WebDAV 密码文件: ${AWUS_NGINX_PASSWD_FILE}"
        if [ -d "/etc/letsencrypt/live/${AWUS_DOMAIN_NAME}" ]; then
            local expiry_date; expiry_date=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${AWUS_DOMAIN_NAME}/fullchain.pem" | cut -d= -f2)
            _info "  SSL 证书到期日: ${expiry_date}"
        fi
    fi
    if _exists "ufw"; then _info "--- UFW 防火墙状态 ---"; ufw status verbose | sed 's/^/  /'; fi
    _info "--- Nginx 监听端口 ---"; ss -tlpn | grep nginx | sed 's/^/  /' || _info "  (Nginx 未运行或未监听任何端口)"
}

do_accounts_manage() {
    load_config; local action="$1"; local username="${2:-}"; local passwd_file="${AWUS_NGINX_PASSWD_FILE}"
    if [ ! -f "$passwd_file" ] && [[ "$action" != "add" ]]; then _error "密码文件 (${passwd_file}) 不存在。"; fi
    case "$action" in
        view) _info "--- WebDAV 用户列表 ---"; cut -d: -f1 "${passwd_file}" | sed 's/^/  /' || _warn "密码文件为空。";;
        add)
            if [[ -z "$username" ]]; then read -r -p "请输入要添加的用户名: " username; fi;
            if ! [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]]; then _error "用户名包含无效字符。"; fi
            if grep -q "^${username}:" "${passwd_file}" &>/dev/null; then _error "用户 ${username} 已存在！"; fi
            local new_pass; while true; do read -r -s -p "为 ${username} 设置密码: " new_pass; echo; read -r -s -p "确认密码: " confirm_pass; echo; if [[ "$new_pass" == "$confirm_pass" && -n "$new_pass" ]]; then break; else _warn "密码为空或不匹配。"; fi; done
            local htpasswd_opts="-b"; if ! [ -s "$passwd_file" ]; then _info "密码文件不存在或为空，将使用 -c 参数创建。"; htpasswd_opts="-cb"; fi
            if htpasswd ${htpasswd_opts} "${passwd_file}" "${username}" "${new_pass}"; then _info "用户 ${username} 已添加，拥有完全访问权限。"; else _error "添加用户 ${username} 失败。"; fi;;
        passwd)
            if [[ -z "$username" ]]; then read -r -p "请输入要修改密码的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if ! grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            local new_pass; while true; do read -r -s -p "为 ${username} 设置新密码: " new_pass; echo; read -r -s -p "确认新密码: " confirm_pass; echo; if [[ "$new_pass" == "$confirm_pass" && -n "$new_pass" ]]; then break; else _warn "密码为空或不匹配。"; fi; done
            if htpasswd -b "${passwd_file}" "${username}" "${new_pass}"; then _info "用户密码已修改。"; else _error "修改密码失败。"; fi;;
        delete)
            if [[ -z "$username" ]]; then read -r -p "请输入要删除的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if ! grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            read -r -p "$(echo -e ${YELLOW}"确定要从密码文件中永久删除 ${username} 吗? (y/n): "${NC})" confirm_del
            if [[ "$confirm_del" =~ ^[Yy] ]]; then if htpasswd -D "${passwd_file}" "${username}"; then _info "用户已从密码文件中删除。"; else _error "从密码文件中删除用户失败。"; fi; else _info "操作已取消。"; fi;;
        *) _error "无效账户操作: ${action}。可用: view, add, passwd, delete" ;;
    esac
}

# --- THOROUGH UNINSTALL FUNCTION ---
do_thorough_uninstall() {
    load_config
    local data_dir="${AWUS_WEBDEV_DIR:-'未配置或未知'}"
    _warn "--- AWUS 彻底卸载程序 (保留数据) ---"
    echo -e "${RED}警告：此操作将执行以下所有步骤："
    echo -e "  - 停止并卸载定制版 Nginx"
    echo -e "  - 删除所有 Nginx 配置 (/etc/nginx) 和日志 (/var/log/nginx)"
    echo -e "  - 删除为域名 ${YELLOW}${AWUS_DOMAIN_NAME:-未知}${NC}${RED} 申请的 SSL 证书"
    echo -e "  - 卸载 Certbot (如果是通过 Snap 安装的)"
    echo -e "  - 移除 AWUS 脚本本身及其配置文件"
    echo -e "  - 尝试清理不再需要的依赖包"
    echo -e "${GREEN}唯一会保留的是您的数据目录：${YELLOW}${data_dir}${NC}"
    echo -e "${RED}此操作不可逆！${NC}"

    if [[ -z "${AWUS_DOMAIN_NAME:-}" ]]; then
        _error "无法从配置文件中读取域名，无法继续。请确保 ${CONFIG_FILE} 存在。"
    fi

    read -r -p "请输入您的域名 (${AWUS_DOMAIN_NAME}) 进行确认以继续: " confirm_domain
    if [[ "$confirm_domain" != "${AWUS_DOMAIN_NAME}" ]]; then
        _error "域名确认不匹配。操作已中止。"
    fi

    _info "正在开始彻底卸载流程..."

    # 1. Stop and disable Nginx
    _info "正在停止并禁用 Nginx 服务..."
    _nginx_ctl "stop"
    systemctl disable nginx &>/dev/null || _warn "禁用 Nginx 服务失败。"

    # 2. Delete SSL Certificate
    if _exists "${CERTBOT_CMD}"; then
        _info "正在为 ${AWUS_DOMAIN_NAME} 删除 SSL 证书..."
        if [ -d "/etc/letsencrypt/live/${AWUS_DOMAIN_NAME}" ]; then
            "${CERTBOT_CMD}" delete --cert-name "${AWUS_DOMAIN_NAME}" --non-interactive || _warn "删除证书失败，可能需要手动处理。"
        else
            _info "未找到 ${AWUS_DOMAIN_NAME} 的证书目录，跳过删除。"
        fi
    fi

    # 3. Uninstall Certbot
    if _exists "snap" && snap list | grep -q 'certbot'; then
        _info "正在通过 Snap 卸载 Certbot..."
        snap remove certbot || _warn "通过 Snap 卸载 Certbot 失败。"
    fi

    # 4. Purge Nginx and remove its directories
    _info "正在使用 'apt-get purge' 彻底卸载 Nginx..."
    _wait_for_apt_lock
    apt-get purge -y nginx-custom-webdav &>/dev/null || _warn "apt-get purge nginx-custom-webdav 失败。"
    _info "正在删除 Nginx 残留目录..."
    rm -rf /etc/nginx /var/log/nginx
    
    # 5. Clean up dependencies
    _info "正在运行 'apt-get autoremove' 来清理不再需要的依赖..."
    _wait_for_apt_lock
    apt-get autoremove --purge -y

    # 6. Remove AWUS script files
    _info "正在移除 AWUS 脚本和配置文件..."
    rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE" "$LOCK_FILE"
    rm -rf "$SCRIPT_INSTALL_DIR"
    
    _info "${GREEN}--- 彻底卸载完成 ---${NC}"
    _info "所有相关组件（除数据外）均已移除。"
    _info "您的数据仍然安全地保存在: ${data_dir}"
}

# --- UNINSTALL WIZARD ---
do_uninstall() {
    load_config; _warn "--- AWUS Nginx WebDAV 卸载向导 ---"
    echo -e "  请选择卸载级别："
    echo -e "  1) ${GREEN}保留式卸载${NC}: 仅移除 AWUS 脚本和 Nginx 站点配置。Nginx 程序、数据和证书将保留。"
    echo -e "  2) ${YELLOW}标准卸载${NC}:   卸载 Nginx 程序和所有配置。数据和证书将保留。"
    echo -e "  3) ${RED}彻底卸载${NC}:   卸载 Nginx、证书、Certbot 及相关依赖。${BOLD}仅保留数据目录。${NC}"
    echo -e "  0) 取消"
    read -r -p "请输入选项 [1, 2, 3, 0]: " choice
    case "$choice" in
        1)
            _warn "这将移除 AWUS 脚本和为 ${AWUS_DOMAIN_NAME:-'your.domain'} 创建的 Nginx 站点配置。"
            read -r -p "$(echo -e ${YELLOW}"确定吗? (y/n): "${NC})" confirm
            if [[ "$confirm" =~ ^[Yy] ]]; then
                if [ -n "${AWUS_DOMAIN_NAME:-}" ]; then rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"; fi
                rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                rm -rf "$SCRIPT_INSTALL_DIR"
                _info "AWUS 配置已移除。建议运行 'nginx -t && systemctl reload nginx'。"
            else
                _info "操作已取消。"
            fi;;
        2)
            _warn "这将彻底卸载 Nginx 程序！您的数据和 SSL 证书不会被删除。"
            read -r -p "$(echo -e ${RED}"确定要完全卸载 Nginx 吗? (y/n): "${NC})" confirm
            if [[ "$confirm" =~ ^[Yy] ]]; then
                if [ -n "${AWUS_DOMAIN_NAME:-}" ]; then rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"; fi
                _nginx_ctl "stop"
                systemctl disable nginx &>/dev/null || true
                _info "正在使用 'apt-get purge' 彻底卸载 Nginx...";
                _wait_for_apt_lock
                apt-get purge -y nginx-custom-webdav && apt-get autoremove -y
                _info "正在移除 Nginx 配置目录..."
                rm -rf /etc/nginx
                _info "正在移除 AWUS 脚本和配置..."
                rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                rm -rf "$SCRIPT_INSTALL_DIR"
                _info "Nginx 已卸载。"
                _warn "WebDAV 数据 (${AWUS_WEBDEV_DIR:-}) 和 SSL 证书 (/etc/letsencrypt/${AWUS_DOMAIN_NAME:-}) 未被删除。"
            else
                _info "操作已取消。"
            fi;;
        3)
            do_thorough_uninstall ;;
        0) _info "操作已取消." ;; *) _warn "无效选项。" ;;
    esac
}

main_menu() {
    load_config; clear; local nginx_status; if ! dpkg -s nginx-custom-webdav &>/dev/null; then nginx_status="${YELLOW}未安装${NC}"; elif systemctl is-active --quiet nginx; then nginx_status="${GREEN}运行中${NC}"; else nginx_status="${YELLOW}已停止${NC}"; fi
    echo -e "
${BLUE}Nginx WebDAV Ultimate Script (AWUS) | v${SCRIPT_VERSION}${NC}
${BLUE}======================================================${NC}
 Nginx 服务状态:  ${nginx_status}
 WebDAV 域名:     ${YELLOW}${AWUS_DOMAIN_NAME:-未配置}${NC}
 WebDAV 目录:     ${YELLOW}${AWUS_WEBDEV_DIR:-未配置}${NC}
${BLUE}------------------------------------------------------${NC}
${GREEN}1.${NC} (重新)安装/配置 WebDAV
${GREEN}2.${NC} ${RED}卸载向导 (提供多种卸载选项)${NC}
${GREEN}3.${NC} 启动 Nginx      ${GREEN}4.${NC} 停止 Nginx      ${GREEN}5.${NC} 重启 Nginx
${GREEN}6.${NC} 查看服务状态和配置信息
${BLUE}------------------ 账户管理 --------------------${NC}
${GREEN}10.${NC} 查看用户      ${GREEN}11.${NC} 添加用户
${GREEN}12.${NC} 修改密码      ${GREEN}13.${NC} 删除用户
${BLUE}------------------------------------------------------${NC}
${GREEN}0.${NC} 退出脚本
"
    read -r -p "请输入选项: " option
    case "$option" in
        0) exit 0 ;;
        1) read -r -p "$(echo -e ${YELLOW}"此操作将引导您完成新的安装或重新配置。(y/n): "${NC})" confirm; if [[ "$confirm" =~ ^[Yy] ]]; then do_install; else _info "操作已取消。"; fi;;
        2) do_uninstall ;;
        3) _nginx_ctl "start" ;;
        4) _nginx_ctl "stop" ;;
        5) _nginx_ctl "restart" ;;
        6) do_status ;;
        10) do_accounts_manage "view" ;;
        11) do_accounts_manage "add" "" ;;
        12) do_accounts_manage "passwd" "" ;;
        13) do_accounts_manage "delete" "" ;;
        *) _warn "无效的选项: $option" ;;
    esac
    if [[ "$option" != "0" ]]; then echo && read -n 1 -s -r -p "按任意键返回主菜单..."; fi
}

# --- Script Entry Point ---
main() {
    check_root
    (
        flock -n 200 || _error "另一个脚本实例正在运行。请等待其完成后再试。"

        case "${1:-}" in
            install)
                do_install
                exit 0
                ;;
            ""|menu)
                if [[ -f "$CONFIG_FILE" ]]; then
                    while true; do main_menu; done
                else
                    _info "欢迎使用 AWUS (Nginx 定制版)!";
                    read -r -p "脚本似乎未安装。是否现在开始交互式安装? (y/n): " choice
                    if [[ "$choice" =~ ^[Yy] ]]; then do_install; else _info "安装已取消。"; fi
                fi
                exit 0;;
            status|uninstall)
                if [ ! -f "$CONFIG_FILE" ]; then _error "AWUS 未安装。请先运行 'install'。"; fi
                "do_$1"
                exit 0
                ;;
            start|stop|restart)
                if [ ! -f "$CONFIG_FILE" ]; then _error "AWUS 未安装。"; fi
                "_nginx_ctl" "$1"
                exit 0
                ;;
            accounts)
                if [ ! -f "$CONFIG_FILE" ]; then _error "AWUS 未安装。"; fi
                shift; do_accounts_manage "$@"
                exit 0
                ;;
            help|-h|--help)
                echo "Nginx WebDAV Ultimate Script (AWUS) v${SCRIPT_VERSION}"
                echo "用法: sudo $(basename "$0") [命令] [参数]"
                echo "无参数运行将进入交互式菜单或安装向导。"; echo
                echo "主要命令:";
                echo "  install          交互式安装或重新配置 WebDAV 服务。"
                echo "  uninstall        启动卸载向导，提供多种卸载选项。"
                echo "  status           显示服务状态和配置信息。"
                echo "  start|stop|restart 控制 Nginx 服务。"
                echo "  accounts <subcommand> [username] 管理用户。"
                exit 0 ;;
            *)
                _error "无效命令: '$1'. 运行 'sudo $(basename "$0") help' 查看用法。"
                ;;
        esac
    ) 200> "$LOCK_FILE"
}

main "$@"
