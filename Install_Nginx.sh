#!/usr/bin/env bash

#================================================================================
# Nginx WebDAV Ultimate Script (AWUS)
#
# Version: 1.4.0 (Final Polished Version)
# Author: wuyou0789 & AI Assistant
# GitHub: https://github.com/wuyou0789/InstallationScript (示例链接)
# License: MIT
#
# Description:
# This script installs, configures, and manages a secure, high-performance
# Nginx WebDAV service with user permissions and SSL encryption (via Let's Encrypt)
# on Ubuntu/Debian systems. It is designed to be run directly on the server.
#================================================================================

# --- Script Environment ---
set -o pipefail # Exit on pipe error if a command in a pipeline fails.

# --- Global Constants ---
readonly SCRIPT_VERSION="1.4.0-nginx"
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Configuration Paths ---
readonly SCRIPT_INSTALL_DIR="/usr/local/etc/awus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_INSTALL_DIR}/awus.sh"
readonly CONFIG_FILE="${SCRIPT_INSTALL_DIR}/config.conf"
readonly DEFAULT_NGINX_PASSWD_FILE="/etc/nginx/webdav.passwd"
readonly ALIAS_FILE="/etc/profile.d/awus-alias.sh"

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*"; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*"; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*"; exit 1; }

# --- Prerequisite and Utility Functions ---
check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。请使用 'sudo'。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }

_os_check() {
    if [[ -f "/etc/debian_version" ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            _info "检测到兼容的操作系统: $ID"
        else
            _error "检测到基于 Debian 的系统 ($ID)，但不是明确的 Ubuntu 或 Debian。"
        fi
    else
        _error "此脚本目前仅为 Ubuntu/Debian 系统设计和测试。"
    fi
}

_install_pkgs() {
    _info "正在更新软件包列表 (apt-get update)..."
    if ! sudo apt-get update; then
        _warn "apt-get update 失败，但仍将尝试安装软件包。"
    fi
    _info "正在安装软件包: $*"
    if ! sudo apt-get install -y "$@"; then
        _error "软件包安装失败: $*。"
    fi
}

install_dependencies() {
    _info "正在检查并安装所需依赖..."
    local pkgs_to_install=""
    ! _exists "nginx" && pkgs_to_install+="nginx "
    ! _exists "htpasswd" && pkgs_to_install+="apache2-utils "
    
    if [[ -n "$pkgs_to_install" ]]; then
        _install_pkgs $pkgs_to_install
    fi

    _info "正在检查并安装 Certbot..."
    if ! _exists "certbot" || ! [[ $(readlink -f $(which certbot) 2>/dev/null) == *"/snap/"* ]]; then
        if ! _exists "certbot"; then
            _info "未找到 Certbot。将使用 Snap 进行安装 (现代 Ubuntu/Debian 推荐方式)..."
        else
            _warn "检测到不推荐的 Certbot 版本 (可能通过 APT 安装)。"
            _info "正在自动移除旧版本并使用 Snap 重新安装以确保功能完整..."
        fi
        
        if ! _exists "snap"; then _install_pkgs "snapd"; fi
        sudo snap install core &>/dev/null; sudo snap refresh core &>/dev/null
        
        _info "正在清理任何可能冲突的旧 Certbot (APT) 包..."
        sudo apt-get remove -y certbot* python3-certbot-* &>/dev/null
        sudo apt-get autoremove -y &>/dev/null

        _info "正在通过 Snap 安装 Certbot..."
        sudo snap install --classic certbot || _error "通过 snap 安装 Certbot 失败。"
        sudo ln -sf /snap/bin/certbot /usr/bin/certbot || _warn "创建 certbot 符号链接失败。"
        _info "Certbot 已通过 Snap 成功安装。"
    else
        _info "检测到已正确安装的 Certbot (Snap 版本)。"
    fi
    
    if ! sudo certbot plugins | grep -q 'nginx'; then
        _error "Certbot Nginx 插件不可用！请检查 Certbot 和 Snap 安装。"
    fi
    _info "Certbot 及 Nginx 插件已准备就绪。"
}


_nginx_ctl() {
    local action="$1"
    _info "正在 ${action} Nginx 服务..."
    if sudo systemctl "${action}" nginx; then
        sleep 1
        if [[ "$action" == "start" || "$action" == "restart" || "$action" == "reload" ]]; then
            if ! systemctl is-active --quiet nginx; then
                _warn "Nginx 服务在 ${action} 后状态为【非活动】，请检查日志！"
                return 1
            fi
        fi
        _info "Nginx 服务 ${action} 完成。"
        return 0
    else
        _error "执行 systemctl ${action} nginx 失败。"
    fi
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

setup_script_invocation() {
    _info "正在安装脚本以供后续使用..."
    if ! sudo mkdir -p "$SCRIPT_INSTALL_DIR"; then _error "无法创建脚本安装目录: ${SCRIPT_INSTALL_DIR}"; fi
    if ! sudo cp -f "$0" "$SCRIPT_SELF_PATH"; then _error "无法复制脚本自身到 ${SCRIPT_SELF_PATH}！"; fi
    if ! sudo chmod +x "$SCRIPT_SELF_PATH"; then _error "无法为 ${SCRIPT_SELF_PATH} 设置执行权限！"; fi
    echo "alias webdav='sudo bash ${SCRIPT_SELF_PATH}'" | sudo tee "$ALIAS_FILE" > /dev/null
    _info "别名 'webdav' 已设置。请运行 'source ${ALIAS_FILE}' 或重新登录以使用。"
}

# --- Core Logic Functions ---

do_install() {
    local DOMAIN_NAME WEBDEV_DIR NGINX_PASSWD_FILE ADMIN_USER ADMIN_PASS
    local nginx_map_file nginx_vhost_path
    
    # This trap ensures that if any command fails, the cleanup function is called.
    trap 'install_cleanup' ERR

    install_cleanup() {
        # This function is only called if the install script fails.
        _warn "\n--- 安装过程中发生错误，正在执行自动清理... ---"
        _nginx_ctl "stop" &>/dev/null
        
        if [ -n "$DOMAIN_NAME" ]; then
            _warn "移除为 ${DOMAIN_NAME} 创建的 Nginx 配置..."
            sudo rm -f "/etc/nginx/sites-enabled/${DOMAIN_NAME}"
            sudo rm -f "/etc/nginx/sites-available/${DOMAIN_NAME}"
        fi
        [ -n "$nginx_map_file" ] && sudo rm -f "$nginx_map_file"
        [ -n "$NGINX_PASSWD_FILE" ] && sudo rm -f "$NGINX_PASSWD_FILE"
        
        if [ -n "$DOMAIN_NAME" ] && _exists "certbot" && sudo certbot certificates -d "$DOMAIN_NAME" &>/dev/null; then
             _warn "删除为 ${DOMAIN_NAME} 创建的 SSL 证书..."
             sudo certbot delete --cert-name "$DOMAIN_NAME" --non-interactive
        fi
        _info "--- 清理完成 ---"
    }

    install_dependencies

    _info "--- Nginx WebDAV 全新安装与配置向导 ---"
    read -p "请输入要绑定的域名 (例如: dav.example.com): " DOMAIN_NAME
    if [[ -z "$DOMAIN_NAME" ]]; then _error "域名不能为空。"; fi

    local default_dir_prompt="/var/www/nginx_webdav/${DOMAIN_NAME}"
    read -p "请输入 WebDAV 文件存储目录 (默认为: ${default_dir_prompt}): " WEBDEV_DIR
    WEBDEV_DIR=${WEBDEV_DIR:-$default_dir_prompt}

    read -p "请输入 WebDAV 密码文件存放路径 (默认为: ${DEFAULT_NGINX_PASSWD_FILE}): " NGINX_PASSWD_FILE
    NGINX_PASSWD_FILE=${NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}

    read -p "请输入初始 WebDAV 管理员用户名 (将拥有所有权限): " ADMIN_USER
    if [[ -z "$ADMIN_USER" ]]; then _error "管理员用户名不能为空。"; fi
    
    while true; do
        read -s -p "请输入 ${ADMIN_USER} 的密码: " ADMIN_PASS; echo
        read -s -p "请再次输入密码进行确认: " ADMIN_PASS_CONFIRM; echo
        if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ] && [ -n "$ADMIN_PASS" ]; then break; else _warn "密码为空或不匹配，请重试。"; fi
    done

    # --- Start creating configurations ---
    _info "正在准备 Nginx 配置文件..."
    nginx_map_file="/etc/nginx/conf.d/awus_webdav_permissions.conf"
    cat <<EOF_MAP | sudo tee "${nginx_map_file}" > /dev/null
map \$remote_user \$is_writer {
    default 0;
    # AWUS:START_WRITERS
    ${ADMIN_USER} 1;
    # AWUS:END_WRITERS
}
EOF_MAP
    
    nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}"
    cat <<EOF_VHOST | sudo tee "${nginx_vhost_path}" > /dev/null
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    root ${WEBDEV_DIR};
    access_log /var/log/nginx/${DOMAIN_NAME}.access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}.error.log;

    client_max_body_size 0; # Allow large file uploads

    location / {
        auth_basic "Secure WebDAV Access";
        auth_basic_user_file ${NGINX_PASSWD_FILE};

        # This block combines permission checks into a single 'if'
        # It creates a key like "PUT-0" (for a non-writer trying a write method)
        # and then matches against it.
        set \$permission_key "\${request_method}-\${is_writer}";
        if (\$permission_key ~* ^(PUT|DELETE|MKCOL|COPY|MOVE)-0$) {
            return 403; # Forbidden
        }

        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_access user:rw group:rw all:r;
        create_full_put_path on;
        autoindex on;
    }
}
EOF_VHOST

    _info "正在执行系统配置..."
    sudo mkdir -p "${WEBDEV_DIR}" || _error "创建 WebDAV 目录失败。"
    sudo chown www-data:www-data "${WEBDEV_DIR}" && sudo chmod 775 "${WEBDEV_DIR}"
    sudo touch "${NGINX_PASSWD_FILE}" && sudo chown root:www-data "${NGINX_PASSWD_FILE}" && sudo chmod 640 "${NGINX_PASSWD_FILE}"
    sudo htpasswd -cb "${NGINX_PASSWD_FILE}" "${ADMIN_USER}" "${ADMIN_PASS}" || _error "创建管理员用户失败。"

    _info "正在启用新站点，以便 Certbot 可以找到它..."
    sudo ln -sf "$nginx_vhost_path" "/etc/nginx/sites-enabled/"
    sudo rm -f /etc/nginx/sites-enabled/default &>/dev/null
    
    _info "初步测试并启动 Nginx..."
    sudo nginx -t || _error "Nginx 配置测试失败。"
    # Use a more robust stop-then-start sequence
    _nginx_ctl "stop" &>/dev/null # Ignore error if already stopped
    _nginx_ctl "start" || _error "Nginx 启动失败。"

    _info "尝试使用 Certbot 为 ${DOMAIN_NAME} 获取并安装 SSL 证书..."
    read -p "请输入用于 Let's Encrypt 的邮箱 (推荐): " cert_email
    if [ -n "$cert_email" ]; then
        sudo certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --email "${cert_email}" --redirect || _error "Certbot 获取或安装证书失败。"
    else
        _warn "未提供邮箱，将尝试无邮箱注册。"
        sudo certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --register-unsafely-without-email --redirect || _error "Certbot 获取或安装证书失败。"
    fi
    
    _info "最终测试并重启 Nginx..."
    sudo nginx -t || _error "Certbot 修改后，Nginx 配置测试失败！"
    _nginx_ctl "restart" || _error "Nginx 最终重启失败。"

    _info "配置防火墙 (UFW)..."
    if _exists "ufw"; then sudo ufw allow 'Nginx Full'; sudo ufw reload || _warn "UFW reload 失败。"; fi

    # --- Success! Disable the cleanup trap. ---
    trap - ERR

    _info "${GREEN}--- Nginx WebDAV 安装和配置成功！ ---${NC}"
    _info "服务应该可以通过 https://${DOMAIN_NAME} 访问。"
    
    sudo mkdir -p "$SCRIPT_INSTALL_DIR"
    {
        echo "AWUS_DOMAIN_NAME=\"${DOMAIN_NAME}\""
        echo "AWUS_WEBDEV_DIR=\"${WEBDEV_DIR}\""
        echo "AWUS_ADMIN_USER=\"${ADMIN_USER}\""
        echo "AWUS_NGINX_PASSWD_FILE=\"${NGINX_PASSWD_FILE}\""
        echo "AWUS_NGINX_MAP_FILE=\"${nginx_map_file}\""
    } | sudo tee "$CONFIG_FILE" > /dev/null
    sudo chmod 600 "$CONFIG_FILE"
    _info "安装配置已保存到 ${CONFIG_FILE}"
    setup_script_invocation
}

# (The functions `do_status`, `do_accounts_manage`, `update_user_permissions`, `do_uninstall`, `main_menu`
# are the same as the previous Nginx version. They are robust and ready.
# For brevity in this final response, I am omitting them, but they should be
# included in the final script file from our last iteration.)

# --- OMITTED FUNCTIONS FOR BREVITY (use previous versions) ---
# do_status() { ... }
# update_user_permissions() { ... }
# do_accounts_manage() { ... }
# do_uninstall() { ... }
# main_menu() { ... }
# -------------------------------------------------------------

# --- Script Entry Point ---
main() {
    check_root
    _os_check

    # Prioritize direct command-line arguments
    case "$1" in
        install)
            read -p "$(echo -e ${YELLOW}"您正在尝试执行安装/重新配置。\n如果已存在 AWUS 配置，相关文件可能会被覆盖。\n确定要继续吗? (yes/no): "${NC})" confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                do_install
            else
                _info "操作已取消。"
            fi
            exit 0
            ;;
        status|uninstall|start|stop|restart)
            # For commands that need an existing installation
            if [ ! -f "$CONFIG_FILE" ]; then
                _error "AWUS 未安装。请先运行 'install' 命令。"
            fi
            if [[ "$1" == "status" || "$1" == "uninstall" ]]; then
                "do_$1"
            else
                "_nginx_ctl" "$1"
            fi
            exit 0
            ;;
        accounts)
            if [ ! -f "$CONFIG_FILE" ]; then _error "AWUS 未安装。"; fi
            shift; do_accounts_manage "$@"; exit 0
            ;;
        help|-h|--help)
            echo "Nginx WebDAV Ultimate Script (AWUS) v${SCRIPT_VERSION}"
            echo "用法: $(basename "$0") [命令] [参数]"
            echo "无参数运行将进入交互式菜单或安装向导。"
            echo "主要命令:"
            echo "  install          交互式安装或重新配置 WebDAV 服务。"
            echo "  uninstall        卸载 AWUS 配置或 Nginx 服务。"
            echo "  status           显示服务状态和配置信息。"
            echo "  start|stop|restart 控制 Nginx 服务。"
            echo "  accounts <subcommand> [username]"
            echo "                   管理 WebDAV 用户 (subcommands: view, add, passwd, delete, setperm)。"
            exit 0
            ;;
    esac

    # If no command is given, proceed with interactive logic
    if [[ -f "$SCRIPT_SELF_PATH" && -f "$CONFIG_FILE" ]]; then
        while true; do main_menu; done
    else
        _info "欢迎使用 AWUS (Nginx 版)!"
        _warn "脚本似乎未安装或安装不完整。"
        read -p "是否现在开始交互式安装? (yes/no): " first_run_choice
        if [[ "$first_run_choice" =~ ^[Yy]$ ]]; then
            do_install
        else
            _info "安装已取消。"
        fi
    fi
}

main "$@"
