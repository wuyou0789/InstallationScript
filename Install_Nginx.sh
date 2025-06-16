#!/usr/bin/env bash

#================================================================================
# Nginx WebDAV Ultimate Script (AWUS)
#
# Version: 1.3.1 (Final Release Candidate)
# Author: Your Name/GitHub Username & AI Assistant
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
readonly SCRIPT_VERSION="1.3.1-nginx"
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
    ! _exists "certbot" && pkgs_to_install+="certbot python3-certbot-nginx "
    if [[ -n "$pkgs_to_install" ]]; then
        _install_pkgs $pkgs_to_install
    else
        _info "所需核心依赖均已安装。"
    fi
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
    
    local ADMIN_PASS ADMIN_PASS_CONFIRM
    while true; do
        read -s -p "请输入 ${ADMIN_USER} 的密码: " ADMIN_PASS; echo
        read -s -p "请再次输入密码进行确认: " ADMIN_PASS_CONFIRM; echo
        if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ] && [ -n "$ADMIN_PASS" ]; then break; else _warn "密码为空或两次输入的密码不匹配，请重试。"; fi
    done

    _info "正在准备 Nginx 配置文件..."
    local nginx_map_file="/etc/nginx/conf.d/awus_webdav_permissions.conf"
    _info "正在创建权限映射文件: ${nginx_map_file}"
    cat <<EOF_MAP | sudo tee "${nginx_map_file}" > /dev/null
# This file is managed by AWUS script. Do not edit manually.
map \$remote_user \$is_writer {
    default 0;
    # AWUS:START_WRITERS
    ${ADMIN_USER} 1;
    # AWUS:END_WRITERS
}
EOF_MAP

    local nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}"
    _info "正在创建虚拟主机文件: ${nginx_vhost_path}"
    cat <<EOF_VHOST | sudo tee "${nginx_vhost_path}" > /dev/null
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    # listen 443 ssl http2; # Certbot will handle this
    server_name ${DOMAIN_NAME};
    root ${WEBDEV_DIR};
    access_log /var/log/nginx/${DOMAIN_NAME}.access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}.error.log;

    location / {
        auth_basic "Secure WebDAV Access";
        auth_basic_user_file ${NGINX_PASSWD_FILE};

        if (\$request_method ~ ^(PUT|DELETE|MKCOL|COPY|MOVE)$) {
            if (\$is_writer = 0) {
                return 403; # Forbidden for non-writers
            }
        }
        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_access user:rwx group:rwx all:r;
        create_full_put_path on;
        autoindex on;
    }
}
EOF_VHOST

    _info "正在执行系统配置..."
    sudo mkdir -p "${WEBDEV_DIR}" || _error "创建 WebDAV 目录 ${WEBDEV_DIR} 失败。"
    sudo chown www-data:www-data "${WEBDEV_DIR}"
    sudo chmod 775 "${WEBDEV_DIR}"

    sudo touch "${NGINX_PASSWD_FILE}"
    sudo chown root:www-data "${NGINX_PASSWD_FILE}"
    sudo chmod 640 "${NGINX_PASSWD_FILE}"
    sudo htpasswd -cb "${NGINX_PASSWD_FILE}" "${ADMIN_USER}" "${ADMIN_PASS}" || _error "创建管理员用户失败。"

    _info "尝试使用 Certbot 为 ${DOMAIN_NAME} 获取并安装 SSL 证书..."
    read -p "请输入用于 Let's Encrypt 的邮箱 (推荐，用于接收续期提醒): " cert_email
    if [ -n "$cert_email" ]; then
        sudo certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --email "${cert_email}" || _error "Certbot 获取或安装证书失败。"
    else
        _warn "未提供邮箱，将尝试无邮箱注册。您将不会收到证书到期提醒。"
        sudo certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos --register-unsafely-without-email || _error "Certbot 获取或安装证书失败。"
    fi

    _info "启用新站点..."
    sudo ln -sf "/etc/nginx/sites-available/${DOMAIN_NAME}" "/etc/nginx/sites-enabled/"
    sudo rm -f /etc/nginx/sites-enabled/default &>/dev/null

    _info "测试 Nginx 配置..."
    if ! sudo nginx -t; then _error "Nginx 配置测试失败！"; fi

    _info "配置防火墙 (UFW)..."
    if _exists "ufw"; then sudo ufw allow 'Nginx Full'; sudo ufw reload || _warn "UFW reload 失败。"; else _warn "未找到 UFW，请手动配置防火墙。"; fi

    if _nginx_ctl "restart"; then
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
    else
        _error "Nginx 重启失败。安装未完成。"
    fi
}

update_user_permissions() {
    local username="$1"; local permission="$2"; load_config
    if [ -z "$AWUS_NGINX_MAP_FILE" ] || [ ! -f "$AWUS_NGINX_MAP_FILE" ]; then _error "权限映射文件未找到。"; return 1; fi
    local map_file="$AWUS_NGINX_MAP_FILE"

    _info "正在更新用户 ${username} 的权限为 [${permission}]..."
    local user_exists_in_map; sudo grep -q "^\s*${username}\s\+1;" "$map_file" && user_exists_in_map=true || user_exists_in_map=false

    if [[ "$permission" == "write" ]]; then
        if $user_exists_in_map; then _info "用户 ${username} 已拥有写入权限。"; return 0; fi
        sudo sed -i "/# AWUS:END_WRITERS/i \    ${username} 1;" "$map_file"
    elif [[ "$permission" == "readonly" ]]; then
        if $user_exists_in_map; then sudo sed -i "/^\s*${username}\s\+1;/d" "$map_file"; else _info "用户 ${username} 已是只读权限。"; return 0; fi
    else _error "无效的权限级别: ${permission}"; return 1; fi
    
    _info "权限文件已更新，正在测试 Nginx 配置..."
    if ! sudo nginx -t; then _error "Nginx 配置测试失败！请手动检查 ${map_file}。"; return 1; fi
    
    _info "配置测试通过，正在平滑重载 Nginx..."; _nginx_ctl "reload"
}

do_accounts_manage() {
    load_config; local action="$1"; local username="$2"; local passwd_file="${AWUS_NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}"
    if [ ! -f "$passwd_file" ] && [[ "$action" != "add" ]]; then _error "密码文件 (${passwd_file}) 不存在。"; fi

    case "$action" in
        view)
            _info "--- WebDAV 用户列表 (从 ${passwd_file}) ---"
            sudo cat "${passwd_file}" | cut -d: -f1 | sed 's/^/  /' || _warn "密码文件为空。"
            ;;
        add)
            if [[ -z "$username" ]]; then read -p "请输入要添加的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if sudo grep -q "^${username}:" "${passwd_file}" &>/dev/null; then _error "用户 ${username} 已存在！"; fi
            local new_pass; while true; do read -s -p "为 ${username} 设置密码: " new_pass; echo; read -s -p "确认密码: " confirm_pass; echo; if [ "$new_pass" = "$confirm_pass" ] && [ -n "$new_pass" ]; then break; else _warn "密码为空或不匹配。"; fi; done
            local htpasswd_opts="-b"; if [ ! -s "$passwd_file" ]; then htpasswd_opts="-cb"; fi
            if sudo htpasswd ${htpasswd_opts} "${passwd_file}" "${username}" "${new_pass}"; then
                _info "用户 ${username} 已创建 (默认只读)。"
                read -p "是否授予 ${username} 完全写入权限? (yes/no): " grant_perm
                if [[ "$grant_perm" =~ ^[Yy]$ ]]; then update_user_permissions "${username}" "write"; fi
            else _error "添加用户 ${username} 失败。"; fi
            ;;
        passwd)
            if [[ -z "$username" ]]; then read -p "请输入要修改密码的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            local new_pass; while true; do read -s -p "为 ${username} 设置新密码: " new_pass; echo; read -s -p "确认新密码: " confirm_pass; echo; if [ "$new_pass" = "$confirm_pass" ] && [ -n "$new_pass" ]; then break; else _warn "密码为空或不匹配。"; fi; done
            if sudo htpasswd -b "${passwd_file}" "${username}" "${new_pass}"; then _info "用户密码已修改。"; else _error "修改密码失败。"; fi
            ;;
        delete)
            if [[ -z "$username" ]]; then read -p "请输入要删除的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            _info "正在从写入权限组中移除 ${username}..."
            update_user_permissions "${username}" "readonly"
            read -p "确定要从密码文件中永久删除 ${username} 吗? (yes/no): " confirm_del
            if [[ "$confirm_del" == "yes" ]]; then
                if sudo htpasswd -D "${passwd_file}" "${username}"; then _info "用户已从密码文件中删除。"; else _error "从密码文件中删除用户失败。"; fi
            else _info "操作已取消。"; fi
            ;;
        setperm)
            if [[ -z "$username" ]]; then read -p "请输入要设置权限的用户名: " username; fi; if [[ -z "$username" ]]; then _error "用户名不能为空。"; fi
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            echo "为用户 [${username}] 选择权限级别:"; echo "  1) 完全访问 (读/写)"; echo "  2) 只读"; echo "  0) 取消"
            read -p "请输入选项 [1, 2, 0]: " perm_choice
            case "$perm_choice" in 1) update_user_permissions "${username}" "write" ;; 2) update_user_permissions "${username}" "readonly" ;; 0) _info "操作已取消。" ;; *) _warn "无效选项。" ;; esac
            ;;
        *) _error "无效账户操作: ${action}。可用: view, add, passwd, delete, setperm" ;;
    esac
}

# (The functions `do_uninstall` and `main_menu` are very similar to the previous version,
# with text changed from Apache to Nginx. They are included here for completeness.)
do_uninstall() {
    load_config; _warn "--- AWUS Nginx WebDAV 卸载向导 ---"
    echo "1) 仅移除 AWUS 配置 (保留 Nginx)"; echo "2) ${RED}彻底卸载 Nginx 及所有配置${NC}"; echo "0) 取消"
    read -p "请输入选项 [1, 2, 0]: " choice
    case "$choice" in
        1)
            read -p "确定要移除 AWUS 脚本和 Nginx 站点配置吗? (yes/no): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                if [ -n "$AWUS_DOMAIN_NAME" ]; then sudo rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"; fi
                [ -n "$AWUS_NGINX_MAP_FILE" ] && sudo rm -f "$AWUS_NGINX_MAP_FILE"
                sudo rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                _info "AWUS 配置已移除。建议运行 'sudo nginx -t && sudo systemctl reload nginx'。"
            fi
            ;;
        2)
            read -p "$(echo -e ${RED}"警告：这将完全卸载 Nginx！数据目录不会被删除。(yes/no): "${NC})" confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                if [ -n "$AWUS_DOMAIN_NAME" ]; then sudo rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"; fi
                [ -n "$AWUS_NGINX_MAP_FILE" ] && sudo rm -f "$AWUS_NGINX_MAP_FILE"
                sudo rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                _nginx_ctl "stop" && sudo systemctl disable nginx &>/dev/null
                _info "正在使用 'apt-get purge' 彻底卸载 Nginx..."
                sudo apt-get purge -y nginx nginx-common && sudo apt-get autoremove -y
                sudo rm -rf /etc/nginx
                _info "Nginx 已卸载。"
                # The show_post_uninstall_message function should also be adapted for Nginx
                _warn "WebDAV 数据 (${AWUS_WEBDEV_DIR}) 和 SSL 证书 (${AWUS_DOMAIN_NAME}) 未被删除。"
            fi
            ;;
        0) _info "操作已取消." ;; *) _warn "无效选项。" ;;
    esac
}

main_menu() {
    load_config; clear; local nginx_status
    if ! _exists "nginx"; then nginx_status="${YELLOW}未安装${NC}"; elif systemctl is-active --quiet nginx; then nginx_status="${GREEN}运行中${NC}"; elif systemctl is-failed --quiet nginx; then nginx_status="${RED}失败状态${NC}"; else nginx_status="${YELLOW}已停止${NC}"; fi
    echo -e "
${BLUE}Nginx WebDAV Ultimate Script (AWUS) | v${SCRIPT_VERSION}${NC}
${BLUE}======================================================${NC}
 Nginx 服务状态:  ${nginx_status}
 WebDAV 域名:     ${YELLOW}${AWUS_DOMAIN_NAME:-未配置}${NC}
 WebDAV 目录:     ${YELLOW}${AWUS_WEBDEV_DIR:-未配置}${NC}
${BLUE}------------------------------------------------------${NC}
${GREEN}1.${NC} (重新)安装/配置 WebDAV
${GREEN}2.${NC} ${RED}卸载向导 (移除配置或彻底卸载Nginx)${NC}
${GREEN}3.${NC} 启动 Nginx      ${GREEN}4.${NC} 停止 Nginx      ${GREEN}5.${NC} 重启 Nginx
${GREEN}6.${NC} 查看服务状态和配置信息
${BLUE}------------------ 账户管理 --------------------${NC}
${GREEN}10.${NC} 查看用户      ${GREEN}11.${NC} 添加用户
${GREEN}12.${NC} 修改密码      ${GREEN}13.${NC} 删除用户      ${GREEN}14.${NC} ${YELLOW}设置权限${NC}
${BLUE}------------------------------------------------------${NC}
${GREEN}0.${NC} 退出脚本
"
    read -rp "请输入选项: " option
    case "$option" in
        0) exit 0 ;;
        1) do_install ;;
        2) do_uninstall ;;
        3) _nginx_ctl "start" ;;
        4) _nginx_ctl "stop" ;;
        5) _nginx_ctl "restart" ;;
        6) do_status ;;
        10) do_accounts_manage "view" ;;
        11) do_accounts_manage "add" "" ;;
        12) do_accounts_manage "passwd" "" ;;
        13) do_accounts_manage "delete" "" ;;
        14) do_accounts_manage "setperm" "" ;;
        *) _warn "无效的选项: $option" ;;
    esac
    if [[ "$option" != "0" ]]; then echo && read -n 1 -s -r -p "按任意键返回主菜单..."; fi
}

# --- Script Entry Point ---
main() {
    check_root
    _os_check

    # If a specific command is given, execute it and exit.
    case "$1" in
        install|uninstall|status)
            "do_$1" # Dynamic function call
            exit 0
            ;;
        accounts)
            shift; do_accounts_manage "$@"; exit 0
            ;;
        start|stop|restart)
            "_nginx_ctl" "$1"; exit 0
            ;;
    esac

    # If no command is given, proceed with interactive logic.
    if [[ -f "$SCRIPT_SELF_PATH" && -f "$CONFIG_FILE" ]]; then
        # If installed, show menu.
        while true; do main_menu; done
    else
        # If not installed, prompt to install.
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
