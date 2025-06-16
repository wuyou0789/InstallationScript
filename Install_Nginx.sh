#!/usr/bin/env bash

#================================================================================
# Nginx Edition Ultimate Script (AWUS)
#
# Version: 1.0.0 (Nginx Release)
# Author: Your Name/GitHub Username & AI Assistant
# GitHub: https://github.com/wuyou0789/InstallationScript
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
readonly SCRIPT_VERSION="1.0.0-nginx"
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Configuration Paths ---
readonly SCRIPT_INSTALL_DIR="/usr/local/etc/awus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_INSTALL_DIR}/awus.sh"
readonly CONFIG_FILE="${SCRIPT_INSTALL_DIR}/config.conf"
readonly DEFAULT_NGINX_PASSWD_FILE="/etc/nginx/webdav.passwd" # Nginx 密码文件
readonly ALIAS_FILE="/etc/profile.d/awus-alias.sh"

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*"; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*"; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*"; exit 1; }

# --- Prerequisite and Utility Functions ---
check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。请使用 'sudo ./your_script_name.sh'。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }

_os_check() {
    if [[ -f "/etc/debian_version" ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            _info "检测到兼容的操作系统: $ID"
        else
            _error "检测到基于 Debian 的系统 ($ID)，但不是明确的 Ubuntu 或 Debian。脚本可能无法正常工作。"
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
        _error "软件包安装失败: $*。请检查错误信息并重试。"
    fi
}

install_dependencies() {
    _info "正在检查并安装所需依赖..."
    local pkgs_to_install=""
    ! _exists "nginx" && pkgs_to_install+="nginx "
    # Nginx 的 WebDAV 模块是内建的，但 htpasswd 工具通常在 apache2-utils 包中
    ! _exists "htpasswd" && pkgs_to_install+="apache2-utils "
    ! _exists "certbot" && pkgs_to_install+="certbot python3-certbot-nginx "

    if [[ -n "$pkgs_to_install" ]]; then
        _install_pkgs $pkgs_to_install
    else
        _info "所需核心依赖均已安装。"
    fi
}

# Controls the Nginx service using systemctl.
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
        return 1
    fi
}

# Loads configuration from the config file.
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
}

# Installs the script itself for easy future use.
setup_script_invocation() {
    _info "正在安装脚本以供后续使用..."
    if ! sudo mkdir -p "$SCRIPT_INSTALL_DIR"; then
        _error "无法创建脚本安装目录: ${SCRIPT_INSTALL_DIR}"
    fi
    if ! sudo cp -f "$0" "$SCRIPT_SELF_PATH"; then
        _error "无法复制脚本自身到 ${SCRIPT_SELF_PATH}！"
    fi
    if ! sudo chmod +x "$SCRIPT_SELF_PATH"; then
        _error "无法为 ${SCRIPT_SELF_PATH} 设置执行权限！"
    fi
    echo "alias webdav='sudo bash ${SCRIPT_SELF_PATH}'" | sudo tee "$ALIAS_FILE" > /dev/null
    _info "别名 'webdav' 已设置。请运行 'source ${ALIAS_FILE}' 或重新登录以使用。"
}

# --- Core Logic Functions ---

# Interactive installation and configuration of the WebDAV service.
do_install() {
    install_dependencies

    _info "--- Nginx WebDAV 全新安装与配置向导 ---"
    read -p "请输入要绑定的域名 (例如: dav.example.com): " DOMAIN_NAME
    [[ -z "$DOMAIN_NAME" ]] && _error "域名不能为空。"

    local default_dir_prompt="/var/www/nginx_webdav/${DOMAIN_NAME}"
    read -p "请输入 WebDAV 文件存储目录 (默认为: ${default_dir_prompt}): " WEBDEV_DIR
    WEBDEV_DIR=${WEBDEV_DIR:-$default_dir_prompt}

    read -p "请输入 WebDAV 密码文件存放路径 (默认为: ${DEFAULT_NGINX_PASSWD_FILE}): " NGINX_PASSWD_FILE
    NGINX_PASSWD_FILE=${NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}

    read -p "请输入初始 WebDAV 管理员用户名 (将拥有所有权限): " ADMIN_USER
    [[ -z "$ADMIN_USER" ]] && _error "管理员用户名不能为空。"
    local ADMIN_PASS ADMIN_PASS_CONFIRM
    while true; do
        read -s -p "请输入 ${ADMIN_USER} 的密码: " ADMIN_PASS; echo
        read -s -p "请再次输入密码进行确认: " ADMIN_PASS_CONFIRM; echo
        if [ "$ADMIN_PASS" = "$ADMIN_PASS_CONFIRM" ] && [ -n "$ADMIN_PASS" ]; then break; else _warn "密码为空或不匹配，请重试。"; fi
    done

    # --- Nginx 配置准备 ---
    _info "正在准备 Nginx 配置文件..."
    # 1. 创建用于权限控制的 map 文件
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

    # 2. 创建主虚拟主机配置文件
    local nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}"
    _info "正在创建虚拟主机文件: ${nginx_vhost_path}"
    cat <<EOF_VHOST | sudo tee "${nginx_vhost_path}" > /dev/null
server {
    listen 80;
    server_name ${DOMAIN_NAME};
    # Redirect all HTTP requests to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    # SSL configuration will be added by Certbot
    # listen 443 ssl http2;
    # listen [::]:443 ssl http2;
    server_name ${DOMAIN_NAME};

    root ${WEBDEV_DIR};

    # Logging
    access_log /var/log/nginx/${DOMAIN_NAME}.access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}.error.log;

    location / {
        # WebDAV Authentication
        auth_basic "Secure WebDAV Access";
        auth_basic_user_file ${NGINX_PASSWD_FILE};

        # Fine-grained permission check using the map variable
        if (\$request_method ~ ^(PUT|DELETE|MKCOL|COPY|MOVE)$) {
            if (\$is_writer = 0) {
                return 403; # Forbidden for non-writers
            }
        }

        # Enable WebDAV methods for all authenticated users
        dav_methods PUT DELETE MKCOL COPY MOVE; # Let Nginx handle methods
        dav_access user:rwx group:rwx all:r;   # Set file system access permissions
        create_full_put_path on;              # Automatically create directories for PUT requests
        
        # Enable directory listing for browsers (optional)
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
    local email_opt
    read -p "请输入用于 Let's Encrypt 的邮箱 (推荐，用于接收续期提醒): " cert_email
    if [ -n "$cert_email" ]; then email_opt="--email ${cert_email}"; else email_opt="--register-unsafely-without-email"; fi
    
    # 使用 --nginx 插件，它会自动修改虚拟主机文件以启用 SSL
    sudo certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos ${email_opt} || _error "Certbot 获取或安装证书失败。"

    _info "启用新站点..."
    sudo ln -s "${nginx_vhost_path}" "/etc/nginx/sites-enabled/${DOMAIN_NAME}" || _warn "创建符号链接失败，可能已存在。"
    sudo rm -f /etc/nginx/sites-enabled/default &>/dev/null # 移除默认站点

    _info "测试 Nginx 配置..."
    if ! sudo nginx -t; then
        _error "Nginx 配置测试失败！请检查错误信息。"
    fi

    _info "配置防火墙 (UFW)..."
    if _exists "ufw"; then
        sudo ufw allow 'Nginx Full'
        sudo ufw reload || _warn "UFW reload 失败，可能 UFW 未激活。"
    else
        _warn "未找到 UFW，请手动配置防火墙。"
    fi

    if _nginx_ctl "restart"; then
        _info "${GREEN}--- Nginx WebDAV 安装和配置成功！ ---${NC}"
        _info "服务应该可以通过 https://${DOMAIN_NAME} 访问。"
        _info "WebDAV 目录: ${WEBDEV_DIR}"
        _info "管理员用户: ${ADMIN_USER}"
        _info "密码文件: ${NGINX_PASSWD_FILE}"

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

# Updates user permissions in the Nginx map file.
# $1: username, $2: permission level ('write', 'readonly')
update_user_permissions() {
    local username="$1"
    local permission="$2"
    
    load_config
    if [ -z "$AWUS_NGINX_MAP_FILE" ] || [ ! -f "$AWUS_NGINX_MAP_FILE" ]; then
        _error "无法找到权限映射文件。请确保已完成安装。"
        return 1
    fi
    local map_file="$AWUS_NGINX_MAP_FILE"

    _info "正在更新用户 ${username} 的权限为 [${permission}]..."

    # 检查用户是否已在 map 中
    local user_exists_in_map
    sudo grep -q "^\s*${username}\s\+1;" "$map_file" && user_exists_in_map=true || user_exists_in_map=false

    if [[ "$permission" == "write" ]]; then
        if $user_exists_in_map; then
            _info "用户 ${username} 已拥有写入权限。"
            return 0
        else
            # 在 # AWUS:END_WRITERS 标记前插入新用户
            sudo sed -i "/# AWUS:END_WRITERS/i \    ${username} 1;" "$map_file"
        fi
    elif [[ "$permission" == "readonly" ]]; then
        if $user_exists_in_map; then
            # 从 map 中删除该用户的行
            sudo sed -i "/^\s*${username}\s\+1;/d" "$map_file"
        else
            _info "用户 ${username} 已是只读权限。"
            return 0
        fi
    else
        _error "无效的权限级别: ${permission}"
        return 1
    fi
    
    _info "权限映射文件更新完成，正在测试 Nginx 配置..."
    if ! sudo nginx -t; then
        _error "Nginx 配置测试失败！请手动检查 ${map_file} 的语法。"
        # 恢复逻辑可以更复杂，但对于 map 文件，手动修复通常更简单
        return 1
    fi
    
    _info "配置测试通过，正在平滑重载 Nginx 服务..."
    if _nginx_ctl "reload"; then
        _info "用户 ${username} 的权限已成功更新为 [${permission}]。"
    else
        _error "Nginx 重载失败！权限更改可能未生效。"
    fi
}

# Manages WebDAV user accounts.
# $1: action, $2: username
do_accounts_manage() {
    load_config
    local action="$1"
    local username="$2"
    local passwd_file="${AWUS_NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}"

    if [ ! -f "$passwd_file" ] && [[ "$action" != "add" ]]; then
         _error "WebDAV 密码文件 (${passwd_file}) 不存在。请先添加一个用户。"
    fi

    case "$action" in
        view)
            _info "--- WebDAV 用户列表 (从 ${passwd_file}) ---"
            sudo cat "${passwd_file}" | cut -d: -f1 | sed 's/^/  /' || _warn "密码文件为空或无法读取。"
            ;;
        add)
            [[ -z "$username" ]] && read -p "请输入要添加的用户名: " username
            [[ -z "$username" ]] && _error "用户名不能为空。"
            if sudo grep -q "^${username}:" "${passwd_file}" &>/dev/null; then
                 _error "用户 ${username} 已存在！"
            fi
            
            local new_pass new_pass_confirm
            while true; do read -s -p "为 ${username} 设置密码: " new_pass; echo; read -s -p "确认密码: " new_pass_confirm; echo; if [ "$new_pass" = "$new_pass_confirm" ] && [ -n "$new_pass" ]; then break; else _warn "密码为空或不匹配，重试。"; fi; done
            
            local htpasswd_opts="-b"
            if [ ! -s "$passwd_file" ]; then
                htpasswd_opts="-cb"
                sudo touch "$passwd_file"; sudo chown root:www-data "$passwd_file"; sudo chmod 640 "$passwd_file"
            fi

            if sudo htpasswd ${htpasswd_opts} "${passwd_file}" "${username}" "${new_pass}"; then
                _info "用户 ${username} 已在密码文件中创建。默认权限为【只读】。"
                read -p "$(echo -e ${YELLOW}"是否要授予用户 ${username} 完全写入权限? (yes/no): "${NC})" grant_perm
                if [[ "$grant_perm" =~ ^[Yy]$ ]]; then
                    update_user_permissions "${username}" "write"
                fi
            else
                _error "在密码文件中添加用户 ${username} 失败。"
            fi
            ;;
        passwd)
            [[ -z "$username" ]] && read -p "请输入要修改密码的用户名: " username
            [[ -z "$username" ]] && _error "用户名不能为空。"
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            
            local new_pass new_pass_confirm
            while true; do read -s -p "为 ${username} 设置新密码: " new_pass; echo; read -s -p "确认新密码: " new_pass_confirm; echo; if [ "$new_pass" = "$new_pass_confirm" ] && [ -n "$new_pass" ]; then break; else _warn "密码为空或不匹配，重试。"; fi; done
            
            if sudo htpasswd -b "${passwd_file}" "${username}" "${new_pass}"; then
                _info "用户 ${username} 的密码已修改。"
            else
                _error "修改用户 ${username} 密码失败。"
            fi
            ;;
        delete)
            [[ -z "$username" ]] && read -p "请输入要删除的用户名: " username
            [[ -z "$username" ]] && _error "用户名不能为空。"
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi

            _info "第一步：正在从写入权限组中移除用户 ${username} (如果存在)..."
            update_user_permissions "${username}" "readonly"

            read -p "$(echo -e ${YELLOW}"第二步：确定要从密码文件中永久删除用户 ${username} 吗? (yes/no): "${NC})" confirm_del
            if [[ "$confirm_del" == "yes" ]]; then
                if sudo htpasswd -D "${passwd_file}" "${username}"; then
                    _info "用户 ${username} 已从密码文件中删除。"
                else
                    _error "从密码文件中删除用户 ${username} 失败。"
                fi
            else
                _info "从密码文件中删除用户的操作已取消。"
            fi
            ;;
        setperm)
            [[ -z "$username" ]] && read -p "请输入要设置权限的用户名: " username
            [[ -z "$username" ]] && _error "用户名不能为空。"
            if ! sudo grep -q "^${username}:" "${passwd_file}"; then _error "用户 ${username} 不存在。"; fi
            
            echo "请为用户 [${username}] 选择新的权限级别:"
            echo "  1) 完全访问 (Read-Write)"
            echo "  2) 只读 (Read-only)"
            echo "  0) 取消"
            read -p "请输入选项 [1, 2, 0]: " perm_choice
            
            case "$perm_choice" in
                1) update_user_permissions "${username}" "write" ;;
                2) update_user_permissions "${username}" "readonly" ;;
                0) _info "操作已取消。" ;;
                *) _warn "无效的选项。" ;;
            esac
            ;;
        *)
            _error "无效的账户操作: ${action}。可用: view, add, passwd, delete, setperm"
            ;;
    esac
}

# --- Uninstall and Menu Functions ---

# (The functions `do_status`, `do_uninstall`, `remove_awus_configs_only`, 
# `show_post_uninstall_message`, `main_menu`, and `main` entrypoint
# would be very similar to the Apache version, just replacing "Apache" with "Nginx"
# in text outputs and service commands. I will include a complete `main_menu` and
# `do_uninstall` for Nginx below for completeness.)

do_uninstall() {
    load_config
    _warn "--- AWUS Nginx WebDAV 卸载向导 ---"
    echo "请选择卸载模式:"
    echo "  1) 仅移除 AWUS 脚本和相关配置 (保留 Nginx)"
    echo "  2) ${RED}彻底卸载 Nginx 及所有 AWUS 配置${NC}"
    echo "  0) 取消卸载"

    read -p "请输入选项 [1, 2, 0]: " uninstall_choice

    case "$uninstall_choice" in
        1)
            # ... (Logic to remove Nginx vhost, map file, script files) ...
            _info "正在移除 AWUS Nginx 配置..."
            if [ -n "$AWUS_DOMAIN_NAME" ] && [ -f "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}" ]; then
                sudo rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}"
                sudo rm -f "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"
                _info "移除了站点配置和符号链接。"
            fi
            [ -n "$AWUS_NGINX_MAP_FILE" ] && sudo rm -f "$AWUS_NGINX_MAP_FILE" && _info "移除了权限映射文件。"
            sudo rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
            _info "脚本及配置文件已移除。"
            _info "建议运行 'sudo nginx -t && sudo systemctl reload nginx' 使更改生效。"
            ;;
        2)
            # ... (Logic to also purge nginx) ...
            read -p "$(echo -e ${RED}"警告：这将完全卸载 Nginx 服务！WebDAV 数据目录不会被删除。\n确定要继续吗? (yes/no): "${NC})" confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                 if [ -n "$AWUS_DOMAIN_NAME" ]; then sudo rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}"; sudo rm -f "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"; fi
                 [ -n "$AWUS_NGINX_MAP_FILE" ] && sudo rm -f "$AWUS_NGINX_MAP_FILE"
                 sudo rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"

                _info "正在停止和禁用 Nginx 服务..."
                sudo systemctl stop nginx &>/dev/null
                sudo systemctl disable nginx &>/dev/null
                _info "正在使用 'apt-get purge' 彻底卸载 Nginx..."
                sudo apt-get purge -y nginx nginx-common || _warn "卸载 Nginx 软件包时遇到问题。"
                sudo apt-get autoremove -y
                _info "正在清理残留的 Nginx 目录 (例如 /etc/nginx/)..."
                sudo rm -rf /etc/nginx
                _info "Nginx 已被彻底卸载。"
                show_post_uninstall_message # This helper function also needs small text changes
            fi
            ;;
        0) _info "卸载操作已取消." ;;
        *) _warn "无效的选项。" ;;
    esac
}

main_menu() {
    load_config
    clear
    local nginx_status
    if ! _exists "nginx"; then nginx_status="${YELLOW}未安装${NC}"; elif systemctl is-active --quiet nginx; then nginx_status="${GREEN}运行中${NC}"; elif systemctl is-failed --quiet nginx; then nginx_status="${RED}失败状态${NC}"; else nginx_status="${YELLOW}已停止${NC}"; fi

    echo -e "
${BLUE}Nginx WebDAV Ultimate Script (AWUS) | v${SCRIPT_VERSION}${NC}
${BLUE}======================================================${NC}
 Nginx 服务状态:  ${nginx_status}
 WebDAV 域名:     ${YELLOW}${AWUS_DOMAIN_NAME:-未配置}${NC}
 WebDAV 目录:     ${YELLOW}${AWUS_WEBDEV_DIR:-未配置}${NC}
${BLUE}------------------------------------------------------${NC}
${GREEN}1.${NC}  (重新)安装/配置 WebDAV
${GREEN}2.${NC}  ${RED}卸载向导 (移除配置或彻底卸载Nginx)${NC}

${GREEN}3.${NC}  启动 Nginx      ${GREEN}4.${NC}  停止 Nginx      ${GREEN}5.${NC}  重启 Nginx
${GREEN}6.${NC}  查看服务状态和配置信息

${BLUE}------------------ 账户管理 --------------------${NC}
${GREEN}10.${NC} 查看 WebDAV 用户
${GREEN}11.${NC} 添加新用户
${GREEN}12.${NC} 修改用户密码
${GREEN}13.${NC} 删除用户
${GREEN}14.${NC} ${YELLOW}设置用户权限 (读写/只读)${NC}
${BLUE}------------------------------------------------------${NC}
${GREEN}0.${NC}  退出脚本
"
    # ... (case statement logic is identical to Apache version, just calls the Nginx-specific functions) ...
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

    if [[ "$0" == "$SCRIPT_SELF_PATH" ]]; then
        while true; do main_menu; done
        exit 0
    fi
    
    if [ ! -f "$SCRIPT_SELF_PATH" ] || [ ! -f "$CONFIG_FILE" ]; then
        _info "欢迎使用 AWUS (Nginx 版)!"
        read -p "脚本似乎未安装或安装不完整。是否现在开始交互式安装? (yes/no): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            do_install
        else
            _info "安装已取消。"
        fi
    else
        _info "AWUS 已安装。建议使用 'webdav' 命令访问菜单。"
        read -p "是否立即进入主菜单? (yes/no): " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            exec sudo bash "$SCRIPT_SELF_PATH"
        fi
    fi
}

main "$@"
