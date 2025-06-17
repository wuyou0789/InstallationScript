#!/usr/bin/env bash
# ================================================================================
# Nginx WebDAV Ultimate Script (AWUS) - Custom Build Edition
#
# Version: 3.1.1 (Recommended Final)
# Author: wuyou0789 & AI Assistant
# GitHub: https://github.com/wuyou0789/InstallationScript
# License: MIT
# ================================================================================
set -euo pipefail
IFS=$'\n\t'

# --- Global Constants ---
readonly SCRIPT_VERSION="3.1.1-nginx-custom"
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

readonly SCRIPT_INSTALL_DIR="/usr/local/etc/awus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_INSTALL_DIR}/awus.sh"
readonly CONFIG_FILE="${SCRIPT_INSTALL_DIR}/config.conf"
readonly DEFAULT_NGINX_PASSWD_FILE="/etc/nginx/webdav.passwd"
readonly ALIAS_FILE="/etc/profile.d/awus-alias.sh"
readonly LOCK_FILE="/tmp/awus.lock"

# --- Logging Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*"; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*"; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*"; exit 1; }

# --- Prerequisites ---
check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }

_os_check() {
    if ! _exists "lsb_release"; then
        _warn "'lsb_release' 命令未找到，正在安装 lsb-core 用于检测系统。"
        apt-get update && apt-get install -y lsb-core
    fi
    local os_id; os_id=$(lsb_release -is)
    local os_release; os_release=$(lsb_release -rs)
    if [[ "$os_id" == "Ubuntu" || "$os_id" == "Debian" ]]; then
        _info "检测到兼容的操作系统: ${os_id} ${os_release}"
    else
        _error "此脚本仅适用于 Ubuntu/Debian 系统。"
    fi
}

_install_pkgs() {
    _info "正在更新软件包列表..."
    apt-get update || _warn "apt-get update 失败，但将继续安装。"
    _info "正在安装: $*"
    apt-get install -y "$@" || _error "安装失败: $*"
}

# --- Dependencies ---
install_dependencies() {
    _info "检测并安装基础依赖..."
    local pkgs_to_install=""; local htpasswd_pkg="apache2-utils"
    ! _exists "curl" && pkgs_to_install+="curl "
    if ! apt-cache show "$htpasswd_pkg" &>/dev/null; then htpasswd_pkg="apache-utils"; fi
    ! _exists "htpasswd" && pkgs_to_install+="${htpasswd_pkg} "
    if [[ -n "$pkgs_to_install" ]]; then _install_pkgs $pkgs_to_install; fi

    _info "检测 Certbot..."
    if ! _exists "certbot" || ! [[ $(readlink -f $(which certbot) 2>/dev/null) == *"/snap/"* ]]; then
        _warn "将通过 Snap 安装 Certbot..."
        ! _exists "snapd" && _install_pkgs "snapd"
        ! snap list core &>/dev/null && snap install core
        snap refresh core
        dpkg -s certbot &>/dev/null && apt-get remove -y certbot*
        snap install --classic certbot || _error "Certbot Snap 安装失败。"
        ln -sf /snap/bin/certbot /usr/bin/certbot
    else
        _info "Certbot (Snap 版) 已安装"
    fi
    certbot plugins | grep -q 'nginx' || _error "Certbot Nginx 插件不可用！"
}

# --- Nginx Custom ---
install_custom_nginx() {
    _info "检测/安装定制版 Nginx..."
    if dpkg -s nginx-custom-webdav &>/dev/null; then
        _info "定制 Nginx 已安装，跳过。"
        return
    fi
    local deb_url="https://github.com/wuyou0789/InstallationScript/releases/download/v2.0.0-nginx-custom/nginx-custom-webdav_1.28.0-1_amd64.deb"
    local deb_path="/tmp/nginx-custom-webdav.deb"
    curl -L --fail -o "${deb_path}" "${deb_url}" || _error "下载 Nginx 定制包失败。"
    systemctl stop nginx &>/dev/null || true
    apt-get purge -y nginx nginx-common &>/dev/null || true
    dpkg -i "${deb_path}" || ( _warn "dpkg 失败，自动修复依赖..." && apt-get install -f -y )
    rm -f "${deb_path}"
    _info "定制 Nginx 安装完成。"
}

_nginx_ctl() {
    local action="$1"
    _info "正在 ${action} Nginx..."
    systemctl "${action}" nginx || _error "systemctl ${action} nginx 失败。"
    sleep 1
    if [[ "$action" == "start" || "$action" == "restart" ]] && ! systemctl is-active --quiet nginx; then
        _warn "Nginx 在 ${action} 后非活动状态，请检查日志。"
    fi
    _info "Nginx ${action} 完成。"
}

# --- Config & Bootstrapping ---
load_config() { [ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"; }

setup_script_invocation() {
    _info "安装脚本自身以备后用..."
    mkdir -p "$SCRIPT_INSTALL_DIR"
    cp -f "$0" "$SCRIPT_SELF_PATH"; chmod +x "$SCRIPT_SELF_PATH"
    echo "alias webdav='sudo bash ${SCRIPT_SELF_PATH}'" > "$ALIAS_FILE"
    _info "别名 'webdav' 已创建。zsh 用户请参考 ~/.zshrc。"
}

do_status() {
    load_config
    echo -e "${BLUE}\nNginx 服务状态:${NC}"
    systemctl status nginx --no-pager | head -20 || true
    echo -e "${BLUE}\n当前 WebDAV 配置:${NC}"
    echo "  配置文件: $CONFIG_FILE"
    if [ -f "$CONFIG_FILE" ]; then cat "$CONFIG_FILE"; fi
    echo -e "\n${BLUE}已配置用户:${NC}"
    if [ -f "${AWUS_NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}" ]; then
        cut -d: -f1 "${AWUS_NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}" | sed 's/^/  /'
    else
        echo "  (未配置密码文件)"
    fi
    echo -e "${BLUE}\n站点Nginx配置:${NC}"
    [[ -n "${AWUS_DOMAIN_NAME:-}" ]] && nginx -T 2>/dev/null | grep "${AWUS_DOMAIN_NAME}" || true
    echo ""
}

# --- 安装主流程 ---
do_install() {
    local DOMAIN_NAME WEBDEV_DIR NGINX_PASSWD_FILE ADMIN_USER
    trap 'install_cleanup' ERR

    install_cleanup() {
        _warn "\n--- 安装出错，自动清理 ---"; _nginx_ctl "stop" &>/dev/null || true
        if [ -n "${DOMAIN_NAME:-}" ]; then
            _warn "移除 Nginx 配置..."; rm -f "/etc/nginx/sites-enabled/${DOMAIN_NAME}" "/etc/nginx/sites-available/${DOMAIN_NAME}"
            _exists "certbot" && _warn "删除证书..." && certbot delete --cert-name "$DOMAIN_NAME" --non-interactive || true
        fi
        _info "--- 清理完成 ---"
    }
    
    _warn "继续前建议备份 /etc/nginx 目录。"
    read -r -p "继续安装吗? (y/n): " confirm; [[ ! "$confirm" =~ ^[Yy] ]] && _info "安装已取消。" && exit 0

    install_dependencies; install_custom_nginx

    _info "--- Nginx WebDAV 配置向导 ---"
    while true; do
        read -r -p "请输入域名 (如 dav.example.com): " DOMAIN_NAME
        [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && break || _warn "域名无效。"
    done
    local default_dir="/var/www/webdav/${DOMAIN_NAME}"
    read -r -p "输入 WebDAV 数据目录 [${default_dir}]: " WEBDEV_DIR; WEBDEV_DIR=${WEBDEV_DIR:-$default_dir}
    [[ ! "$WEBDEV_DIR" =~ ^/ ]] && _error "路径必须绝对。"
    WEBDEV_DIR=$(realpath -m "$WEBDEV_DIR")
    local default_passwd_file="$DEFAULT_NGINX_PASSWD_FILE"
    read -r -p "输入 WebDAV 密码文件路径 [${default_passwd_file}]: " NGINX_PASSWD_FILE
    NGINX_PASSWD_FILE=${NGINX_PASSWD_FILE:-$default_passwd_file}

    while true; do
        read -r -p "请输入管理员用户名: " ADMIN_USER
        [[ "$ADMIN_USER" =~ ^[a-zA-Z0-9._-]+$ ]] && break || _warn "用户名无效。"
    done

    local ADMIN_PASS
    while true; do
        read -r -s -p "为 ${ADMIN_USER} 设置密码: " ADMIN_PASS; echo
        read -r -s -p "确认密码: " confirm_pass; echo
        [[ "$ADMIN_PASS" == "$confirm_pass" && -n "$ADMIN_PASS" ]] && break || _warn "密码不匹配或为空。"
    done

    _info "准备 Nginx 配置文件..."
    grep -q "dav_ext_lock_zone" /etc/nginx/nginx.conf || sed -i '/^[[:space:]]*http[[:space:]]*{/a \    dav_ext_lock_zone zone=webdav:10m;' /etc/nginx/nginx.conf

    local nginx_vhost_path="/etc/nginx/sites-available/${DOMAIN_NAME}"
    cat <<EOF_VHOST | tee "${nginx_vhost_path}" > /dev/null
server { listen 80; server_name ${DOMAIN_NAME}; root /var/www/html; location /.well-known/acme-challenge/ { allow all; } location / { return 404; }}
EOF_VHOST

    _info "创建目录/密码文件..."
    mkdir -p "${WEBDEV_DIR}"; chown www-data:www-data "${WEBDEV_DIR}"; chmod 775 "${WEBDEV_DIR}"
    touch "${NGINX_PASSWD_FILE}"; chown root:www-data "${NGINX_PASSWD_FILE}"; chmod 640 "${NGINX_PASSWD_FILE}"
    htpasswd -cb "${NGINX_PASSWD_FILE}" "${ADMIN_USER}" "${ADMIN_PASS}" || _error "创建用户失败。"

    _info "启用站点并重启 Nginx..."
    ln -sf "$nginx_vhost_path" "/etc/nginx/sites-enabled/"
    if [ -f /etc/nginx/sites-enabled/default ]; then
        if grep -q "listen 80;" /etc/nginx/sites-enabled/default; then
            _warn "即将删除默认站点(80端口)。"
            rm -f /etc/nginx/sites-enabled/default
        fi
    fi
    nginx -t || _error "Nginx 配置测试失败。"; _nginx_ctl "restart"

    # 证书检测与申请
    if certbot certificates | grep -qE "/live/${DOMAIN_NAME}($|/)" ; then
        _warn "检测到 ${DOMAIN_NAME} 的证书已存在。"
        read -r -p "使用现有证书 [1]，强制重新申请 [2]，中止 [0] : " cert_choice
        case "$cert_choice" in
            1) _info "继续使用现有证书。";;
            2) _info "正在重新申请证书..."; certbot --nginx -d "${DOMAIN_NAME}" --force-renewal --non-interactive --agree-tos || _error "Certbot 失败。";;
            *) _error "操作中止。";;
        esac
    else
        _info "开始申请 SSL 证书..."
        read -r -p "输入Let's Encrypt 邮箱(推荐): " cert_email
        local email_option="--register-unsafely-without-email"
        [[ -n "$cert_email" ]] && email_option="--email ${cert_email}"
        [[ -z "$cert_email" ]] && _warn "未提供邮箱，将无法接收到期通知！"
        certbot --nginx -d "${DOMAIN_NAME}" --non-interactive --agree-tos $email_option || _error "Certbot 获取证书失败。"
    fi

    _info "写入最终 WebDAV Nginx 配置..."
    cat <<EOF_VHOST_FINAL | tee "${nginx_vhost_path}" > /dev/null
server {
    listen 80; listen [::]:80; server_name ${DOMAIN_NAME};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$server_name\$request_uri; }
}
server {
    listen 443 ssl http2; listen [::]:443 ssl http2;
    server_name ${DOMAIN_NAME};
    root ${WEBDEV_DIR};

    access_log /var/log/nginx/${DOMAIN_NAME}.access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}.error.log warn;

    client_max_body_size 0; charset utf-8;

    location ~ /\.(_.*|DS_Store|thumbs\.db)$ { return 403; }

    location / {
        auth_basic "Secure WebDAV";
        auth_basic_user_file ${NGINX_PASSWD_FILE};
        dav_methods PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods PROPFIND OPTIONS LOCK UNLOCK;
        dav_access user:rw group:r all:r;
        create_full_put_path on;
        autoindex on;
        dav_ext_lock zone=webdav;
        more_set_headers "DAV: 1, 2";
    }

    ssl_certificate /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}
EOF_VHOST_FINAL

    _info "再次测试并重启 Nginx..."; nginx -t || _error "Nginx 最终配置测试失败！"; _nginx_ctl "restart"
    
    trap - ERR EXIT; _info "${GREEN}--- Nginx WebDAV 安装和配置成功！ ---${NC}"; _info "WebDAV 地址: https://${DOMAIN_NAME}"
    { echo "AWUS_DOMAIN_NAME=\"${DOMAIN_NAME}\""; echo "AWUS_WEBDEV_DIR=\"${WEBDEV_DIR}\""; echo "AWUS_NGINX_PASSWD_FILE=\"${NGINX_PASSWD_FILE}\""; } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"; setup_script_invocation
}

# --- 用户管理 ---
do_accounts_manage() {
    load_config; local action="$1"; local username="$2"; local passwd_file="${AWUS_NGINX_PASSWD_FILE:-$DEFAULT_NGINX_PASSWD_FILE}"
    [ ! -f "$passwd_file" ] && [[ "$action" != "add" ]] && _error "密码文件(${passwd_file})不存在。"
    case "$action" in
        view) _info "--- 用户列表 ---"; cut -d: -f1 "${passwd_file}" | sed 's/^/  /' || _warn "密码文件为空。";;
        add)
            while :; do
                [ -n "$username" ] || read -r -p "输入新用户名: " username
                [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]] && break || _warn "用户名无效。"
            done
            grep -q "^${username}:" "${passwd_file}" &>/dev/null && _error "用户已存在。"
            local new_pass; while :; do
                read -r -s -p "为 ${username} 设置密码: " new_pass; echo
                read -r -s -p "确认密码: " confirm_pass; echo
                [[ "$new_pass" == "$confirm_pass" && -n "$new_pass" ]] && break || _warn "密码为空或不一致。"
            done
            [ -s "$passwd_file" ] && htpasswd -b "${passwd_file}" "${username}" "${new_pass}" || htpasswd -cb "${passwd_file}" "${username}" "${new_pass}"
            _info "用户 ${username} 已添加。" ;;
        passwd)
            while :; do
                [ -n "$username" ] || read -r -p "输入用户名: " username
                [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]] && break || _warn "用户名无效。"
            done
            grep -q "^${username}:" "${passwd_file}" || _error "用户不存在。"
            local new_pass; while :; do
                read -r -s -p "为 ${username} 设置新密码: " new_pass; echo
                read -r -s -p "确认密码: " confirm_pass; echo
                [[ "$new_pass" == "$confirm_pass" && -n "$new_pass" ]] && break || _warn "密码为空或不一致。"
            done
            htpasswd -b "${passwd_file}" "${username}" "${new_pass}" && _info "密码已更新。" || _error "修改密码失败。" ;;
        delete)
            while :; do
                [ -n "$username" ] || read -r -p "删除用户名: " username
                [[ "$username" =~ ^[a-zA-Z0-9._-]+$ ]] && break || _warn "用户名无效。"
            done
            grep -q "^${username}:" "${passwd_file}" || _error "用户不存在。"
            read -r -p "$(echo -e ${YELLOW}确定删除 ${username}? (y/n):${NC}) " confirm_del
            [[ "$confirm_del" =~ ^[Yy] ]] && ( htpasswd -D "${passwd_file}" "${username}" && _info "已删除。" ) || _info "操作已取消。" ;;
        *) _error "无效操作: $action. 可用: view, add, passwd, delete" ;;
    esac
}

do_uninstall() {
    load_config; _warn "--- AWUS Nginx WebDAV 卸载向导 ---"
    echo -e "  1) 仅移除 AWUS 配置 (保留 Nginx)"; echo -e "  2) ${RED}彻底卸载 Nginx 及所有配置${NC}"; echo -e "  0) 取消"
    read -r -p "请输入选项 [1,2,0]: " choice
    case "$choice" in
        1)
            read -r -p "$(echo -e ${YELLOW}确定移除 AWUS 脚本及配置?(y/n):${NC})" confirm
            [[ "$confirm" =~ ^[Yy] ]] && {
                [ -n "${AWUS_DOMAIN_NAME:-}" ] && rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"
                [ -f "/etc/nginx/conf.d/awus_dav_ext.conf" ] && rm -f "/etc/nginx/conf.d/awus_dav_ext.conf"
                rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                _info "已移除 AWUS 配置。请运行 'nginx -t && systemctl reload nginx'。"
            } ;;
        2)
            read -r -p "$(echo -e ${RED}警告: 将卸载 Nginx！WebDAV数据/证书不会删除(y/n):${NC})" confirm
            [[ "$confirm" =~ ^[Yy] ]] && {
                [ -n "${AWUS_DOMAIN_NAME:-}" ] && rm -f "/etc/nginx/sites-enabled/${AWUS_DOMAIN_NAME}" "/etc/nginx/sites-available/${AWUS_DOMAIN_NAME}"
                [ -f "/etc/nginx/conf.d/awus_dav_ext.conf" ] && rm -f "/etc/nginx/conf.d/awus_dav_ext.conf"
                rm -f "$SCRIPT_SELF_PATH" "$CONFIG_FILE" "$ALIAS_FILE"
                _nginx_ctl "stop"; systemctl disable nginx &>/dev/null || true
                apt-get purge -y nginx-custom-webdav nginx nginx-common && apt-get autoremove -y
                rm -rf /etc/nginx; _info "已卸载 Nginx。"
                _warn "WebDAV 数据(${AWUS_WEBDEV_DIR:-})和证书未删除。"
            } ;;
        0) _info "取消。" ;; *) _warn "无效选项。" ;;
    esac
}

main_menu() {
    load_config; clear; local nginx_status
    if ! dpkg -s nginx-custom-webdav &>/dev/null; then nginx_status="${YELLOW}未安装${NC}"
    elif systemctl is-active --quiet nginx; then nginx_status="${GREEN}运行中${NC}"
    else nginx_status="${YELLOW}已停止${NC}"; fi
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
${GREEN}12.${NC} 修改密码      ${GREEN}13.${NC} 删除用户
${BLUE}------------------------------------------------------${NC}
${GREEN}0.${NC} 退出脚本
"
    read -r -p "请输入选项: " option
    case "$option" in
        0) exit 0 ;;
        1) read -r -p "$(echo -e ${YELLOW}此操作将重装或重新配置 WebDAV (y/n):${NC})" confirm; [[ "$confirm" =~ ^[Yy] ]] && do_install || _info "取消。";;
        2) do_uninstall ;;
        3) _nginx_ctl "start" ;;
        4) _nginx_ctl "stop" ;;
        5) _nginx_ctl "restart" ;;
        6) do_status ;;
        10) do_accounts_manage "view" ;;
        11) do_accounts_manage "add" ;;
        12) do_accounts_manage "passwd" ;;
        13) do_accounts_manage "delete" ;;
        *) _warn "无效选项: $option" ;;
    esac
    if [[ "$option" != "0" ]]; then echo && read -n 1 -s -r -p "按任意键返回主菜单..."; fi
}

# --- Script Entry Point ---
main() {
    check_root
    (
        flock -n 200 || _error "已有脚本实例正在运行，请稍后。"
        _os_check
        case "${1:-}" in
            install)
                read -r -p "$(echo -e ${YELLOW}您要执行安装/重新配置，相关配置将覆盖。\n继续?(y/n):${NC})" confirm
                [[ "$confirm" =~ ^[Yy] ]] && do_install || _info "操作已取消。"
                exit 0 ;;
            status) do_status; exit 0 ;;
            uninstall) do_uninstall; exit 0 ;;
            start|stop|restart) _nginx_ctl "$1"; exit 0 ;;
            accounts) shift; do_accounts_manage "$@"; exit 0 ;;
            help|-h|--help)
                echo "Nginx WebDAV Ultimate Script (AWUS) v${SCRIPT_VERSION}"
                echo "用法: $(basename "$0") [命令]"
                echo "无参数运行进入菜单。"
                echo "可用命令: install, uninstall, status, start, stop, restart, accounts, help"
                exit 0 ;;
            ""|menu) if [[ -f "$CONFIG_FILE" && -f "$SCRIPT_SELF_PATH" ]]; then while true; do main_menu; done
                        else _info "AWUS 未安装。需要立即安装吗? (y/n):"; read -r choice; [[ "$choice" =~ ^[Yy] ]] && do_install || _info "已取消。"
                    fi ;;
            *) _error "无效命令: '$1'。用 help 查看用法。" ;;
        esac
    ) 200> "$LOCK_FILE"
}

main "$@"
