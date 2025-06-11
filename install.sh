#!/usr/bin/env bash

# Xray Simplified Script (XUS)
#
# Version: 1.1.0
# Author: AI Assistant
# Inspired by: User's requirements and the robust zxcvos/Xray-script
#
# This script combines robust, professional features with ultimate simplicity.
# It installs and manages ONE specific setup: VLESS-XTLS-uTLS-REALITY.
# No bloat, no confusing options. Just the best, simplified.
# New in 1.1.0: Added automatic kernel parameter tuning for better performance.

# --- Script Environment ---
set -o pipefail
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
readonly SCRIPT_VERSION="1.1.0"
# IMPORTANT: For the updater to work, create a file named 'version.txt' in your
# GitHub repo with just the version number (e.g., "1.1.0").
readonly VERSION_CHECK_URL="https://raw.githubusercontent.com/YourUsername/YourRepo/main/version.txt"
readonly SCRIPT_URL="https://raw.githubusercontent.com/YourUsername/YourRepo/main/install.sh"

# --- Color Codes ---
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# --- Configuration Paths ---
readonly SCRIPT_DIR="/usr/local/etc/xus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_DIR}/menu.sh"
readonly XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"
readonly XRAY_BIN_PATH="/usr/local/bin/xray"
readonly ALIAS_FILE="/etc/profile.d/xus-alias.sh"

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*"; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*"; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*"; exit 1; }

# --- Prerequisite and Utility Functions ---

check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }
_os() {
    [[ -f "/etc/debian_version" ]] && source /etc/os-release && echo "$ID" && return
    [[ -f "/etc/redhat-release" ]] && echo "centos" && return
}

_install() {
    _info "正在安装软件包: $*"
    case "$(_os)" in
    centos) _exists "dnf" && dnf install -y "$@" || yum install -y "$@";;
    ubuntu|debian) apt-get update && apt-get install -y "$@";;
    *) _error "不支持的操作系统，请手动安装: $*";;
    esac
}

install_dependencies() {
    local pkgs_to_install=""
    ! _exists "curl" && pkgs_to_install+="curl "
    ! _exists "jq" && pkgs_to_install+="jq "
    ! _exists "openssl" && pkgs_to_install+="openssl "
    ! _exists "qrencode" && pkgs_to_install+="qrencode "
    if [[ -n "$pkgs_to_install" ]]; then
        _install $pkgs_to_install
    else
        _info "所需依赖均已安装。"
    fi
}

_systemctl() {
    local action="$1"
    _info "正在 ${action} Xray 服务..."
    systemctl "${action}" xray &>/dev/null
    sleep 1
    if ! systemctl is-active --quiet xray && [[ "$action" != "stop" ]]; then
        _warn "Xray 服务操作后状态异常，请检查日志！"
    else
        _info "Xray 服务 ${action} 完成。"
    fi
}

# --- Advanced Features Inspired by Professional Scripts ---

# Checks for new script version on GitHub
check_script_version() {
    local remote_version
    remote_version=$(curl -sL "${VERSION_CHECK_URL}")
    if [[ -z "$remote_version" ]]; then
        _warn "无法检查脚本更新，请确认网络或更新链接。"
        return
    fi
    if [[ "$remote_version" != "$SCRIPT_VERSION" ]]; then
        _warn "发现新版脚本 (v${remote_version})。当前版本: v${SCRIPT_VERSION}"
        read -p "是否立即下载并更新? [Y/n]: " choice
        if [[ -z "$choice" || "$choice" =~ ^[Yy]$ ]]; then
            if ! wget -O "$SCRIPT_SELF_PATH.tmp" "$SCRIPT_URL"; then
                _error "下载新脚本失败！"
            fi
            mv "$SCRIPT_SELF_PATH.tmp" "$SCRIPT_SELF_PATH"
            chmod +x "$SCRIPT_SELF_PATH"
            _info "脚本已更新，请重新运行 'xs'。"
            exit 0
        fi
    fi
}

# Validates that the fallback domain supports what REALITY needs
validate_dest_domain() {
    local prompt="请输入一个真实存在、可访问的【国外】域名作为回落地址 (例如: www.apple.com):"
    local new_dest
    while true; do
        read -p "$prompt " new_dest
        [[ -z "$new_dest" ]] && new_dest="www.apple.com" && _info "使用默认域名: www.apple.com"

        _info "正在严格验证域名 ${new_dest} 对 REALITY 的支持..."
        if echo "QUIT" | openssl s_client -connect "${new_dest}:443" -tls1_3 -servername "${new_dest}" 2>&1 | grep -q "X25519"; then
            _info "域名 ${new_dest} 验证通过！"
            break
        else
            prompt="${RED}域名 ${new_dest} 验证失败 (不支持TLSv1.3或REALITY所需加密套件)，请更换一个域名:${NC}"
        fi
    done
    echo "$new_dest"
}

# Automatically tunes kernel parameters for better network performance
tune_kernel() {
    _info "正在优化内核网络参数..."
    cat >/etc/sysctl.d/99-xus.conf <<EOF
fs.file-max = 1024000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p /etc/sysctl.d/99-xus.conf >/dev/null 2>&1
}


# --- Core Logic ---

install_xray_core() {
    _info "正在使用官方脚本安装/更新 Xray-core..."
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root; then
        _info "Xray-core 安装成功。"
    else
        _error "Xray-core 安装失败，请检查网络或官方脚本输出。"
    fi
}

generate_xray_config() {
    _info "--- 开始 Xray 配置向导 ---"
    read -p "请输入 Xray 监听端口 (1-65535, 默认 443): " xray_port
    [[ -z "$xray_port" ]] && xray_port=443
    local fallback_dest=$(validate_dest_domain)
    read -p "请输入自定义 UUID (留空将自动生成): " client_uuid
    [[ -z "$client_uuid" ]] && client_uuid=$($XRAY_BIN_PATH uuid)

    local keys=$($XRAY_BIN_PATH x25519)
    local private_key=$(echo "$keys" | awk '/Private key/ {print $3}')
    local short_id=$(openssl rand -hex 8)

    _info "正在创建配置文件: ${XRAY_CONFIG_FILE}"
    mkdir -p /usr/local/etc/xray

    jq -n \
      --argjson port "$xray_port" --arg uuid "$client_uuid" --arg p_key "$private_key" \
      --arg s_id "$short_id" --arg dest "$fallback_dest" \
      '{
        "log": {"loglevel": "warning"},
        "routing": {
          "domainStrategy": "AsIs",
          "rules": [
            {"type": "field", "outboundTag": "block", "ip": ["geoip:cn"], "ruleTag": "block-cn-ip"},
            {"type": "field", "outboundTag": "block", "domain": ["geosite:cn"], "ruleTag": "block-cn-domain"},
            {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"], "ruleTag": "block-bittorrent"},
            {"type": "field", "outboundTag": "block", "ip": ["geoip:private"], "ruleTag": "block-private-ip"}
          ]
        },
        "inbounds": [{
          "listen": "0.0.0.0", "port": $port, "protocol": "vless",
          "settings": {"clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
          "streamSettings": {
            "network": "tcp", "security": "reality",
            "realitySettings": {
              "show": false, "dest": ($dest + ":443"), "xver": 0,
              "serverNames": [$dest], "privateKey": $p_key, "shortIds": [$s_id]
            }
          },
          "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]
      }' > "$XRAY_CONFIG_FILE" || _error "使用 jq 生成配置文件失败。"
    
    _info "配置文件生成成功。"
}

show_client_config() {
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件不存在！" && return
    
    local server_ip=$(curl -s4 ip.sb || curl -s4 icanhazip.com || echo "<你的服务器IP>")
    
    local config_data=$(jq -r '[
        .inbounds[0].port, .inbounds[0].settings.clients[0].id, .inbounds[0].streamSettings.realitySettings.privateKey,
        .inbounds[0].streamSettings.realitySettings.serverNames[0], .inbounds[0].streamSettings.realitySettings.shortIds[0]
    ] | @tsv' "$XRAY_CONFIG_FILE")
    read -r xray_port uuid private_key sni short_id <<< "$config_data"
    
    local public_key=$($XRAY_BIN_PATH x25519 -i "${private_key}" | awk '/Public key/ {print $3}')
    local vless_link="vless://${uuid}@${server_ip}:${xray_port}?security=reality&encryption=none&pbk=${public_key}&host=${sni}&fp=chrome&sid=${short_id}&type=tcp&flow=xtls-rprx-vision&sni=${sni}#XUS_REALITY_$(hostname)"

    clear
    _info "Xray 配置信息"
    echo -e "
  地址 (Address)   : ${YELLOW}${server_ip}${NC}
  端口 (Port)      : ${YELLOW}${xray_port}${NC}
  用户 ID (UUID)   : ${YELLOW}${uuid}${NC}
  公钥 (PublicKey) : ${YELLOW}${public_key}${NC}
  短ID (ShortId)   : ${YELLOW}${short_id}${NC}
  域名 (SNI/Host)  : ${YELLOW}${sni}${NC}

${BLUE}---------------- 分享链接 ----------------${NC}
${vless_link}
${BLUE}---------------- 二维码 ------------------${NC}"

    _exists "qrencode" && qrencode -t ANSIUTF8 -m 1 "${vless_link}" || \
    _warn "未找到 qrencode, 无法生成二维码。请运行 'apt install qrencode' 或 'yum install qrencode'。"
    
    echo -e "${BLUE}-------------------------------------------${NC}"
}

# --- Installation & Menu Logic ---

do_install() {
    check_root
    install_dependencies
    tune_kernel # Apply kernel optimizations
    mkdir -p "$SCRIPT_DIR"
    install_xray_core
    generate_xray_config

    cp -f "$0" "$SCRIPT_SELF_PATH"
    chmod +x "$SCRIPT_SELF_PATH"
    echo "alias xs='bash ${SCRIPT_SELF_PATH}'" > "$ALIAS_FILE"

    systemctl daemon-reload
    systemctl enable xray &>/dev/null
    _systemctl "restart"

    show_client_config
}

do_uninstall() {
    check_root
    read -p "$(echo -e ${YELLOW}"确定要完全卸载 Xray 和本脚本吗? (y/n): "${NC})" choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        _systemctl "stop"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        rm -rf "$SCRIPT_DIR" "$XRAY_CONFIG_FILE" "$ALIAS_FILE" "/etc/sysctl.d/99-xus.conf"
        _info "Xray 已成功卸载。"
        _warn "请执行 'source /etc/profile' 或重新登录以移除 'xs' 命令。"
    else
        _info "卸载操作已取消。"
    fi
}

main_menu() {
    clear
    local xray_status
    systemctl is-active --quiet xray && xray_status="${GREEN}运行中${NC}" || xray_status="${RED}已停止${NC}"

    echo -e "
${BLUE}Xray Ultimate Simplified Script (xs) | v${SCRIPT_VERSION}${NC}
${BLUE}===================================================${NC}
 Xray 状态: ${xray_status}
 Xray 版本: $(_exists xray && xray --version | head -n1 | awk '{print $2}' || echo "${RED}未安装${NC}")
 配置文件:  $([[ -f "$XRAY_CONFIG_FILE" ]] && echo "${GREEN}存在${NC}" || echo "${RED}不存在${NC}")
${BLUE}---------------------------------------------------${NC}
${GREEN}1.${NC}  完整安装 (覆盖当前配置)
${GREEN}2.${NC}  ${RED}卸载 Xray 和本脚本${NC}
${GREEN}3.${NC}  检查脚本更新

${GREEN}4.${NC}  启动 Xray      ${GREEN}5.${NC}  停止 Xray      ${GREEN}6.${NC}  重启 Xray
${BLUE}----------------- 配置管理 ------------------${NC}
${GREEN}101.${NC} 查看配置 / 分享链接
${GREEN}102.${NC} 查看实时日志
${GREEN}103.${NC} 修改用户 ID (UUID)
${GREEN}104.${NC} 修改回落域名 (dest/sni)
${GREEN}105.${NC} 更新 Xray 内核至最新版
${BLUE}---------------------------------------------------${NC}
${GREEN}0.${NC}  退出脚本
"
    read -rp "请输入选项: " option

    case "$option" in
    0) exit 0 ;;
    1) do_install ;;
    2) do_uninstall ;;
    3) check_script_version ;;
    4) _systemctl "start" ;;
    5) _systemctl "stop" ;;
    6) _systemctl "restart" ;;
    101) show_client_config ;;
    102) journalctl -u xray -f --no-pager ;;
    103)
        read -p "请输入新 UUID (留空自动生成): " new_uuid
        [[ -z "$new_uuid" ]] && new_uuid=$($XRAY_BIN_PATH uuid)
        jq ".inbounds[0].settings.clients[0].id = \"$new_uuid\"" "$XRAY_CONFIG_FILE" >tmp.json && mv tmp.json "$XRAY_CONFIG_FILE"
        _systemctl "restart" && show_client_config
        ;;
    104)
        local new_dest=$(validate_dest_domain)
        jq ".inbounds[0].streamSettings.realitySettings.dest = \"${new_dest}:443\" | .inbounds[0].streamSettings.realitySettings.serverNames = [\"$new_dest\"]" "$XRAY_CONFIG_FILE" >tmp.json && mv tmp.json "$XRAY_CONFIG_FILE"
        _systemctl "restart" && show_client_config
        ;;
    105) install_xray_core && _systemctl "restart" ;;
    *) _warn "无效的选项。" ;;
    esac
    echo && read -n 1 -s -r -p "按任意键返回主菜单..."
}

# --- Script Entry Point ---
if [[ "$1" == "install" ]]; then
    do_install
else
    check_root
    if [[ ! -f "$XRAY_CONFIG_FILE" ]]; then
      _warn "未找到 Xray 配置文件。"
      read -p "是否立即开始安装? (y/n): " choice
      [[ "$choice" =~ ^[Yy]$ ]] && do_install
      exit 0
    fi
    while true; do main_menu; done
fi
