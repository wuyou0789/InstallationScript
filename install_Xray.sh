#!/usr/bin/env bash

#================================================================================
# Xray Ultimate Simplified Script (XUS)
#
# Version: 1.7.1 (Enhanced Reinstall & Robustness)
# Author: AI Assistant & wuyou0789
# GitHub: (Host this on your own GitHub repository)
#
# This script installs and manages one specific setup: VLESS-XTLS-uTLS-REALITY.
# Designed to be invoked via a one-liner that handles download, execution, and cleanup.
# New in 1.7.2: Improved robustness for reinstall, input validation, and explicit confirmation.
#================================================================================

# --- Script Environment ---
# set -e # Uncomment for stricter error checking during development
set -o pipefail
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
readonly SCRIPT_VERSION="1.7.1"
# TODO: Replace with your actual URLs if using self-update
readonly SCRIPT_URL="https://raw.githubusercontent.com/YourUsername/YourRepo/main/install_Xray.sh" # Example
readonly VERSION_CHECK_URL="https://raw.githubusercontent.com/YourUsername/YourRepo/main/version.txt" # Example

# --- Color Codes ---
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Configuration Paths ---
readonly SCRIPT_DIR="/usr/local/etc/xus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_DIR}/menu.sh"
readonly PREFS_FILE="${SCRIPT_DIR}/user_prefs.conf"
readonly XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"
readonly XRAY_BIN_PATH="/usr/local/bin/xray"
readonly ALIAS_FILE="/etc/profile.d/xus-alias.sh"
readonly XRAY_TEMP_CONFIG_FILE="/tmp/xray_config_tmp.json" # For safer config updates

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*" >&2; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*" >&2; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*" >&2; exit 1; }

# --- Prerequisite and Utility Functions ---

check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }
_os() {
    # Enhanced OS detection
    if [[ -f "/etc/os-release" ]]; then
        source /etc/os-release
        echo "$ID"
    elif [[ -f "/etc/redhat-release" ]]; then
        echo "centos" # Older CentOS might not have os-release
    elif [[ -f "/etc/debian_version" ]]; then
        echo "debian" # Fallback for very old Debian/Ubuntu
    else
        # If no specific file found, try lsb_release if available
        if _exists "lsb_release"; then
            lsb_release -is | tr '[:upper:]' '[:lower:]' # Get ID and lowercase it
        else
            _error "无法识别的操作系统。"
        fi
    fi
}


_install_pkgs() {
    local os_type
    os_type=$(_os) # Get OS type
    [[ -z "$os_type" ]] && _error "无法确定操作系统类型，无法安装软件包。" # Exit if _os failed

    _info "在 ${os_type} 上安装软件包: $*"
    case "$os_type" in
    centos|rhel|almalinux|rocky|fedora) # Added fedora
        _exists "dnf" && dnf install -y "$@" || yum install -y "$@"
        ;;
    ubuntu|debian)
        # Run apt-get update only if needed (e.g., once per script run or if cache is old)
        # For simplicity here, we run it before install if packages are to be installed.
        # A more advanced script might track last update time.
        apt-get update -qq && apt-get install -yqq "$@"
        ;;
    *) _error "不支持的操作系统 ($os_type)，请手动安装: $*";;
    esac || _error "软件包安装失败: $*"
}

install_dependencies() {
    _info "正在检查和安装依赖..."
    local pkgs_to_install=()
    ! _exists "curl" && pkgs_to_install+=("curl")
    ! _exists "jq" && pkgs_to_install+=("jq")
    ! _exists "openssl" && pkgs_to_install+=("openssl") # Usually 'openssl' binary or package providing it
    ! _exists "qrencode" && pkgs_to_install+=("qrencode")
    ! _exists "timeout" && pkgs_to_install+=("coreutils") # for timeout command

    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then
        _install_pkgs "${pkgs_to_install[@]}"
    else
        _info "所需依赖均已安装。"
    fi
}

_systemctl() {
    local action="$1"
    local service_name="xray"
    local output
    _info "正在 ${action} ${service_name} 服务..."

    output=$(systemctl "${action}" "${service_name}" 2>&1)
    local status=$?
    sleep 1

    if [[ "$action" == "stop" || "$action" == "disable" ]]; then
        if [[ $status -ne 0 ]]; then
             _warn "${service_name} 服务 ${action} 操作本身失败。Systemctl 输出: ${output}"
        elif systemctl is-active --quiet "$service_name"; then
             _warn "${service_name} 服务 ${action} 后仍处于活动状态。请检查。"
        else
            _info "${service_name} 服务 ${action} 完成。"
        fi
    else
        if ! systemctl is-active --quiet "$service_name"; then
            _warn "${service_name} 服务 ${action} 后状态异常。Systemctl 输出: ${output}"
            _warn "请使用 'journalctl -u ${service_name} -e --no-pager' 查看详细日志。"
        else
            _info "${service_name} 服务 ${action} 完成。"
        fi
    fi

    if [[ "$action" == "enable" ]] && [[ $status -eq 0 ]]; then
        systemctl daemon-reload &>/dev/null
    fi
    return $status
}


validate_dest_domain() {
    local prompt="请输入一个真实存在、可访问的【国外】域名作为回落目标 (例如: www.apple.com):"
    local new_dest
    while true; do
        read -p "$prompt " new_dest
        [[ -z "$new_dest" ]] && new_dest="www.apple.com" && _info "使用默认域名: www.apple.com"

        _info "正在严格验证域名 ${new_dest} 对 REALITY 的支持 (超时10秒)..."
        local timeout_cmd="timeout 10"
        ! _exists "timeout" && timeout_cmd="" && _warn "timeout 命令未找到，验证可能在无响应时挂起。"

        if echo "QUIT" | ${timeout_cmd} openssl s_client -connect "${new_dest}:443" -tls1_3 -servername "${new_dest}" 2>&1 | grep -q "X25519"; then
            _info "域名 ${new_dest} 验证通过！"
            break
        else
            prompt="${RED}域名 ${new_dest} 验证失败 (不支持TLSv1.3或REALITY所需加密套件，或连接超时)，请更换一个域名:${NC}"
        fi
    done
    echo "$new_dest"
}

# --- Core Logic ---

install_xray_core() {
    _info "正在使用官方脚本安装/更新 Xray-core..."
    if bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root --without-service; then
        _info "Xray-core 官方脚本执行完毕。"
        if ! _exists "$XRAY_BIN_PATH"; then
            _error "Xray-core 安装后未找到可执行文件于 ${XRAY_BIN_PATH}。请检查官方脚本输出。"
        fi
        if [[ ! -x "$XRAY_BIN_PATH" ]]; then
            _error "Xray-core 文件 ${XRAY_BIN_PATH} 安装后不可执行。"
        fi
        _info "Xray-core 验证通过 ($($XRAY_BIN_PATH version | head -n1))."
    else
        _error "Xray-core 安装/更新失败，请检查网络或官方脚本输出。"
    fi
}

generate_xray_config() {
    _info "--- 开始 Xray 配置向导 ---"
    
    local xray_port client_uuid fallback_target private_key short_id client_uuid_val keys_val
    
    while true; do
        read -p "请输入 Xray 监听端口 (1-65535, 默认 443): " xray_port
        [[ -z "$xray_port" ]] && xray_port=443
        if [[ "$xray_port" =~ ^[0-9]+$ ]] && [ "$xray_port" -ge 1 ] && [ "$xray_port" -le 65535 ]; then
            break
        else
            _warn "端口号 '${xray_port}' 无效。请输入1-65535之间的数字。"
        fi
    done

    fallback_target=$(validate_dest_domain)
    
    if ! _exists "$XRAY_BIN_PATH"; then
      _warn "Xray 可执行文件未找到，尝试安装/更新核心..."
      install_xray_core
    fi

    read -p "请输入自定义 UUID (留空将自动生成): " client_uuid
    if [[ -z "$client_uuid" ]]; then
        client_uuid_val=$($XRAY_BIN_PATH uuid)
        if [[ -z "$client_uuid_val" ]]; then _error "无法使用 Xray 生成 UUID。Xray是否正确安装并可执行？"; fi
        client_uuid="$client_uuid_val"
        _info "已自动生成 UUID: ${client_uuid}"
    else
        if ! [[ "$client_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
            _warn "输入的 UUID 格式似乎不正确，但仍会使用。"
        fi
    fi

    keys_val=$($XRAY_BIN_PATH x25519)
    if [[ -z "$keys_val" ]]; then _error "无法使用 Xray 生成密钥对。Xray是否正确安装并可执行？"; fi
    
    private_key=$(echo "$keys_val" | awk '/Private key/ {print $3}')
    if [[ -z "$private_key" ]]; then _error "从 Xray 输出中提取私钥失败。"; fi
    
    short_id=$(openssl rand -hex 8)

    _info "正在创建配置文件内容..."
    mkdir -p "$(dirname "$XRAY_CONFIG_FILE")"

    jq -n \
      --argjson port "$xray_port" --arg uuid "$client_uuid" --arg p_key "$private_key" \
      --arg s_id "$short_id" --arg target_domain "$fallback_target" \
      '{
        "log": {"loglevel": "warning"},
        "inbounds": [{
          "listen": "0.0.0.0", "port": $port, "protocol": "vless",
          "settings": {"clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
          "streamSettings": {
            "network": "raw", "security": "reality",
            "realitySettings": {
              "show": false, "dest": ($target_domain + ":443"), "xver": 0,
              "serverNames": [$target_domain], "privateKey": $p_key, "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 60000, "shortIds": [$s_id]
            }
          },
          "sniffing": {"enabled": true, "destOverride": ["http", "tls", "fakedns"]}
        }],
        "outbounds": [
          {"protocol": "freedom", "tag": "direct"},
          {"protocol": "blackhole", "tag": "block"}
        ],
        "routing": {
          "domainStrategy": "AsIs",
          "rules": [
            {"type": "field", "outboundTag": "block", "ip": ["geoip:cn"], "ruleTag": "block-cn-ip"},
            {"type": "field", "outboundTag": "block", "domain": ["geosite:cn"], "ruleTag": "block-cn-domain"},
            {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"], "ruleTag": "block-bittorrent"},
            {"type": "field", "outboundTag": "block", "ip": ["geoip:private"], "ruleTag": "block-private-ip"}
          ]
        }
      }' > "$XRAY_TEMP_CONFIG_FILE" || _error "使用 jq 生成配置文件内容失败。"

    _info "正在验证生成的配置文件 ${XRAY_TEMP_CONFIG_FILE}..."
    if "$XRAY_BIN_PATH" check -c "$XRAY_TEMP_CONFIG_FILE"; then
        _info "配置文件验证通过。"
        mv "$XRAY_TEMP_CONFIG_FILE" "$XRAY_CONFIG_FILE"
        _info "配置文件已保存至: ${XRAY_CONFIG_FILE}"
    else
        _error "生成的配置文件 ${XRAY_TEMP_CONFIG_FILE} 未通过 Xray 验证。配置未更改。请检查临时文件内容。"
    fi
}

display_share_link() {
    local server_address="$1"
    local remark_name="$2"

    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件 ${XRAY_CONFIG_FILE} 不存在！" && return 1

    local config_data
    config_data=$(jq -r '[
        .inbounds[0].port, 
        .inbounds[0].settings.clients[0].id, 
        .inbounds[0].streamSettings.realitySettings.privateKey,
        .inbounds[0].streamSettings.realitySettings.serverNames[0], 
        .inbounds[0].streamSettings.realitySettings.shortIds[0]
    ] | @tsv' "$XRAY_CONFIG_FILE" 2>/dev/null)

    if [[ -z "$config_data" ]]; then
        _error "无法从配置文件 ${XRAY_CONFIG_FILE} 中读取必要信息。文件可能已损坏或格式不正确。"
        return 1
    fi
    
    read -r xray_port uuid private_key sni short_id <<< "$config_data"
    
    local public_key
    public_key=$($XRAY_BIN_PATH x25519 -i "${private_key}" | awk '/Public key/ {print $3}')
    if [[ -z "$public_key" ]]; then
        _warn "无法从私钥生成公钥。分享链接中的公钥将为空。"
    fi

    local encoded_remark
    encoded_remark=$(echo -n "$remark_name" | jq -sRr @uri)
    local vless_link="vless://${uuid}@${server_address}:${xray_port}?security=reality&encryption=none&pbk=${public_key}&host=${sni}&fp=chrome&sid=${short_id}&type=tcp&flow=xtls-rprx-vision&sni=${sni}#${encoded_remark}"


    clear
    _info "Xray 配置信息 (VLESS-XTLS-uTLS-REALITY)"
    echo -e "
  地址 (Address)   : ${YELLOW}${server_address}${NC}
  端口 (Port)      : ${YELLOW}${xray_port}${NC}
  用户 ID (UUID)   : ${YELLOW}${uuid}${NC}
  公钥 (PublicKey) : ${YELLOW}${public_key}${NC}
  短ID (ShortId)   : ${YELLOW}${short_id}${NC}
  目标域名 (SNI)   : ${YELLOW}${sni}${NC}

${BLUE}---------------- 分享链接 (备注: ${remark_name}) ----------------${NC}
${vless_link}
${BLUE}---------------- 二维码 (如果 qrencode 已安装) ------------------${NC}"

    if _exists "qrencode"; then
        qrencode -t ANSIUTF8 -m 1 "${vless_link}"
    else
        _warn "未找到 qrencode, 无法生成二维码。请运行 'apt install qrencode' 或 'yum install qrencode'。"
    fi
    echo -e "${BLUE}--------------------------------------------------------------${NC}"
}

view_existing_config() {
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件不存在！请先安装。" && return 1
    
    local server_address="$SHARE_ADDRESS"
    
    if [[ -z "$server_address" ]]; then
        _info "未在偏好设置中找到连接地址，正在自动检测服务器IP地址..."
        server_address=$(curl -s4m10 ip.sb || curl -s4m10 icanhazip.com || echo "your_server_ip_or_domain")
        if [[ "$server_address" == "your_server_ip_or_domain" ]]; then
            _warn "无法自动检测IP，请稍后使用选项102手动设置。"
        fi
    fi

    display_share_link "$server_address" "VLESS-XTLS-uTLS-REALITY" || _warn "显示配置时发生错误。"
}

regenerate_share_link() {
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件不存在！请先安装。" && return 1
    
    clear
    _info "--- 重新生成/自定义分享链接 ---"
    
    local server_address
    local auto_ip
    auto_ip=$(curl -s4m10 ip.sb || curl -s4m10 icanhazip.com || echo "")
    
    local current_pref_address="$SHARE_ADDRESS"
    if [[ -n "$current_pref_address" ]]; then
        _info "当前偏好连接地址: ${YELLOW}${current_pref_address}${NC}"
    fi
    _info "自动检测到的IP地址: ${YELLOW}${auto_ip:- (检测失败或为空)}${NC}"
    
    local choice_prompt="请选择连接地址来源: [C]当前偏好 (${current_pref_address:-无}), [A]自动IP (${auto_ip:-N/A}), [M]手动输入: "
    if [[ -z "$current_pref_address" && -z "$auto_ip" ]]; then
        choice_prompt="当前无偏好地址且无法自动检测IP。请[M]手动输入连接地址: "
    elif [[ -z "$current_pref_address" ]]; then
        choice_prompt="无偏好地址。请选择: [A]自动IP (${auto_ip}), [M]手动输入: "
    elif [[ -z "$auto_ip" ]]; then
         choice_prompt="无法自动检测IP。请选择: [C]当前偏好 (${current_pref_address}), [M]手动输入: "
    fi

    read -p "$choice_prompt" addr_choice
    
    case "$addr_choice" in
        [Cc]) 
            [[ -z "$current_pref_address" ]] && _error "无偏好地址可选，请手动输入或使用自动IP。"
            server_address="$current_pref_address" 
            ;;
        [Aa]) 
            [[ -z "$auto_ip" ]] && _error "无法自动检测IP，请手动输入或使用偏好地址。"
            server_address="$auto_ip" 
            ;;
        [Mm]) 
            read -p "请输入您的域名或IP地址: " server_address 
            ;;
        *) 
            _warn "无效选择。操作取消。"
            return 1
            ;;
    esac
     
    [[ -z "$server_address" ]] && _error "连接地址不能为空！操作已取消。" && return 1

    echo "SHARE_ADDRESS=\"$server_address\"" > "$PREFS_FILE"
    _info "您的选择 '${server_address}' 已被保存为默认连接地址。"

    local remark_name
    read -p "请输入分享链接的备注名 (默认: VLESS-XTLS-uTLS-REALITY): " remark_name
    [[ -z "$remark_name" ]] && remark_name="VLESS-XTLS-uTLS-REALITY"

    display_share_link "$server_address" "$remark_name" || _warn "生成分享链接时发生错误。"
}

do_install() {
    local is_reinstall_from_menu="$1"
    check_root

    if [[ "$is_reinstall_from_menu" == "true" ]]; then
        _warn "您选择了重新安装。这将覆盖现有的 Xray 配置、偏好设置并重新安装核心组件。"
        read -p "确定要继续吗? (y/N): " confirm_reinstall
        if [[ ! "$confirm_reinstall" =~ ^[Yy]$ ]]; then
            _info "重新安装已取消。"
            return 0
        fi
        _info "开始执行重新安装..."
    else
        _info "开始首次安装..."
    fi

    install_dependencies
    install_xray_core
    generate_xray_config

    _info "正在设置脚本环境和别名..."
    mkdir -p "$SCRIPT_DIR"
    if ! cp -f "$0" "$SCRIPT_SELF_PATH"; then
      _warn "警告：无法将脚本自身 ($0) 复制到 ${SCRIPT_SELF_PATH}。"
      _warn "这通常发生在直接通过管道执行脚本时。菜单功能可能不完整或不持久。"
      _warn "建议的首次运行方式是：curl -o script.sh URL && sudo bash script.sh install"
    else
        chmod +x "$SCRIPT_SELF_PATH"
        _info "管理脚本已复制到 ${SCRIPT_SELF_PATH}"
    fi
    
    echo "alias xs='bash ${SCRIPT_SELF_PATH}'" > "$ALIAS_FILE"

    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_BIN_PATH} run -config ${XRAY_CONFIG_FILE}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    _info "Xray systemd 服务文件已创建/更新。"

    systemctl daemon-reload
    if ! systemctl enable xray &>/dev/null; then
        _warn "启用 Xray 服务失败。"
    else
        _info "Xray 服务已设置为开机自启。"
    fi
    
    if ! _systemctl "restart"; then
        _warn "Xray 服务启动失败。请检查上述日志和配置文件。"
        _warn "您可能需要手动修复配置文件 (${XRAY_CONFIG_FILE}) 并尝试 'systemctl restart xray'。"
    fi
    
    regenerate_share_link 

    _info "Xray 安装/重新安装完成！"
    _warn "为了确保 'xs' 命令别名在当前SSH会话中可用，您可能需要执行 'source /etc/profile' 或重新连接。"
}


do_uninstall() {
    check_root
    read -p "$(echo -e "${YELLOW}确定要完全卸载 Xray 和本管理脚本吗? (这将删除配置和相关文件) (y/N): ${NC}")" choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        _systemctl "stop"
        if ! systemctl disable xray &>/dev/null; then
             _warn "禁用 Xray 服务时发生错误。"
        fi
        _info "正在尝试使用官方脚本卸载 Xray-core..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge &>/dev/null 
        
        _info "正在删除相关文件和目录..."
        rm -rf "$SCRIPT_DIR" \
                 "$XRAY_CONFIG_FILE" \
                 "$(dirname "$XRAY_CONFIG_FILE")" \
                 "$XRAY_BIN_PATH" \
                 "$ALIAS_FILE" \
                 "/etc/systemd/system/xray.service" \
                 "/etc/systemd/system/xray.service.d"
        
        systemctl daemon-reload

        _info "Xray 及相关组件已成功卸载。"
        _warn "请执行 'source /etc/profile' 或重新登录以移除 'xs' 命令别名。"
        _info "如果之前配置过防火墙规则，请记得手动移除。"
    else
        _info "卸载操作已取消。"
    fi
}

_load_prefs() {
    SHARE_ADDRESS="" # Default to empty if not set
    [[ -f "$PREFS_FILE" ]] && source "$PREFS_FILE"
}

_safe_update_config_value() {
    local jq_filter="$1"
    local success_msg="$2"
    local failure_msg="$3"

    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件 ${XRAY_CONFIG_FILE} 不存在。" && return 1
    ! _exists "$XRAY_BIN_PATH" && _error "Xray 执行文件 ${XRAY_BIN_PATH} 未找到。" && return 1


    if jq "$jq_filter" "$XRAY_CONFIG_FILE" > "$XRAY_TEMP_CONFIG_FILE" && [[ -s "$XRAY_TEMP_CONFIG_FILE" ]]; then
        if "$XRAY_BIN_PATH" check -c "$XRAY_TEMP_CONFIG_FILE"; then
            mv "$XRAY_TEMP_CONFIG_FILE" "$XRAY_CONFIG_FILE"
            _info "$success_msg"
            _systemctl "restart" && regenerate_share_link
        else
            _error "修改后的配置文件未通过 Xray 验证。配置未更改。临时文件: $XRAY_TEMP_CONFIG_FILE"
            # rm -f "$XRAY_TEMP_CONFIG_FILE" # Keep for inspection
        fi
    else
        _error "$failure_msg (jq 操作失败或临时文件为空)。配置文件未更改。临时文件: $XRAY_TEMP_CONFIG_FILE"
        # rm -f "$XRAY_TEMP_CONFIG_FILE" # Keep for inspection
    fi
}

main_menu() {
    _load_prefs
    clear
    local xray_status xray_version config_exists
    if systemctl is-active --quiet xray; then xray_status="${GREEN}运行中${NC}"; else xray_status="${RED}已停止${NC}"; fi
    if _exists "$XRAY_BIN_PATH"; then xray_version="$($XRAY_BIN_PATH version | head -n1 | awk '{print $2}')"; else xray_version="${RED}未安装${NC}"; fi
    if [[ -f "$XRAY_CONFIG_FILE" ]]; then config_exists="${GREEN}存在${NC}"; else config_exists="${RED}不存在${NC}"; fi

    echo -e "
${BLUE}Xray Ultimate Simplified Script | v${SCRIPT_VERSION}${NC}
${BLUE}===================================================${NC}
 Xray 状态: ${xray_status}
 Xray 版本: ${xray_version}
 配置文件:  ${config_exists}
 偏好地址:  ${YELLOW}${SHARE_ADDRESS:-未设置}${NC}
${BLUE}---------------------------------------------------${NC}
${GREEN}1.${NC}  完整安装/重新安装 (覆盖当前配置)
${GREEN}2.${NC}  ${RED}卸载 Xray 和本脚本${NC}
${GREEN}3.${NC}  更新 Xray 内核 (使用官方脚本)

${GREEN}4.${NC}  启动 Xray      ${GREEN}5.${NC}  停止 Xray      ${GREEN}6.${NC}  重启 Xray
${BLUE}----------------- 配置管理 ------------------${NC}
${GREEN}101.${NC} 查看当前分享链接/二维码
${GREEN}102.${NC} 自定义分享链接的连接地址/备注
${GREEN}103.${NC} 查看 Xray 实时日志
${GREEN}104.${NC} 修改用户 ID (UUID)
${GREEN}105.${NC} 修改回落目标域名 (Fallback Dest)
${BLUE}---------------------------------------------------${NC}
${GREEN}0.${NC}  退出脚本
"
    read -rp "请输入选项: " option

    case "$option" in
    0) exit 0 ;;
    1) do_install "true" ;;
    2) do_uninstall ;;
    3) install_xray_core && _systemctl "restart" ;;
    4) _systemctl "start" ;;
    5) _systemctl "stop" ;;
    6) _systemctl "restart" ;;
    101) view_existing_config ;;
    102) regenerate_share_link ;;
    103) 
        _info "按 Ctrl+C 停止查看日志。"
        journalctl -u xray -f --no-pager 
        ;;
    104)
        local new_uuid new_uuid_val
        read -p "请输入新 UUID (留空自动生成): " new_uuid
        if [[ -z "$new_uuid" ]]; then
            ! _exists "$XRAY_BIN_PATH" && _error "Xray 未安装，无法生成 UUID。" && return 1
            new_uuid_val=$($XRAY_BIN_PATH uuid)
            [[ -z "$new_uuid_val" ]] && _error "无法使用 Xray 生成 UUID。" && return 1
            new_uuid="$new_uuid_val"
            _info "已自动生成新 UUID: ${new_uuid}"
        fi
        _safe_update_config_value ".inbounds[0].settings.clients[0].id = \"$new_uuid\"" \
                                  "UUID 修改成功。" "修改 UUID 失败。"
        ;;
    105)
        local new_dest
        new_dest=$(validate_dest_domain)
        _safe_update_config_value ".inbounds[0].streamSettings.realitySettings.dest = \"${new_dest}:443\" | .inbounds[0].streamSettings.realitySettings.serverNames = [\"$new_dest\"]" \
                                  "回落目标域名修改成功。" "修改回落目标域名失败。"
        ;;
    *) _warn "无效的选项。" ;;
    esac
    
    if [[ "$option" != "103" && "$option" != "0" ]]; then
        echo && read -n 1 -s -r -p "按任意键返回主菜单..."
    fi
}


# --- Script Entry Point ---
if [[ "$1" == "install" ]]; then
    do_install "false"
elif [[ "$1" == "menu" && -f "$SCRIPT_SELF_PATH" && "$0" == "$SCRIPT_SELF_PATH" ]]; then
    check_root
    _load_prefs
    while true; do main_menu; done
else
    check_root
    _load_prefs
    if [[ ! -f "$SCRIPT_SELF_PATH" || ! -f "$XRAY_CONFIG_FILE" ]]; then
      _warn "未找到 Xray 配置文件或管理脚本未正确初始化 ($SCRIPT_SELF_PATH)。"
      read -p "是否立即开始完整安装? (y/N): " choice
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          if [[ -f "$0" && "$0" != "-" && "$0" != "bash" && "$0" != "-bash" && "$0" != "/bin/bash" && ! ("$0" =~ ^-s$) ]]; then # Check if $0 looks like a script file path
            do_install "false"
          else
            _error "无法确定脚本文件路径 ($0)。\n请先下载脚本，然后运行，例如：\n  curl -o install_Xray.sh <你的脚本URL>\n  sudo bash install_Xray.sh install"
          fi
      else
        _info "安装已取消。"
      fi
      exit 0
    fi
    while true; do main_menu; done
fi
