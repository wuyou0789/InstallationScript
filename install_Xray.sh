#!/usr/bin/env bash

#================================================================================
# Xray Ultimate Simplified Script (XUS)
#
# Version: 1.7.6 (Fix systemd service file format)
# Author: AI Assistant & wuyou0789
# GitHub: (Host this on your own GitHub repository)
#
# New in 1.7.6: Corrected multi-directive lines in xray.service file.
#================================================================================

# --- Script Environment ---
set -o pipefail
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
readonly SCRIPT_VERSION="1.7.6"
readonly SCRIPT_URL="https://raw.githubusercontent.com/wuyou0789/InstallationScript/main/install_Xray.sh" 
readonly VERSION_CHECK_URL="https://raw.githubusercontent.com/wuyou0789/InstallationScript/main/version.txt"

# --- Color Codes ---
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# --- Configuration Paths ---
readonly SCRIPT_DIR="/usr/local/etc/xus-script"
readonly SCRIPT_SELF_PATH="${SCRIPT_DIR}/menu.sh"
readonly PREFS_FILE="${SCRIPT_DIR}/user_prefs.conf"
readonly XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"
readonly XRAY_BIN_PATH="/usr/local/bin/xray"
readonly ALIAS_FILE="/etc/profile.d/xus-alias.sh"
readonly XRAY_TEMP_CONFIG_FILE="/tmp/xray_config_tmp.json"

# --- Logging and Status Functions ---
_info() { printf "${GREEN}[信息] %s${NC}\n" "$*" >&2; }
_warn() { printf "${YELLOW}[警告] %s${NC}\n" "$*" >&2; }
_error() { printf "${RED}[错误] %s${NC}\n" "$*" >&2; exit 1; }

# --- Prerequisite and Utility Functions ---
check_root() { [[ $EUID -ne 0 ]] && _error "此脚本必须以 root 权限运行。"; }
_exists() { command -v "$1" >/dev/null 2>&1; }
_os() {
    if [[ -f "/etc/os-release" ]]; then source /etc/os-release && echo "$ID";
    elif [[ -f "/etc/redhat-release" ]]; then echo "centos";
    elif [[ -f "/etc/debian_version" ]]; then echo "debian";
    elif _exists "lsb_release"; then lsb_release -is | tr '[:upper:]' '[:lower:]';
    else _error "无法识别的操作系统。"; fi
}

_install_pkgs() {
    local os_type=$(_os)
    [[ -z "$os_type" ]] && _error "无法确定操作系统类型。"
    _info "在 ${os_type} 上安装软件包: $*"
    case "$os_type" in
    centos|rhel|almalinux|rocky|fedora) _exists "dnf" && dnf install -y "$@" || yum install -y "$@";;
    ubuntu|debian) apt-get update -qq && apt-get install -yqq "$@";;
    *) _error "不支持的操作系统 ($os_type)，请手动安装: $*";;
    esac || _error "软件包安装失败: $*"
}

install_dependencies() {
    _info "正在检查和安装依赖..."
    local pkgs_to_install=()
    ! _exists "curl" && pkgs_to_install+=("curl")
    ! _exists "jq" && pkgs_to_install+=("jq")
    ! _exists "openssl" && pkgs_to_install+=("openssl")
    ! _exists "qrencode" && pkgs_to_install+=("qrencode")
    ! _exists "timeout" && pkgs_to_install+=("coreutils")
    if [[ ${#pkgs_to_install[@]} -gt 0 ]]; then _install_pkgs "${pkgs_to_install[@]}"; else _info "所需依赖均已安装。"; fi
}

_systemctl() {
    local action="$1" service_name="xray" output status
    _info "正在 ${action} ${service_name} 服务..."
    output=$(systemctl "${action}" "${service_name}" 2>&1); status=$?
    sleep 1
    if [[ "$action" == "stop" || "$action" == "disable" ]]; then
        if [[ $status -ne 0 ]]; then _warn "${service_name} 服务 ${action} 操作本身失败。Output: ${output}";
        elif systemctl is-active --quiet "$service_name"; then _warn "${service_name} 服务 ${action} 后仍处于活动状态。";
        else _info "${service_name} 服务 ${action} 完成。"; fi
    else
        if ! systemctl is-active --quiet "$service_name"; then
            _warn "${service_name} 服务 ${action} 后状态异常。Output: ${output}"
            _warn "请使用 'journalctl -u ${service_name} -e --no-pager' 查看日志。"
        else _info "${service_name} 服务 ${action} 完成。"; fi
    fi
    [[ "$action" == "enable" && $status -eq 0 ]] && systemctl daemon-reload &>/dev/null
    return $status
}

validate_dest_domain() {
    local prompt="请输入真实【国外】域名作回落目标 (例: www.apple.com):" new_dest timeout_cmd="timeout 10"
    ! _exists "timeout" && timeout_cmd="" && _warn "timeout 命令未找到，验证可能挂起。"
    while true; do
        read -p "$prompt " new_dest
        [[ -z "$new_dest" ]] && new_dest="www.apple.com" && _info "使用默认: www.apple.com"
        _info "验证域名 ${new_dest} 对 REALITY 支持 (超时10秒)..."
        if echo "QUIT" | ${timeout_cmd} openssl s_client -connect "${new_dest}:443" -tls1_3 -servername "${new_dest}" 2>&1 | grep -q "X25519"; then
            _info "域名 ${new_dest} 验证通过！"; break
        else prompt="${RED}域名 ${new_dest} 验证失败，请更换:${NC}"; fi
    done
    echo "$new_dest"
}

# --- Core Logic ---
install_xray_core() {
    _info "正在使用官方脚本安装/更新 Xray-core..."
    local official_script_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    local temp_official_script="/tmp/install-release-core.sh"

    _info "下载 Xray 官方安装脚本至 ${temp_official_script}..."
    if ! curl -L -o "$temp_official_script" "$official_script_url"; then _error "下载 Xray 官方脚本失败。"; fi
    chmod +x "$temp_official_script"
    
    _info "执行 Xray 官方脚本 (参数: install -u root)..."
    if bash "$temp_official_script" install -u root; then
        _info "Xray-core 官方脚本执行完毕。"
        rm -f "$temp_official_script"
        ! _exists "$XRAY_BIN_PATH" && _error "Xray-core 安装后未找到: ${XRAY_BIN_PATH}"
        [[ ! -x "$XRAY_BIN_PATH" ]] && _error "Xray-core 文件不可执行: ${XRAY_BIN_PATH}"
        _info "Xray-core 验证通过 ($($XRAY_BIN_PATH version | head -n1))."
    else
        rm -f "$temp_official_script"
        _error "Xray-core 安装/更新失败，检查网络或官方脚本输出。"
    fi
}

update_geodata() {
    _info "正在更新 Xray GeoIP 和 GeoSite 数据文件..."
    local official_script_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
    local temp_official_script="/tmp/install-release-geodata.sh"

    _info "下载 Xray 官方安装脚本至 ${temp_official_script}..."
    if ! curl -L -o "$temp_official_script" "$official_script_url"; then _error "下载 Xray 官方脚本失败。"; fi
    chmod +x "$temp_official_script"

    _info "执行 Xray 官方脚本更新 GeoData (参数: install-geodata)..."
    if bash "$temp_official_script" install-geodata; then
        _info "GeoIP 和 GeoSite 数据文件更新成功。"
        rm -f "$temp_official_script"
        _info "建议重启 Xray 服务以确保新数据加载 (若需要)。"
    else
        rm -f "$temp_official_script"
        _error "GeoIP 和 GeoSite 数据文件更新失败。"
    fi
}

generate_xray_config() {
    _info "--- 开始 Xray 配置向导 ---"
    local xray_port client_uuid fallback_target private_key short_id client_uuid_val keys_val
    while true; do
        read -p "Xray 监听端口 (1-65535, 默认 443): " xray_port; [[ -z "$xray_port" ]] && xray_port=443
        if [[ "$xray_port" =~ ^[0-9]+$ && "$xray_port" -ge 1 && "$xray_port" -le 65535 ]]; then break
        else _warn "端口 '${xray_port}' 无效。"; fi
    done
    fallback_target=$(validate_dest_domain)
    ! _exists "$XRAY_BIN_PATH" && _warn "Xray 未找到，尝试安装/更新..." && install_xray_core
    read -p "自定义 UUID (留空自动生成): " client_uuid
    if [[ -z "$client_uuid" ]]; then
        client_uuid_val=$($XRAY_BIN_PATH uuid); [[ -z "$client_uuid_val" ]] && _error "Xray 生成 UUID 失败。"
        client_uuid="$client_uuid_val"; _info "已生成 UUID: ${client_uuid}"
    elif ! [[ "$client_uuid" =~ ^[0-9a-fA-F]{8}-(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$ ]]; then _warn "UUID 格式似不正确。"; fi
    keys_val=$($XRAY_BIN_PATH x25519); [[ -z "$keys_val" ]] && _error "Xray 生成密钥对失败。"
    private_key=$(echo "$keys_val" | awk '/Private key/ {print $3}'); [[ -z "$private_key" ]] && _error "提取私钥失败。"
    short_id=$(openssl rand -hex 8)
    _info "创建配置文件内容..." && mkdir -p "$(dirname "$XRAY_CONFIG_FILE")"
    
    jq -n --argjson port "$xray_port" --arg uuid "$client_uuid" --arg p_key "$private_key" \
          --arg s_id "$short_id" --arg target_domain "$fallback_target" \
      '{ "log": {"loglevel": "warning"},
         "inbounds": [{"listen": "0.0.0.0", "port": $port, "protocol": "vless",
           "settings": {"clients": [{"id": $uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
           "streamSettings": {"network": "raw", "security": "reality",
             "realitySettings": {"show": false, "dest": ($target_domain + ":443"), "xver": 0,
                                "serverNames": [$target_domain], "privateKey": $p_key, "minClientVer": "", 
                                "maxClientVer": "", "maxTimeDiff": 60000, "shortIds": [$s_id]}},
           "sniffing": {"enabled": true, "destOverride": ["http", "tls", "fakedns"]}}],
         "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
         "routing": {"domainStrategy": "AsIs", "rules": [
           {"type": "field", "outboundTag": "block", "ip": ["geoip:cn"], "ruleTag": "block-cn-ip"},
           {"type": "field", "outboundTag": "block", "domain": ["geosite:cn"], "ruleTag": "block-cn-domain"},
           {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"], "ruleTag": "block-bittorrent"},
           {"type": "field", "outboundTag": "block", "ip": ["geoip:private"], "ruleTag": "block-private-ip"}]}}' > "$XRAY_TEMP_CONFIG_FILE" || _error "jq 生成配置失败。"
    
    _info "配置文件内容已生成到 ${XRAY_TEMP_CONFIG_FILE}."
    mkdir -p "$(dirname "$XRAY_CONFIG_FILE")"
    mv "$XRAY_TEMP_CONFIG_FILE" "$XRAY_CONFIG_FILE"
    _info "配置已写入: ${XRAY_CONFIG_FILE}"
    _warn "当前 Xray 版本可能无内置配置检查命令。配置正确性将在服务重启时验证。"
}

display_share_link() {
    local server_address="$1" remark_name="$2" config_data xray_port uuid private_key sni short_id public_key encoded_remark vless_link
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置 ${XRAY_CONFIG_FILE} 不存在！" && return 1
    config_data=$(jq -r '[.inbounds[0].port, .inbounds[0].settings.clients[0].id, .inbounds[0].streamSettings.realitySettings.privateKey, .inbounds[0].streamSettings.realitySettings.serverNames[0], .inbounds[0].streamSettings.realitySettings.shortIds[0]] | @tsv' "$XRAY_CONFIG_FILE" 2>/dev/null)
    [[ -z "$config_data" ]] && _error "从配置 ${XRAY_CONFIG_FILE} 读信息失败。" && return 1
    read -r xray_port uuid private_key sni short_id <<< "$config_data"
    public_key=$($XRAY_BIN_PATH x25519 -i "${private_key}" | awk '/Public key/ {print $3}')
    [[ -z "$public_key" ]] && _warn "无法从私钥生成公钥。"
    encoded_remark=$(echo -n "$remark_name" | jq -sRr @uri)
    vless_link="vless://${uuid}@${server_address}:${xray_port}?security=reality&encryption=none&pbk=${public_key}&host=${sni}&fp=chrome&sid=${short_id}&type=tcp&flow=xtls-rprx-vision&sni=${sni}#${encoded_remark}"
    clear; _info "Xray 配置 (VLESS-XTLS-uTLS-REALITY)"
    echo -e " 地址: ${YELLOW}${server_address}${NC}\n 端口: ${YELLOW}${xray_port}${NC}\n UUID: ${YELLOW}${uuid}${NC}\n 公钥: ${YELLOW}${public_key}${NC}\n ShortId: ${YELLOW}${short_id}${NC}\n SNI: ${YELLOW}${sni}${NC}\n\n${BLUE}--- 分享 (备注: ${remark_name}) ---${NC}\n${vless_link}\n${BLUE}--- 二维码 ---${NC}"
    _exists "qrencode" && qrencode -t ANSIUTF8 -m 1 "${vless_link}" || _warn "未装 qrencode,无法生成二维码。"
    echo -e "${BLUE}---------------------------------${NC}"
}

view_existing_config() {
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置不存在！先安装。" && return 1
    local server_address="$SHARE_ADDRESS"
    if [[ -z "$server_address" ]]; then
        _info "无偏好地址,尝试自动检测IP..."
        server_address=$(curl -s4m10 ip.sb || curl -s4m10 icanhazip.com || echo "your_server_ip")
        [[ "$server_address" == "your_server_ip" ]] && _warn "无法自动检测IP,请用102手动设置。"
    fi
    display_share_link "$server_address" "VLESS-XTLS-uTLS-REALITY" || _warn "显示配置出错。"
}

regenerate_share_link() {
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置不存在！先安装。" && return 1
    clear; _info "--- 自定义分享链接 ---"; local server_address auto_ip current_pref_address choice_prompt addr_choice remark_name
    auto_ip=$(curl -s4m10 ip.sb || curl -s4m10 icanhazip.com || echo "")
    current_pref_address="$SHARE_ADDRESS"
    [[ -n "$current_pref_address" ]] && _info "当前偏好地址: ${YELLOW}${current_pref_address}${NC}"
    _info "自动检测IP: ${YELLOW}${auto_ip:- (失败/为空)}${NC}"
    choice_prompt="选连接地址: [C]当前偏好 (${current_pref_address:-无}), [A]自动IP (${auto_ip:-N/A}), [M]手动输入: "
    [[ -z "$current_pref_address" && -z "$auto_ip" ]] && choice_prompt="无偏好且无法自动检测IP. 请[M]手动输入: "
    [[ -z "$current_pref_address" && -n "$auto_ip" ]] && choice_prompt="无偏好. 选: [A]自动IP (${auto_ip}), [M]手动输入: "
    [[ -n "$current_pref_address" && -z "$auto_ip" ]] && choice_prompt="无法自动检测IP. 选: [C]当前偏好 (${current_pref_address}), [M]手动输入: "
    read -p "$choice_prompt" addr_choice
    case "$addr_choice" in
        [Cc]) [[ -z "$current_pref_address" ]] && _error "无偏好可选。" && return 1; server_address="$current_pref_address" ;;
        [Aa]) [[ -z "$auto_ip" ]] && _error "无法自动检测IP。" && return 1; server_address="$auto_ip" ;;
        [Mm]) read -p "输入域名或IP: " server_address ;;
        *) _warn "无效选择。"; return 1 ;;
    esac
    [[ -z "$server_address" ]] && _error "地址不能为空！" && return 1
    echo "SHARE_ADDRESS=\"$server_address\"" > "$PREFS_FILE"; _info "选择 '${server_address}' 已存为默认。"
    read -p "分享链接备注 (默认: VLESS-XTLS-uTLS-REALITY): " remark_name; [[ -z "$remark_name" ]] && remark_name="VLESS-XTLS-uTLS-REALITY"
    display_share_link "$server_address" "$remark_name" || _warn "生成分享链接出错。"
}

do_install() {
    local is_reinstall="$1"
    check_root
    if [[ "$is_reinstall" == "true" ]]; then
        _warn "将覆盖现有配置并重装核心。" && read -p "确定继续? (y/N): " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && _info "重装已取消。" && return 0
        _info "开始重装..."
    else _info "开始首次安装..."; fi
    install_dependencies; install_xray_core; generate_xray_config
    _info "设置脚本环境和别名..." && mkdir -p "$SCRIPT_DIR"
    if ! cp -f "$0" "$SCRIPT_SELF_PATH"; then
      _warn "警告: 无法复制脚本 ($0) 到 ${SCRIPT_SELF_PATH}。\n这通常在管道执行时发生。菜单可能不持久。\n建议：curl -o s.sh URL && bash s.sh install"
    else chmod +x "$SCRIPT_SELF_PATH"; _info "管理脚本已存: ${SCRIPT_SELF_PATH}"; fi
    echo "alias xs='bash ${SCRIPT_SELF_PATH}'" > "$ALIAS_FILE"
    
    # Corrected systemd service file content
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
    _info "Xray systemd服务文件已创建/更新。" && systemctl daemon-reload
    ! systemctl enable xray &>/dev/null && _warn "启用Xray服务失败。" || _info "Xray已设开机自启。"
    
    _info "尝试重启Xray服务以应用新配置..."
    if ! _systemctl "restart"; then 
        _warn "Xray服务启动失败！这可能意味着生成的配置文件 (${XRAY_CONFIG_FILE}) 有问题。"
        _warn "请检查Xray日志获取详细错误: journalctl -u xray -e --no-pager"
        _warn "脚本将继续，但Xray可能无法正常工作。"
    else
        _info "Xray服务已成功重启。"
    fi
    
    regenerate_share_link; _info "Xray安装/重装完成！"
    _warn "为使 'xs' 别名生效, 可能需 'source /etc/profile' 或重连SSH。"
}

do_uninstall() {
    check_root; read -p "$(echo -e "${YELLOW}确定完全卸载Xray和本脚本? (y/N):${NC}")" choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        _systemctl "stop"; ! systemctl disable xray &>/dev/null && _warn "禁用Xray服务出错。"
        _info "尝试用官方脚本卸载Xray-core..."; local official_script_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"; local temp_script="/tmp/uninstall.sh"
        if curl -L -o "$temp_script" "$official_script_url"; then chmod +x "$temp_script"; bash "$temp_script" remove --purge &>/dev/null; rm -f "$temp_script";
        else _warn "无法下载官方卸载脚本,仅删已知文件。"; fi
        _info "删除相关文件和目录..."
        rm -rf "$SCRIPT_DIR" "$XRAY_CONFIG_FILE" "$(dirname "$XRAY_CONFIG_FILE")" "$XRAY_BIN_PATH" "$ALIAS_FILE" "/etc/systemd/system/xray.service" "/etc/systemd/system/xray.service.d"
        systemctl daemon-reload; _info "Xray及组件已卸载。"
        _warn "请 'source /etc/profile' 或重连以移除 'xs' 别名。"; _info "若有防火墙规则请手动移除。"
    else _info "卸载已取消。"; fi
}

_load_prefs() { SHARE_ADDRESS=""; [[ -f "$PREFS_FILE" ]] && source "$PREFS_FILE"; }

_safe_update_config_value() {
    local jq_filter="$1" success_msg="$2" failure_msg="$3"
    [[ ! -f "$XRAY_CONFIG_FILE" ]] && _error "配置文件 ${XRAY_CONFIG_FILE} 不存在。" && return 1
    ! _exists "$XRAY_BIN_PATH" && _error "Xray ${XRAY_BIN_PATH} 未找到。" && return 1

    if jq "$jq_filter" "$XRAY_CONFIG_FILE" > "$XRAY_TEMP_CONFIG_FILE" && [[ -s "$XRAY_TEMP_CONFIG_FILE" ]]; then
        mv "$XRAY_TEMP_CONFIG_FILE" "$XRAY_CONFIG_FILE"
        _info "$success_msg (配置已写入，将在重启时验证)"
        if _systemctl "restart"; then
             regenerate_share_link
        else
            _warn "服务重启失败！修改后的配置可能有问题。请检查Xray日志。"
        fi
    else 
        _error "$failure_msg (jq 操作失败或临时文件为空)。配置文件未更改。"
        rm -f "$XRAY_TEMP_CONFIG_FILE"
    fi
}

main_menu() {
    _load_prefs; clear; local xray_status xray_version config_exists
    systemctl is-active --quiet xray && xray_status="${GREEN}运行中${NC}" || xray_status="${RED}已停止${NC}"
    _exists "$XRAY_BIN_PATH" && xray_version="$($XRAY_BIN_PATH version|head -n1|awk '{print $2}')" || xray_version="${RED}未安装${NC}"
    [[ -f "$XRAY_CONFIG_FILE" ]] && config_exists="${GREEN}存在${NC}" || config_exists="${RED}不存在${NC}"
    echo -e "
${BLUE}Xray Ultimate Simplified Script | v${SCRIPT_VERSION}${NC}
${BLUE}===================================================${NC}
 Xray 状态: ${xray_status}  版本: ${xray_version}
 配置文件: ${config_exists}   偏好地址: ${YELLOW}${SHARE_ADDRESS:-未设置}${NC}
${BLUE}---------------------------------------------------${NC}
${GREEN}1.${NC} 完整安装/重新安装    ${GREEN}2.${NC} ${RED}卸载Xray和脚本${NC}
${GREEN}3.${NC} 更新 Xray 内核       ${GREEN}7.${NC} 更新 GeoData

${GREEN}4.${NC} 启动 Xray            ${GREEN}5.${NC} 停止 Xray
${GREEN}6.${NC} 重启 Xray
${BLUE}----------------- 配置管理 ------------------${NC}
${GREEN}101.${NC} 查看分享链接/QR  ${GREEN}102.${NC} 自定义分享地址/备注
${GREEN}103.${NC} 查看实时日志     ${GREEN}104.${NC} 修改用户 ID (UUID)
${GREEN}105.${NC} 修改回落目标域名
${BLUE}---------------------------------------------------${NC}
${GREEN}0.${NC}  退出脚本
"
    read -rp "请输入选项: " option
    case "$option" in
    0) exit 0 ;; 1) do_install "true" ;; 2) do_uninstall ;;
    3) install_xray_core && _systemctl "restart" ;; 4) _systemctl "start" ;;
    5) _systemctl "stop" ;; 6) _systemctl "restart" ;; 7) update_geodata ;;
    101) view_existing_config ;; 102) regenerate_share_link ;;
    103) _info "按 Ctrl+C 停止日志。" && journalctl -u xray -f --no-pager ;;
    104) local new_uuid new_uuid_val; read -p "新UUID(留空自动): " new_uuid
         if [[ -z "$new_uuid" ]]; then
            ! _exists "$XRAY_BIN_PATH" && _error "Xray未装无法生成UUID" && return 1
            new_uuid_val=$($XRAY_BIN_PATH uuid); [[ -z "$new_uuid_val" ]] && _error "Xray生成UUID失败" && return 1
            new_uuid="$new_uuid_val"; _info "已生成UUID: ${new_uuid}"
         fi
         _safe_update_config_value ".inbounds[0].settings.clients[0].id = \"$new_uuid\"" "UUID修改成功。" "修改UUID失败." ;;
    105) local new_dest; new_dest=$(validate_dest_domain)
         _safe_update_config_value ".inbounds[0].streamSettings.realitySettings.dest = \"${new_dest}:443\" | .inbounds[0].streamSettings.realitySettings.serverNames = [\"$new_dest\"]" "回落域名修改成功。" "修改回落域名失败。" ;;
    *) _warn "无效选项。" ;;
    esac
    [[ "$option" != "103" && "$option" != "0" ]] && echo && read -n 1 -s -r -p "按任意键返回主菜单..."
}

# --- Script Entry Point ---
if [[ "$1" == "install" ]]; then do_install "false";
elif [[ "$1" == "menu" && -f "$SCRIPT_SELF_PATH" && "$0" == "$SCRIPT_SELF_PATH" ]]; then
    check_root; _load_prefs; while true; do main_menu; done
else
    check_root; _load_prefs
    if [[ ! -f "$SCRIPT_SELF_PATH" || ! -f "$XRAY_CONFIG_FILE" ]]; then
      _warn "未找到Xray配置或管理脚本未正确初始化($SCRIPT_SELF_PATH)。"
      read -p "是否立即开始完整安装? (y/N): " choice
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          if [[ -f "$0" && "$0" != "-" && "$0" != "bash" && "$0" != "-bash" && "$0" != "/bin/bash" && ! ("$0" =~ ^-s$) ]]; then do_install "false";
          else _error "无法确定脚本路径($0)。\n请先下载脚本再运行, 例:\n curl -o i.sh <URL>\n bash i.sh install"; fi
      else _info "安装已取消。"; fi; exit 0
    fi
    while true; do main_menu; done
fi
