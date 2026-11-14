#!/bin/bash
# ============================================================================
#  Xray REALITY 极简安装脚本（核心版本锁定 v26.6.27）
# ----------------------------------------------------------------------------
#  为什么必须锁版本：
#    Xray-core 从 v26.7 起收紧 REALITY 对 ClientHello 的校验，v26.9.8 起服务端
#    强制要求 key_share 必须携带 X25519MLKEM768（且必须在 X25519 之前）。
#    mihomo 默认剥掉 MLKEM，sing-box 系客户端（Karing 的 sing-box 内核）也不发
#    MLKEM，握手不被当作 REALITY 而回落到伪装站 —— 症状是「节点能连但上不了网
#    / 像打开了真网站」。参考：https://github.com/MetaCubeX/mihomo/issues/3193
#    v26.6.27 是最后一个不强制 MLKEM 的稳定版：Karing / mihomo / v2rayN /
#    Xray（新老版本）客户端都能正常握手。
#    以后不要手工执行不带 --version 的安装命令，否则会被升级到最新版。
#
#  可靠性设计（相对上一版）：
#    1) 端口预检：443 被别的程序占着（nginx / docker-proxy 等）时直接报出占用者
#    2) 幂等：重跑默认沿用已有 UUID / 私钥 / ShortId，不会把老客户端踢下线
#    3) 原子写入 + 落盘自检 + 失败自动回滚到上一份配置
#    4) 模板下载失败时使用脚本内置模板，不再中途退出
#    5) 启动后二次校验：服务 active + 端口真的在监听 + 3 秒后没崩
#    6) 交互可被环境变量覆盖，`curl | bash` 之类非交互场景不会把 stdin 吃错
#    7) 安装 REALITY 回落域名前先探测目标是否支持 TLS1.3 + h2（REALITY 硬要求）
#    8) 配置与备份权限 600，备份最多保留 5 份
#
#  非交互用法示例：
#    SERVER_ADDR=1.2.3.4 FALLBACK_DOMAIN=www.apple.com REUSE_CREDS=y bash install_Xray.sh
# ============================================================================

set -o pipefail

readonly XRAY_PIN_VERSION="v26.6.27"
readonly INSTALL_SCRIPT_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
readonly TEMPLATE_URL="https://raw.githubusercontent.com/wuyou0789/InstallationScript/main/config_template.json"
readonly XRAY_BIN="/usr/local/bin/xray"
readonly CONFIG_DIR="/usr/local/etc/xray"
readonly CONFIG_FILE="${CONFIG_DIR}/config.json"
readonly LINK_FILE="${CONFIG_DIR}/share_link.txt"
readonly XRAY_PORT="${XRAY_PORT:-443}"
readonly BACKUP_KEEP=5

BACKUP_FILE=""
TMP_FILES=()
cleanup() {
    local f
    for f in "${TMP_FILES[@]:-}"; do
        [ -n "$f" ] && [ -f "$f" ] && rm -f "$f"
    done
}
trap cleanup EXIT

# --- 0. 输出与交互小工具 ---
info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*"; }
err()  { echo "[x] $*" >&2; }
die()  { err "$*"; exit 1; }

# ask "提示" "默认值" [非交互时的取值]
# 能读 /dev/tty 就读终端，保证 `curl ... | bash` 也能正常交互
ask() {
    local prompt="$1" default="$2" noninteractive="${3:-$2}" ans=""
    if { [ -c /dev/tty ] && exec 3</dev/tty; } 2>/dev/null; then
        read -r -p "$prompt" ans <&3 2>/dev/null || ans=""
        exec 3<&- || true
    else
        ans="$noninteractive"
    fi
    printf '%s' "${ans:-$default}"
}

# --- 1. 基础检查与环境准备 ---
[ "$EUID" -eq 0 ] || die "错误：必须使用 root 权限运行此脚本。"
case "$XRAY_PORT" in
    ''|*[!0-9]*) die "错误：XRAY_PORT 必须是数字，当前为 '${XRAY_PORT}'" ;;
esac

info "正在安装依赖 (curl, jq, openssl, coreutils)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y >/dev/null 2>&1 || warn "apt-get update 失败，继续尝试安装依赖"
    apt-get install -y curl jq openssl ca-certificates >/dev/null 2>&1 || warn "apt-get install 未完全成功"
elif [ -f /etc/redhat-release ]; then
    yum install -y curl jq openssl ca-certificates >/dev/null 2>&1 || warn "yum install 未完全成功"
fi
for cmd in curl jq openssl; do
    command -v "$cmd" >/dev/null 2>&1 || die "错误：缺少依赖 $cmd，请手动安装后重试。"
done

# --- 1.1 端口预检：443 被别的进程占用时先报出来 ---
port_owner() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p'
    fi
    return 0
}

owner="$(port_owner "$XRAY_PORT" | head -1)"
if [ -z "$owner" ]; then
    ok "端口 ${XRAY_PORT} 空闲。"
elif echo "$owner" | grep -qi 'xray' || systemctl is-active --quiet xray 2>/dev/null; then
    info "端口 ${XRAY_PORT} 当前由现有的 xray 占用（正常，重启服务后生效）。"
elif echo "$owner" | grep -q 'users:'; then
    # ss/netstat 能看到进程名，说明确实被别的程序占着
    err "端口 ${XRAY_PORT} 已被其它程序占用，REALITY 装好也起不来："
    echo "    $owner"
    echo "    处理办法：停掉该程序（如 nginx / docker 容器），或换端口重跑："
    echo "      XRAY_PORT=8443 bash install_Xray.sh   # 记得同时放行防火墙与安全组"
    exit 1
else
    # 容器里 ss 常常显示不出进程名，这里只提示不阻断；真冲突会在启动校验时回滚
    warn "端口 ${XRAY_PORT} 已在监听，但当前环境看不到占用进程名（容器里常见）。"
    warn "若启动失败，脚本会自动回滚到旧配置并打印日志。"
fi

# --- 2. 安装/更新 Xray 核心（锁定版本）---
info "正在安装 Xray 核心 ${XRAY_PIN_VERSION}（锁定版本，勿升级）..."
installer="$(mktemp)"
TMP_FILES+=("$installer")
curl -fsSL "$INSTALL_SCRIPT_URL" -o "$installer" || die "错误：下载 Xray 安装器失败，请检查网络：${INSTALL_SCRIPT_URL}"
[ -s "$installer" ] || die "错误：Xray 安装器下载内容为空。"
bash "$installer" @ install --version "${XRAY_PIN_VERSION}" || die "错误：Xray 安装失败（见上面的输出）。"
systemctl enable xray >/dev/null 2>&1 || true

# --- 2.1 版本校验：不是锁定版本就直接退出 ---
installed_version="$("$XRAY_BIN" -version 2>/dev/null | awk 'NR==1 {print $2}')"
# xray -version 输出形如 "Xray 26.6.27 (...)"，取到的版本不带 v 前缀，统一去掉再比
if [ "${installed_version#v}" != "${XRAY_PIN_VERSION#v}" ]; then
    err "错误：当前 Xray 版本为 ${installed_version:-未知}，不是锁定版本 ${XRAY_PIN_VERSION}。"
    err "      >= v26.7 的新版要求 ClientHello 携带 X25519MLKEM768，"
    err "      mihomo / sing-box(Karing) 等客户端会 REALITY 握手失败。"
    err "      请重新执行：bash -c \"\$(curl -L ${INSTALL_SCRIPT_URL})\" @ install --version ${XRAY_PIN_VERSION}"
    exit 1
fi
ok "Xray 版本校验通过：${installed_version}"

# --- 3. 交互式配置 ---
echo "=========================================="
echo "       Xray REALITY 极简安装向导"
echo "       (核心版本: ${XRAY_PIN_VERSION} 已锁定)"
echo "=========================================="

# 3.1 服务器地址：多源探测，避免单一 ip.sb 拉不到就没默认值
detect_ip() {
    local ip=""
    local src
    for src in "https://api.ipify.org" "https://ip.sb" "https://ifconfig.me/ip" "https://ipinfo.io/ip"; do
        ip="$(curl -fsS4m6 "$src" 2>/dev/null | tr -d '[:space:]')"
        if [ -n "$ip" ] && echo "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
            printf '%s' "$ip"; return 0
        fi
    done
    # 最后兜底：取默认路由的源地址
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
    printf '%s' "$ip"
}
default_ip="$(detect_ip)"
[ -n "$default_ip" ] || warn "未能自动探测本机公网 IP，请手动输入。"

SERVER_ADDR="${SERVER_ADDR:-$(ask "请输入服务器IP或绑定的域名[默认: ${default_ip:-无}]: " "$default_ip")}"
[ -n "$SERVER_ADDR" ] || die "错误：服务器地址为空，无法生成分享链接。"

FALLBACK_DOMAIN="${FALLBACK_DOMAIN:-$(ask "请输入伪装回落域名 (例: www.apple.com)[默认: www.amazon.com]: " "www.amazon.com")}"
[ -n "$FALLBACK_DOMAIN" ] || die "错误：回落域名为空。"

# 3.2 REALITY 对回落站点的硬要求：TLS 1.3 + HTTP/2，先探一下
check_tls13_h2() {
    local domain="$1" out=""
    command -v openssl >/dev/null 2>&1 || return 0   # 没有 openssl 就不拦
    out="$(timeout 12 openssl s_client -connect "${domain}:443" -servername "$domain" -tls1_3 -alpn h2 </dev/null 2>/dev/null)"
    echo "$out" | grep -q 'TLSv1.3' || return 1
    echo "$out" | grep -qi 'ALPN protocol: *h2' || return 2
    return 0
}
check_tls13_h2 "$FALLBACK_DOMAIN"
tls_rc=$?
if [ "$tls_rc" -eq 0 ]; then
    ok "回落域名 ${FALLBACK_DOMAIN} TLS1.3 + h2 探测通过。"
else
    if [ "$tls_rc" -eq 1 ]; then
        warn "回落域名 ${FALLBACK_DOMAIN} 似乎不支持 TLS 1.3（REALITY 硬性要求），握手大概率失败。"
    else
        warn "回落域名 ${FALLBACK_DOMAIN} 未协商出 h2（HTTP/2），部分客户端可能握手失败。"
    fi
    ans="$(ask "仍然继续安装? [Y/n]: " "y" "y")"
    case "${ans}" in [nN]*) die "已取消，请换一个支持 TLS1.3 + h2 的域名（如 www.apple.com / www.microsoft.com）。" ;; esac
fi

# 3.3 凭据：重跑时优先沿用旧配置，避免把已分发的客户端踢下线
xray_uuid=""; private_key=""; short_id=""
if [ -f "$CONFIG_FILE" ]; then
    old_uuid="$(jq -r '.inbounds[0].settings.clients[0].id // empty' "$CONFIG_FILE" 2>/dev/null)"
    old_pk="$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey // empty' "$CONFIG_FILE" 2>/dev/null)"
    old_sid="$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0] // empty' "$CONFIG_FILE" 2>/dev/null)"
    if [ -n "$old_uuid" ] && [ -n "$old_pk" ]; then
        info "检测到已有配置：UUID ${old_uuid:0:8}…  ShortId ${old_sid:-无}"
        reuse="${REUSE_CREDS:-$(ask "沿用现有 UUID / 私钥 / ShortId（推荐，客户端不用改）? [Y/n]: " "y" "y")}"
        case "$reuse" in
            [nN]*) info "将重新生成全部凭据，记得给客户端换新链接。" ;;
            *)     xray_uuid="$old_uuid"; private_key="$old_pk"; short_id="$old_sid"; ok "已沿用现有凭据。" ;;
        esac
    fi
fi

if [ -z "$xray_uuid" ]; then
    info "正在生成 UUID / REALITY 密钥 / ShortId..."
    xray_uuid="$("$XRAY_BIN" uuid)"
    keys="$("$XRAY_BIN" x25519)"
    # 兼容新旧两种输出格式：
    #   旧: Private key: xxx / Public key: yyy
    #   新: PrivateKey: xxx / Password (PublicKey): yyy / Hash32: zzz
    private_key="$(echo "$keys" | grep -E -i "Private key|PrivateKey" | head -1 | awk '{print $NF}')"
    short_id="$(openssl rand -hex 4)"
fi
[ -n "$xray_uuid" ] && [ -n "$private_key" ] || die "错误：UUID / 私钥生成失败。"

# 3.4 由私钥推导公钥（沿用旧凭据时也必须重新算出来给分享链接用）
public_key="$("$XRAY_BIN" x25519 -i "$private_key" 2>/dev/null | grep -E -i "Public key|Password" | head -1 | awk '{print $NF}')"
[ -n "$public_key" ] || die "错误：无法由私钥推导出公钥，请删除 ${CONFIG_FILE} 后重跑。"
[ -n "$short_id" ] || short_id="$(openssl rand -hex 4)"

# --- 4. 生成配置（模板失败则用内置模板）---
mkdir -p "$CONFIG_DIR"
BUILTIN_TEMPLATE='{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": { "clients": [{ "id": "PLACEHOLDER", "flow": "xtls-rprx-vision" }], "decryption": "none" },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false,
        "dest": "PLACEHOLDER:443",
        "xver": 0,
        "serverNames": ["PLACEHOLDER"],
        "privateKey": "PLACEHOLDER",
        "shortIds": ["PLACEHOLDER"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" }],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "outboundTag": "direct", "domain": ["geosite:geolocation-!cn"] },
      { "type": "field", "outboundTag": "block", "protocol": ["bittorrent"] },
      { "type": "field", "outboundTag": "block", "domain": ["geosite:category-ads", "geosite:cn"] },
      { "type": "field", "outboundTag": "block", "ip": ["geoip:private", "geoip:cn"] }
    ]
  }
}'

info "正在获取配置模板..."
remote_template="$(mktemp)"; TMP_FILES+=("$remote_template")
template_src=""
if curl -fsSL "$TEMPLATE_URL" -o "$remote_template" 2>/dev/null && jq -e . "$remote_template" >/dev/null 2>&1; then
    template_src="$remote_template"
    ok "已使用远程模板：${TEMPLATE_URL}"
else
    warn "远程模板不可用（下载失败或 JSON 非法），改用脚本内置模板。"
    template_src="$(mktemp)"; TMP_FILES+=("$template_src")
    printf '%s' "$BUILTIN_TEMPLATE" > "$template_src"
fi

# IPv6 可用则监听 ::（双栈），否则只监听 0.0.0.0
listen_addr="0.0.0.0"
if [ -f /proc/net/if_inet6 ] && awk '$1 !~ /^fe80/ && $6 != "lo" {found=1} END{exit !found}' /proc/net/if_inet6 2>/dev/null; then
    listen_addr="::"
fi

info "正在写入配置（端口 ${XRAY_PORT}，监听 ${listen_addr}）..."
new_cfg="${CONFIG_FILE}.new.$$.json"; TMP_FILES+=("$new_cfg")
jq --arg uuid "$xray_uuid" \
   --arg domain "$FALLBACK_DOMAIN" \
   --arg pk "$private_key" \
   --arg sid "$short_id" \
   --arg listen "$listen_addr" \
   --argjson port "$XRAY_PORT" \
   '.inbounds[0].settings.clients[0].id = $uuid |
    .inbounds[0].settings.clients[0].flow = "xtls-rprx-vision" |
    .inbounds[0].listen = $listen |
    .inbounds[0].port = $port |
    .inbounds[0].streamSettings.network = "tcp" |
    .inbounds[0].streamSettings.security = "reality" |
    .inbounds[0].streamSettings.realitySettings.dest = ($domain + ":443") |
    del(.inbounds[0].streamSettings.realitySettings.target) |
    .inbounds[0].streamSettings.realitySettings.serverNames = [$domain] |
    .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
    .inbounds[0].streamSettings.realitySettings.shortIds = [$sid]' \
   "$template_src" > "$new_cfg" || die "错误：jq 生成配置失败（模板结构异常）。"

# 4.1 落盘前校验：JSON 合法 + 关键字段齐全
jq -e '
  .inbounds[0].settings.clients[0].id != ""
  and .inbounds[0].streamSettings.realitySettings.privateKey != ""
  and (.inbounds[0].streamSettings.realitySettings.serverNames | length > 0)
  and (.inbounds[0].streamSettings.realitySettings.shortIds | length > 0)
  and .inbounds[0].port != null
' "$new_cfg" >/dev/null 2>&1 || die "错误：生成的配置缺少关键字段，已中止（未改动线上配置）。"

# 4.2 xray 自身自检（在临时文件上做，坏了也不影响线上）
if ! "$XRAY_BIN" run -test -c "$new_cfg" >/tmp/xray_cfg_test.log 2>&1; then
    err "错误：新配置未通过 Xray 自检，详情："
    cat /tmp/xray_cfg_test.log >&2
    exit 1
fi
rm -f /tmp/xray_cfg_test.log
chmod 600 "$new_cfg"
ok "配置生成并通过自检。"

# 4.3 备份旧配置（最多保留 BACKUP_KEEP 份）
if [ -f "$CONFIG_FILE" ]; then
    BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -a "$CONFIG_FILE" "$BACKUP_FILE" && chmod 600 "$BACKUP_FILE"
    info "旧配置已备份：${BACKUP_FILE}"
    ls -1t "${CONFIG_FILE}".bak.* 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)) | xargs -r rm -f
fi

# 4.4 原子替换
mv -f "$new_cfg" "$CONFIG_FILE" || die "错误：写入 ${CONFIG_FILE} 失败。"
ok "配置已写入 ${CONFIG_FILE}"

# --- 5. 重启服务并做二次校验 ---
info "正在重启 Xray 服务..."
systemctl restart xray || true

wait_active() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        systemctl is-active --quiet xray && return 0
        sleep 0.5
    done
    return 1
}

rollback() {
    if [ -z "$BACKUP_FILE" ] || [ ! -f "$BACKUP_FILE" ]; then
        warn "首次安装没有可回滚的旧配置，请按上面的日志排查（配置文件在 ${CONFIG_FILE}）。"
        return 1
    fi
    warn "正在回滚到上一份配置：${BACKUP_FILE}"
    cp -a "$BACKUP_FILE" "$CONFIG_FILE" && chmod 600 "$CONFIG_FILE"
    systemctl restart xray >/dev/null 2>&1 || true
    if systemctl is-active --quiet xray; then
        ok "回滚成功，服务已恢复到改动前的状态。"
    else
        err "回滚后服务仍未起来，请手工排查：journalctl -u xray -e"
    fi
    return 0
}

failure_reason=""
if ! wait_active; then
    failure_reason="服务未能进入 active 状态"
elif ! (port_owner "$XRAY_PORT" | grep -qi 'xray'); then
    failure_reason="服务是 active 的，但端口 ${XRAY_PORT} 没有在监听"
else
    sleep 3
    systemctl is-active --quiet xray || failure_reason="启动 3 秒内进程退出（疑似配置错误崩溃）"
fi

if [ -n "$failure_reason" ]; then
    err "错误：Xray 启动失败 —— ${failure_reason}"
    echo "----- journalctl -u xray -n 20 -----" >&2
    journalctl -u xray -n 20 --no-pager 2>/dev/null >&2 || true
    echo "-----------------------------------" >&2
    rollback
    exit 1
fi
ok "Xray 启动成功，端口 ${XRAY_PORT} 正在监听。"

# --- 6. 生成分享链接并保存 ---
VLESS_LINK="vless://${xray_uuid}@${SERVER_ADDR}:${XRAY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${FALLBACK_DOMAIN}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#Xray-${SERVER_ADDR}"
printf '%s\n' "$VLESS_LINK" > "$LINK_FILE"
chmod 600 "$LINK_FILE"

cat > /usr/local/bin/link <<EOF
#!/bin/bash
echo "========================================================"
echo " Xray 配置信息 (读取自: $LINK_FILE)"
echo " 核心版本: ${XRAY_PIN_VERSION} (已锁定，勿升级到 >= v26.7)"
echo "========================================================"
echo "地址 (Address): $SERVER_ADDR"
echo "端口 (Port)   : ${XRAY_PORT}"
echo "用户ID (UUID) : $xray_uuid"
echo "流控 (Flow)   : xtls-rprx-vision"
echo "伪装域名 (SNI): $FALLBACK_DOMAIN"
echo "公钥 (PbK)    : $public_key"
echo "ShortId       : $short_id"
echo "--------------------------------------------------------"
echo "分享链接 (直接复制到客户端):"
echo ""
cat $LINK_FILE
echo ""
echo "========================================================"
EOF
chmod +x /usr/local/bin/link

# --- 6.1 版本巡检命令：被意外升级时可以一眼发现 ---
cat > /usr/local/bin/xray-version-check <<EOF
#!/bin/bash
PINNED="${XRAY_PIN_VERSION#v}"
CURRENT="\$(${XRAY_BIN} -version 2>/dev/null | awk 'NR==1 {print \$2}')"
if [ "\${CURRENT#v}" = "\$PINNED" ]; then
    echo "OK: Xray \$CURRENT (锁定版本)"
    exit 0
fi
echo "警告: Xray 当前 \$CURRENT，锁定版本应为 \$PINNED。"
echo "      >= v26.7 要求 ClientHello 携带 X25519MLKEM768，mihomo/sing-box(Karing) 会握手失败。"
echo "      修复: bash -c \"\\\$(curl -L ${INSTALL_SCRIPT_URL})\" @ install --version \$PINNED"
exit 1
EOF
chmod +x /usr/local/bin/xray-version-check

# --- 6.2 防火墙提示（只提示，不改你的规则）---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    ufw status 2>/dev/null | grep -q "${XRAY_PORT}" || \
        warn "检测到 ufw 已启用但未放行 ${XRAY_PORT}：ufw allow ${XRAY_PORT}/tcp"
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --list-ports 2>/dev/null | grep -q "${XRAY_PORT}/tcp" || \
        warn "检测到 firewalld 已启用但未放行 ${XRAY_PORT}：firewall-cmd --permanent --add-port=${XRAY_PORT}/tcp && firewall-cmd --reload"
fi
warn "云厂商账号（Oracle/AWS/阿里云等）的安全组请自行放行 ${XRAY_PORT}/tcp。"

# --- 7. 显示结果 ---
link
echo ""
ok "安装完成！"
echo "以后如果忘记了链接，直接在终端输入命令: link 即可查看。"
echo "想确认核心版本有没有被意外升级，执行: xray-version-check"
if [ -n "$BACKUP_FILE" ]; then echo "本次改动前的配置备份在: $BACKUP_FILE"; fi
