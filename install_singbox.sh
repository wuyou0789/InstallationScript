#!/bin/bash
# ============================================================================
#  sing-box VLESS + REALITY 安装脚本（systemd Linux）
# ----------------------------------------------------------------------------
#  核心版本默认装「最新稳定版」；要固定版本（可复现部署）：SINGBOX_VERSION=1.14.4 bash ...
#
#  ★ 路由策略（本脚本的重点，按顺序判定）
#    1) sniff
#    2) 来源 IP 属于中国 → reject        ← 国内进来的流量直接丢弃（必须）
#    3) bittorrent → reject
#    4) 广告域名 → reject
#    5) 目标为私有地址 → reject
#    6) Google / Apple / Microsoft / GitHub / OpenAI 等「在中国也可能有节点」的外网服务
#       → direct（排在所有国内判定之前，避免 Google 登录这类流程被误判成国内）
#    7) 目标属于国内域名（geosite-geolocation-cn）→ direct
#    8) 目标解析到国内 IP（geoip-cn）→ direct
#    9) 其余 → direct
#
#    第 7/8 条默认 direct：朋友忘关 VPN、没开分流去看淘宝，脚本不会把这条连接打断。
#    想改成「国内目标也丢弃」以省流量：DROP_CN_DEST=1 bash install_singbox.sh
#    （第 6 条白名单仍然优先，Google 登录不会被误杀）
#
#  ★ 可用环境变量覆盖（便于自动化 / 无人值守）
#    SINGBOX_VERSION=latest   核心版本（默认 latest=最新稳定版，也可写 1.14.4 固定）
#    SINGBOX_REINSTALL=1      即使版本一致也强制重新下载安装
#    MAIN_PORT=443            主端口
#    BACKUP_PORT=8443         备用端口（设空字符串可关闭）
#    SERVER_ADDR=1.2.3.4      分享链接里的服务器地址（免交互）
#    FALLBACK_DOMAIN=www.apple.com
#    REUSE_CREDS=y|n          重跑时是否沿用现有凭据
#    DROP_CN_DEST=1           国内目标也直接丢弃（默认 0=直连不打断）
#    ALLOW_NO_GEODATA=1       geo 数据拉取失败时允许降级运行（不推荐）
#
#  ★ 可靠性（与 install_Xray.sh 同一套）
#    端口预检 / 幂等沿用凭据 / 发布包 SHA256 校验 / geo 数据本地预取
#    原子写配置 + sing-box check + 备份 + 启动校验 + 失败自动回滚
#    双端口冗余（443 + 8443），443 被封时还有备用入口
# ============================================================================

set -o pipefail
umask 077

readonly BIN="/usr/local/bin/sing-box"
readonly ETC="/usr/local/etc/sing-box"
readonly CFG="$ETC/config.json"
readonly RULE_DIR="$ETC/rule-set"
readonly DATA="/var/lib/sing-box"
readonly UNIT="/etc/systemd/system/sing-box.service"
readonly LINK_FILE="$ETC/share_link.txt"

readonly SINGBOX_VERSION="${SINGBOX_VERSION:-latest}"
readonly MAIN_PORT="${MAIN_PORT:-443}"
readonly BACKUP_PORT="${BACKUP_PORT:-8443}"
readonly DROP_CN_DEST="${DROP_CN_DEST:-0}"
readonly ALLOW_NO_GEODATA="${ALLOW_NO_GEODATA:-0}"
readonly BACKUP_KEEP=5

TMP_DIRS=()
BACKUP_DIR=""
cleanup() {
    local d
    for d in "${TMP_DIRS[@]:-}"; do [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d"; done
}
trap cleanup EXIT

# --- 0. 输出与交互 ---
info() { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
warn() { echo "[!] $*"; }
err()  { echo "[x] $*" >&2; }
die()  { err "$*"; exit 1; }

# 注意：本函数常被 $( ) 调用（例如 SERVER="$(ask ...)"），
# 因此提示语必须写到 /dev/tty，写到 stdout 会被命令替换吞掉，用户只会看到光标发呆。
ask() {
    local prompt="$1" default="$2" noninteractive="${3:-$2}" ans=""
    if { [ -c /dev/tty ] && exec 3<>/dev/tty; } 2>/dev/null; then
        printf '%s' "$prompt" >&3
        IFS= read -r ans <&3 || ans=""
        exec 3>&- || true
        printf '%s' "${ans:-$default}"
    else
        if [ "${NONINTERACTIVE_WARNED:-0}" != "1" ]; then
            warn "当前环境没有可用的终端（/dev/tty），后续交互全部使用默认值。" >&2
            NONINTERACTIVE_WARNED=1
        fi
        printf '%s' "$noninteractive"
    fi
}

port_owner() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltnp 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p'
    fi
    return 0
}
service_running() { systemctl is-active --quiet sing-box 2>/dev/null; }

# --- 1. 平台与依赖 ---
[ "$EUID" -eq 0 ] || die "请使用 root 运行。"
case "$MAIN_PORT" in ''|*[!0-9]*) die "MAIN_PORT 必须是数字：'${MAIN_PORT}'" ;; esac
case "$BACKUP_PORT" in ''|*[!0-9]*) die "BACKUP_PORT 必须是数字或留空：'${BACKUP_PORT}'" ;; esac
[ "$MAIN_PORT" = "$BACKUP_PORT" ] && BACKUP_PORT=""

[ -d /run/systemd/system ] || warn "未检测到运行中的 systemd，本脚本按 systemd 方式部署。"

case "$(uname -m)" in
    x86_64|amd64)  SB_ARCH="amd64" ;;
    aarch64|arm64) SB_ARCH="arm64" ;;
    armv7l|armv7)  SB_ARCH="armv7" ;;
    *) die "暂不支持 CPU 架构：$(uname -m)" ;;
esac

info "正在安装依赖 (curl, jq, openssl, tar, ca-certificates)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y >/dev/null 2>&1 || warn "apt-get update 失败，继续尝试安装依赖"
    apt-get install -y curl jq openssl tar ca-certificates iproute2 >/dev/null 2>&1 || warn "apt-get install 未完全成功"
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl jq openssl tar ca-certificates iproute >/dev/null 2>&1 || warn "dnf install 未完全成功"
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq openssl tar ca-certificates iproute >/dev/null 2>&1 || warn "yum install 未完全成功"
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl jq openssl tar ca-certificates iproute2 >/dev/null 2>&1 || warn "apk add 未完全成功"
fi
for c in curl jq openssl tar; do command -v "$c" >/dev/null 2>&1 || die "缺少命令：$c"; done

# --- 2. 端口预检 ---
check_port() {
    local port="$1" role="$2" owner
    [ -n "$port" ] || return 0
    owner="$(port_owner "$port" | head -1)"
    [ -n "$owner" ] || { ok "${role}端口 ${port} 空闲。"; return 0; }
    if echo "$owner" | grep -qi 'sing-box' || service_running; then
        info "${role}端口 ${port} 由现有的 sing-box 占用（正常，重启后生效）。"
    elif echo "$owner" | grep -q 'users:'; then
        err "${role}端口 ${port} 已被其它程序占用："
        echo "    $owner"
        echo "    先停掉它，或换端口重跑：MAIN_PORT=8443 BACKUP_PORT=8444 bash install_singbox.sh"
        return 1
    else
        warn "${role}端口 ${port} 已在监听但看不到进程名（容器里常见），继续；失败会自动回滚。"
    fi
    return 0
}
check_port "$MAIN_PORT" "主" || exit 1
check_port "$BACKUP_PORT" "备用" || exit 1

# --- 3. 安装核心（SHA256 校验；版本一致时跳过下载）---
if [ "$SINGBOX_VERSION" = "latest" ]; then
    info "正在查询 sing-box 最新稳定版..."
    TAG="$(curl -fsSL --retry 3 --connect-timeout 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
           | jq -r '.tag_name // empty' 2>/dev/null)"
    if [ -z "$TAG" ]; then
        die "获取 sing-box 最新版本号失败。可显式指定版本重试：SINGBOX_VERSION=1.14.4 bash $0"
    fi
    info "最新稳定版：${TAG}"
else
    TAG="v${SINGBOX_VERSION#v}"
fi
ASSET="sing-box-${TAG#v}-linux-${SB_ARCH}.tar.gz"
URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/${ASSET}"

current_version="$("$BIN" version 2>/dev/null | awk '/sing-box version/ {print $3; exit}')"
if [ "${current_version}" = "${TAG#v}" ] && [ "${SINGBOX_REINSTALL:-0}" != "1" ]; then
    installed_version="$current_version"
    ok "已安装 sing-box ${installed_version}，跳过下载（要强制重装：SINGBOX_REINSTALL=1）"
else
info "正在下载 sing-box ${TAG} (${SB_ARCH})..."
WORK="$(mktemp -d)"; TMP_DIRS+=("$WORK")
curl -fsSL --retry 3 --connect-timeout 15 -o "$WORK/$ASSET" "$URL" || die "下载失败：$URL"

digest="$(curl -fsSL --retry 2 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/${TAG}" 2>/dev/null \
          | jq -r --arg a "$ASSET" '.assets[]? | select(.name==$a) | .digest // empty' 2>/dev/null | head -n1)"
if [ -n "$digest" ]; then
    case "$digest" in sha256:*) ;; *) die "发布页 digest 格式异常：$digest" ;; esac
    echo "${digest#sha256:}  $WORK/$ASSET" | sha256sum -c - >/dev/null 2>&1 || die "SHA256 校验失败，安装包不完整。"
    ok "安装包 SHA256 校验通过。"
else
    tar -tzf "$WORK/$ASSET" >/dev/null 2>&1 || die "下载归档无法读取。"
    warn "该 Release 未提供 digest，已改为归档完整性检查。"
fi

tar -xzf "$WORK/$ASSET" -C "$WORK" || die "解压失败。"
extracted="$WORK/sing-box-${TAG#v}-linux-${SB_ARCH}/sing-box"
[ -x "$extracted" ] || die "归档中未找到 sing-box 可执行文件。"
install -m 0755 "$extracted" "$BIN"

installed_version="$("$BIN" version 2>/dev/null | awk '/sing-box version/ {print $3; exit}')"
[ "${installed_version}" = "${TAG#v}" ] || die "安装版本不符：期望 ${TAG#v}，实际 ${installed_version:-未知}"
ok "sing-box ${installed_version} 安装完成。"
fi
mkdir -p "$ETC"
printf '%s\n' "$installed_version" > "$ETC/script-installed-version"

# 只有「发行版包管理器装的」sing-box 服务才需要关掉，避免误停我们自己的 unit
pkg_unit="$(systemctl show -p FragmentPath sing-box.service 2>/dev/null | cut -d= -f2)"
case "$pkg_unit" in
    /lib/systemd/*|/usr/lib/systemd/*)
        info "检测到发行版安装的 sing-box 服务（${pkg_unit}），先停用以免抢端口。"
        systemctl disable --now sing-box >/dev/null 2>&1 || true ;;
esac

# --- 4. 交互与凭据 ---
echo "=========================================="
echo "     sing-box REALITY 安装向导"
echo "     (核心版本: ${installed_version})"
echo "=========================================="

detect_ip() {
    local ip src
    for src in "https://api.ipify.org" "https://ip.sb" "https://ifconfig.me/ip" "https://ipinfo.io/ip"; do
        ip="$(curl -fsS4m6 "$src" 2>/dev/null | tr -d '[:space:]')"
        if [ -n "$ip" ] && echo "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then printf '%s' "$ip"; return 0; fi
    done
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')"
    printf '%s' "$ip"
}
default_ip="$(detect_ip)"
[ -n "$default_ip" ] || warn "未能自动探测公网 IP，请手动输入。"

SERVER_ADDR="${SERVER_ADDR:-$(ask "请输入服务器IP或域名[默认: ${default_ip:-无}]: " "$default_ip")}"
[ -n "$SERVER_ADDR" ] || die "服务器地址为空。"

FALLBACK_DOMAIN="${FALLBACK_DOMAIN:-$(ask "请输入伪装回落域名[默认: www.amazon.com]: " "www.amazon.com")}"
[ -n "$FALLBACK_DOMAIN" ] || die "回落域名为空。"

check_tls13_h2() {
    local domain="$1" out=""
    command -v openssl >/dev/null 2>&1 || return 0
    out="$(timeout 12 openssl s_client -connect "${domain}:443" -servername "$domain" -tls1_3 -alpn h2 </dev/null 2>/dev/null)"
    echo "$out" | grep -q 'TLSv1.3' || return 1
    echo "$out" | grep -qi 'ALPN protocol: *h2' || return 2
    return 0
}
check_tls13_h2 "$FALLBACK_DOMAIN"; tls_rc=$?
if [ "$tls_rc" -eq 0 ]; then
    ok "回落域名 ${FALLBACK_DOMAIN} TLS1.3 + h2 探测通过。"
else
    if [ "$tls_rc" -eq 1 ]; then
        warn "回落域名 ${FALLBACK_DOMAIN} 似乎不支持 TLS 1.3（REALITY 硬要求）。"
    else
        warn "回落域名 ${FALLBACK_DOMAIN} 未协商出 h2（HTTP/2）。"
    fi
    ans="$(ask "仍然继续? [Y/n]: " "y" "y")"
    case "$ans" in [nN]*) die "已取消。换 www.apple.com / www.microsoft.com 这类站点更稳。" ;; esac
fi

uuid=""; private_key=""; short_id=""; public_key=""
if [ -f "$CFG" ]; then
    old_uuid="$(jq -r '.inbounds[0].users[0].uuid // empty' "$CFG" 2>/dev/null)"
    old_pk="$(jq -r '.inbounds[0].tls.reality.private_key // empty' "$CFG" 2>/dev/null)"
    old_sid="$(jq -r '.inbounds[0].tls.reality.short_id[0] // empty' "$CFG" 2>/dev/null)"
    old_pbk="$(grep -oE 'pbk=[^&]+' "$LINK_FILE" 2>/dev/null | head -1 | cut -d= -f2)"
    if [ -n "$old_uuid" ] && [ -n "$old_pk" ] && [ -n "$old_pbk" ]; then
        info "检测到已有配置：UUID ${old_uuid:0:8}…  ShortId ${old_sid:-无}"
        reuse="${REUSE_CREDS:-$(ask "沿用现有 UUID / 私钥 / ShortId（推荐，客户端不用改）? [Y/n]: " "y" "y")}"
        case "$reuse" in
            [nN]*) info "将重新生成全部凭据，记得给客户端换新链接。" ;;
            *) uuid="$old_uuid"; private_key="$old_pk"; short_id="$old_sid"; public_key="$old_pbk"
               ok "已沿用现有凭据。" ;;
        esac
    elif [ -f "$CFG" ]; then
        warn "旧配置存在但缺少可用凭据或分享链接，将重新生成。"
    fi
fi
if [ -z "$uuid" ]; then
    info "正在生成 UUID / REALITY 密钥 / ShortId..."
    uuid="$("$BIN" generate uuid)"
    keypair="$("$BIN" generate reality-keypair)"
    private_key="$(echo "$keypair" | grep -i '^PrivateKey' | head -1 | awk '{print $NF}')"
    public_key="$(echo "$keypair" | grep -i '^PublicKey' | head -1 | awk '{print $NF}')"
    short_id="$("$BIN" generate rand --hex 4)"
fi
[ -n "$uuid" ] && [ -n "$private_key" ] && [ -n "$public_key" ] && [ -n "$short_id" ] \
    || die "UUID / 密钥 / ShortId 生成失败。"

# --- 5. 预取 geo 数据（本地文件，启动时不再依赖网络）---
mkdir -p "$ETC" "$DATA" "$RULE_DIR"
GEO_SETS="geoip-cn geosite-geolocation-cn geosite-category-ads-all geosite-google geosite-apple geosite-microsoft geosite-github geosite-openai"

geo_url() {
    case "$1" in
        geoip-*) printf 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/%s.srs' "$1" ;;
        *)       printf 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/%s.srs' "$1" ;;
    esac
}
geo_have() {
    local f="$RULE_DIR/$1.srs"
    [ -s "$f" ] && [ "$(head -c 3 "$f" 2>/dev/null)" = "SRS" ]
}
geo_download() {
    local name="$1" url f
    url="$(geo_url "$name")"
    f="$RULE_DIR/${name}.srs"
    geo_have "$name" && return 0
    curl -fsSL --retry 3 --connect-timeout 15 -o "$f.tmp" "$url" 2>/dev/null || { rm -f "$f.tmp"; return 1; }
    if [ ! -s "$f.tmp" ] || [ "$(head -c 3 "$f.tmp" 2>/dev/null)" != "SRS" ]; then
        rm -f "$f.tmp"; return 1
    fi
    mv -f "$f.tmp" "$f" && chmod 0644 "$f"
}

info "正在预取 geo 数据到 ${RULE_DIR}（用于「国内来源丢弃」等规则）..."
geo_fail=""
for s in $GEO_SETS; do
    if geo_download "$s"; then printf '.'; else geo_fail="$geo_fail $s"; printf 'x'; fi
done
printf '\n'

if [ -n "$geo_fail" ]; then
    if [ "$ALLOW_NO_GEODATA" = "1" ]; then
        warn "以下数据不可用，相关规则将被跳过：${geo_fail}"
        case "$geo_fail" in *geoip-cn*)
            err "geoip-cn 缺失 → 「国内来源丢弃」规则会失效，请确认你接受这个降级。"
            ;;
        esac
    else
        err "以下 geo 数据下载失败：${geo_fail}"
        err "国内来源丢弃依赖 geoip-cn，不能静默跳过。请检查到 raw.githubusercontent.com 的网络；"
        err "确认可以接受降级运行后，加 ALLOW_NO_GEODATA=1 重跑。"
        exit 1
    fi
else
    ok "geo 数据就绪。"
fi
geo_have geoip-cn || warn "缺少 geoip-cn，来源丢弃规则不会生效！"

# --- 6. 生成配置（jq 组装，避免手写 JSON 出错）---
rulesets_json='[]'
for s in $GEO_SETS; do
    geo_have "$s" || continue
    rulesets_json="$(jq -c --arg t "$s" --arg p "$RULE_DIR/$s.srs" \
        '. + [{type:"local", tag:$t, format:"binary", path:$p}]' <<<"$rulesets_json")"
done

wl_json='[]'
for s in geosite-google geosite-apple geosite-microsoft geosite-github geosite-openai; do
    geo_have "$s" && wl_json="$(jq -c --arg t "$s" '. + [$t]' <<<"$wl_json")"
done

if [ "$DROP_CN_DEST" = "1" ]; then
    CN_ACTION="reject"; CN_DESC="丢弃（DROP_CN_DEST=1，省出口流量）"
else
    CN_ACTION="route";  CN_DESC="直连（不打断：朋友忘关 VPN 也能开淘宝）"
fi

info "正在写入配置（主端口 ${MAIN_PORT}${BACKUP_PORT:+，备用端口 ${BACKUP_PORT}}，国内目标策略=${CN_ACTION}）..."
new_cfg="${CFG}.new.$$.json"
TMP_DIRS+=("$new_cfg")
jq -n \
  --arg uuid "$uuid" --arg sni "$FALLBACK_DOMAIN" --arg pk "$private_key" --arg sid "$short_id" \
  --argjson p1 "$MAIN_PORT" --argjson p2 "${BACKUP_PORT:-0}" \
  --arg cn_action "$CN_ACTION" --argjson wl "$wl_json" --argjson rulesets "$rulesets_json" \
  --argjson has_geoipcn "$(geo_have geoip-cn && echo true || echo false)" \
  --argjson has_geosite_cn "$(geo_have geosite-geolocation-cn && echo true || echo false)" \
  --argjson has_ads "$(geo_have geosite-category-ads-all && echo true || echo false)" \
  '
  def inb($tag; $port):
    { type: "vless", tag: $tag, listen: "::", listen_port: $port,
      users: [ { uuid: $uuid, flow: "xtls-rprx-vision" } ],
      tls: { enabled: true, server_name: $sni,
             reality: { enabled: true,
                        handshake: { server: $sni, server_port: 443 },
                        private_key: $pk, short_id: [ $sid ] } } };

  ( [ inb("vless-main"; $p1) ] + (if $p2 > 0 then [ inb("vless-backup"; $p2) ] else [] end) ) as $inbounds
  | ( [ { action: "sniff" } ]
      + (if $has_geoipcn then
           [ { rule_set: ["geoip-cn"], rule_set_ip_cidr_match_source: true, action: "reject" } ]
         else [] end)
      + [ { protocol: ["bittorrent"], action: "reject" } ]
      + (if $has_ads then [ { rule_set: ["geosite-category-ads-all"], action: "reject" } ] else [] end)
      + [ { ip_is_private: true, action: "reject" } ]
      + (if ($wl | length) > 0 then
           [ { rule_set: $wl, action: "route", outbound: "direct" } ]
         else [] end)
      + (if $has_geosite_cn then
           [ (if $cn_action == "route"
              then { rule_set: ["geosite-geolocation-cn"], action: "route", outbound: "direct" }
              else { rule_set: ["geosite-geolocation-cn"], action: "reject" } end) ]
         else [] end)
      + (if $has_geoipcn then
           [ (if $cn_action == "route"
              then { rule_set: ["geoip-cn"], action: "route", outbound: "direct" }
              else { rule_set: ["geoip-cn"], action: "reject" } end) ]
         else [] end)
    ) as $rules
  | { log: { level: "warn", timestamp: true },
      inbounds: $inbounds,
      outbounds: [ { type: "direct", tag: "direct" } ],
      route: { rules: $rules, rule_set: $rulesets, final: "direct", auto_detect_interface: true } }
  ' > "$new_cfg" || die "jq 生成配置失败。"

# 6.1 结构校验：JSON 合法 + 关键字段齐全
jq -e '
  (.inbounds | length) >= 1
  and .inbounds[0].users[0].uuid != ""
  and .inbounds[0].tls.reality.private_key != ""
  and (.inbounds[0].tls.reality.short_id | length) > 0
  and (.route.rules | length) >= 3
' "$new_cfg" >/dev/null 2>&1 || die "生成的配置缺少关键字段，已中止（线上配置未改动）。"

# 6.2 sing-box 自检（在临时文件上做）
if ! "$BIN" check -c "$new_cfg"; then
    err "新配置未通过 sing-box check，已中止（线上配置未改动）。"
    exit 1
fi
chmod 0640 "$new_cfg" 2>/dev/null || chmod 0600 "$new_cfg"
ok "配置生成并通过自检。"

# --- 7. 备份 → 原子替换 → 重启 → 校验（失败回滚）---
if [ -f "$CFG" ] || [ -f "$UNIT" ] || [ -x "$BIN" ]; then
    BACKUP_DIR="/root/sing-box-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    [ ! -f "$CFG" ]  || cp -a "$CFG"  "$BACKUP_DIR/config.json"
    [ ! -f "$UNIT" ] || cp -a "$UNIT" "$BACKUP_DIR/sing-box.service"
    [ ! -x "$BIN" ]  || cp -a "$BIN"  "$BACKUP_DIR/sing-box"
    info "已备份现有文件：${BACKUP_DIR}"
    # 只保留最近 BACKUP_KEEP 份备份
    ls -1dt /root/sing-box-backup-* 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)) | xargs -r rm -rf
fi

cat > "$UNIT" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} run -c ${CFG}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

mv -f "$new_cfg" "$CFG" || die "写入 ${CFG} 失败。"
chmod 0640 "$CFG" 2>/dev/null || chmod 0600 "$CFG"
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable sing-box >/dev/null 2>&1 || true
systemctl restart sing-box >/dev/null 2>&1 || true

wait_active() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        service_running && return 0
        sleep 0.5
    done
    return 1
}

rollback() {
    if [ -z "$BACKUP_DIR" ] || [ ! -f "$BACKUP_DIR/config.json" ]; then
        warn "首次安装没有可回滚的旧配置，请按上面的日志排查（配置在 ${CFG}）。"
        return 1
    fi
    warn "正在回滚：${BACKUP_DIR} → 线上"
    cp -a "$BACKUP_DIR/config.json" "$CFG"
    [ ! -f "$BACKUP_DIR/sing-box.service" ] || cp -a "$BACKUP_DIR/sing-box.service" "$UNIT"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart sing-box >/dev/null 2>&1 || true
    if service_running; then ok "回滚成功，服务已恢复到改动前状态。"; else err "回滚后仍起不来：journalctl -u sing-box -e"; fi
    return 0
}

failure=""
wait_port() {
    local port="$1" i
    for i in $(seq 1 30); do
        [ -n "$(port_owner "$port")" ] && return 0
        sleep 0.5
    done
    return 1
}

if ! wait_active; then
    failure="服务未能进入 active 状态"
elif ! wait_port "$MAIN_PORT"; then
    failure="主端口 ${MAIN_PORT} 在 15 秒内没有开始监听"
elif [ -n "$BACKUP_PORT" ] && ! wait_port "$BACKUP_PORT"; then
    failure="备用端口 ${BACKUP_PORT} 在 15 秒内没有开始监听"
else
    sleep 3
    service_running || failure="启动 3 秒内进程退出（疑似配置或 geo 数据问题）"
fi

if [ -n "$failure" ]; then
    err "错误：sing-box 启动失败 —— ${failure}"
    echo "----- journalctl -u sing-box -n 20 -----" >&2
    journalctl -u sing-box -n 20 --no-pager 2>/dev/null >&2 || true
    echo "---------------------------------------" >&2
    rollback
    exit 1
fi
ok "sing-box 启动成功：主端口 ${MAIN_PORT}$( [ -n "$BACKUP_PORT" ] && printf ' / 备用端口 %s' "$BACKUP_PORT" ) 均在监听。"

# --- 8. 分享链接 ---
link_for_port() {
    local port="$1" tag="$2"
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&headerType=none#%s-%s\n' \
        "$uuid" "$SERVER_ADDR" "$port" "$FALLBACK_DOMAIN" "$public_key" "$short_id" "$tag" "$SERVER_ADDR"
}
{
    link_for_port "$MAIN_PORT" "singbox"
    [ -n "$BACKUP_PORT" ] && link_for_port "$BACKUP_PORT" "singbox-backup"
} > "$LINK_FILE"
chmod 0600 "$LINK_FILE"

cat > /usr/local/bin/sblink <<EOF
#!/bin/bash
echo "========================================================"
echo " sing-box 配置信息 (读取自: $LINK_FILE)"
echo " 核心版本: ${installed_version}"
echo "========================================================"
echo "地址 (Address): $SERVER_ADDR"
echo "主端口        : ${MAIN_PORT}$( [ -n "$BACKUP_PORT" ] && printf '   备用端口: %s' "$BACKUP_PORT" )"
echo "用户ID (UUID) : $uuid"
echo "流控 (Flow)   : xtls-rprx-vision"
echo "伪装域名 (SNI): $FALLBACK_DOMAIN"
echo "公钥 (PbK)    : $public_key"
echo "ShortId       : $short_id"
echo "--------------------------------------------------------"
echo "路由策略："
echo "  · 来源 IP 属于中国      → 丢弃"
echo "  · Google/Apple/MS/GitHub/OpenAI 等 → 直连（不受国内判定影响）"
echo "  · 国内域名 / 国内 IP    → ${CN_DESC}"
echo "  · 其余                  → 直连"
echo "--------------------------------------------------------"
echo "分享链接:"
echo ""
cat $LINK_FILE
echo ""
echo "========================================================"
EOF
chmod +x /usr/local/bin/sblink

cat > /usr/local/bin/singbox-version-check <<EOF
#!/bin/bash
# 与「本脚本安装时记录的版本」比对，被意外改动时可一眼发现
RECORD="${ETC}/script-installed-version"
WANT="\$(cat "\$RECORD" 2>/dev/null || echo '${installed_version}')"
CUR="\$(${BIN} version 2>/dev/null | awk '/sing-box version/ {print \$3; exit}')"
LATEST="\$(curl -fsSL -m 8 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null | sed 's/^v//')"
echo "已安装: \$CUR   由本脚本安装: \$WANT   当前最新稳定版: \${LATEST:-未知}"
if [ "\$CUR" = "\$WANT" ]; then
    echo "OK"
    exit 0
fi
echo "提示: 版本与脚本安装时不一致（可能有手动升级/降级）。重跑 install_singbox.sh 可回到统一状态。"
exit 1
EOF
chmod +x /usr/local/bin/singbox-version-check

# --- 9. 防火墙提示（只提示，不改你的规则）---
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
    for p in $MAIN_PORT $BACKUP_PORT; do
        ufw status 2>/dev/null | grep -q "$p" || warn "ufw 未放行 ${p}：ufw allow ${p}/tcp"
    done
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    for p in $MAIN_PORT $BACKUP_PORT; do
        firewall-cmd --list-ports 2>/dev/null | grep -q "${p}/tcp" || \
            warn "firewalld 未放行 ${p}：firewall-cmd --permanent --add-port=${p}/tcp && firewall-cmd --reload"
    done
fi
warn "云厂商安全组请自行放行 ${MAIN_PORT}${BACKUP_PORT:+, $BACKUP_PORT}/tcp。"

# --- 10. 结果 ---
/usr/local/bin/sblink
echo ""
ok "安装完成！"
echo "查看链接: sblink    版本巡检: singbox-version-check"
echo "服务管理: systemctl {status|restart|stop} sing-box    日志: journalctl -u sing-box -e"
echo "geo 数据: ${RULE_DIR}（升级方式：删除该目录下对应 .srs 后重跑本脚本）"
if [ -n "$BACKUP_DIR" ]; then echo "改动前备份: ${BACKUP_DIR}"; fi
