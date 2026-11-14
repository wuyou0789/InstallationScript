#!/bin/bash
# ============================================================================
#  sing-box REALITY 极简安装脚本（与 install_Xray.sh 同款流程）
# ----------------------------------------------------------------------------
#  为什么提供 sing-box 版本：
#    Xray-core >= v26.7 收紧 REALITY 的 ClientHello 校验，v26.9.8 起服务端要求
#    key_share 必须携带 X25519MLKEM768。mihomo 默认剥掉 MLKEM，sing-box/Karing
#    也不发 MLKEM，于是握手失败（表现为「节点连上但打不开网页 / 像打开真网站」）。
#    Xray 侧的解法是锁 v26.6.27（见 install_Xray.sh）。
#    sing-box 作为服务端没有这个版本坑，实测同时兼容：
#      · sing-box 内核客户端（Karing / sing-box / Shadowrocket 等）
#      · mihomo（Clash Meta，含默认 MLKEM 关闭状态）
#      · 各版本 Xray 内核客户端（v2rayN / v2rayNG / NekoBox 等）
#  参考：https://github.com/MetaCubeX/mihomo/issues/3193
# ============================================================================

set -o pipefail

# 想固定 sing-box 版本就改成 v1.14.4 这种具体版本号，留 latest 表示装最新版
readonly SINGBOX_VERSION="${SINGBOX_VERSION:-latest}"
readonly LISTEN_PORT="${LISTEN_PORT:-443}"

# --- 1. 基础检查与环境准备 ---
if [ "$EUID" -ne 0 ]; then
    echo "错误：必须使用 root 权限运行此脚本。"
    exit 1
fi

echo "正在安装依赖 (curl, jq, openssl, tar)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y && apt-get install -y curl jq openssl tar
elif [ -f /etc/redhat-release ]; then
    yum install -y curl jq openssl tar
fi

for cmd in curl jq openssl tar; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "错误：缺少依赖 $cmd"; exit 1; }
done

# --- 2. 下载并安装 sing-box 核心 ---
case "$(uname -m)" in
    x86_64|amd64)  SB_ARCH="amd64" ;;
    aarch64|arm64) SB_ARCH="arm64" ;;
    armv7l|armv7)  SB_ARCH="armv7" ;;
    *) echo "错误：不支持的架构 $(uname -m)"; exit 1 ;;
esac

if [ "$SINGBOX_VERSION" = "latest" ]; then
    echo "正在查询 sing-box 最新版本..."
    SB_TAG="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name')"
    [ -n "$SB_TAG" ] && [ "$SB_TAG" != "null" ] || { echo "错误：查询 sing-box 版本失败。"; exit 1; }
else
    SB_TAG="v${SINGBOX_VERSION#v}"
fi
SB_VER="${SB_TAG#v}"

echo "正在下载 sing-box ${SB_VER} (${SB_ARCH})..."
SB_TMP="$(mktemp -d)"
trap 'rm -rf "$SB_TMP"' EXIT
SB_URL="https://github.com/SagerNet/sing-box/releases/download/${SB_TAG}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz"
if ! curl -fsSL -o "$SB_TMP/sb.tar.gz" "$SB_URL"; then
    echo "错误：下载失败，请检查版本号或网络：$SB_URL"
    exit 1
fi
tar xzf "$SB_TMP/sb.tar.gz" -C "$SB_TMP"
install -m 0755 "$SB_TMP/sing-box-${SB_VER}-linux-${SB_ARCH}/sing-box" /usr/local/bin/sing-box

installed_version="$(/usr/local/bin/sing-box version 2>/dev/null | awk '/sing-box version/ {print $3; exit}')"
if [ "${installed_version}" != "${SB_VER}" ]; then
    echo "错误：sing-box 安装异常（期望 ${SB_VER}，实际 ${installed_version:-未知}）。"
    exit 1
fi
echo "sing-box 版本校验通过：${installed_version}"

# 关闭官方包管理服务（如果之前装过 sing-box 的 deb/rpm，避免抢 443）
if systemctl list-unit-files 2>/dev/null | grep -qw 'sing-box.service'; then
    systemctl disable --now sing-box >/dev/null 2>&1 || true
fi

# --- 3. 交互式配置 ---
echo "=========================================="
echo "       sing-box REALITY 极简安装向导"
echo "       (核心版本: ${installed_version})"
echo "=========================================="

default_ip=$(curl -s4m8 ip.sb)
read -p "请输入服务器IP或绑定的域名[默认: $default_ip]: " SERVER_ADDR
SERVER_ADDR=${SERVER_ADDR:-$default_ip}

read -p "请输入伪装回落域名 (例: www.apple.com)[默认: www.amazon.com]: " FALLBACK_DOMAIN
FALLBACK_DOMAIN=${FALLBACK_DOMAIN:-"www.amazon.com"}

echo "正在生成 UUID / REALITY 密钥 / ShortId..."
singbox_uuid="$(/usr/local/bin/sing-box generate uuid)"
keypair="$(/usr/local/bin/sing-box generate reality-keypair)"
private_key="$(echo "$keypair" | grep -i '^PrivateKey' | head -1 | awk '{print $NF}')"
public_key="$(echo "$keypair" | grep -i '^PublicKey' | head -1 | awk '{print $NF}')"
short_id="$(/usr/local/bin/sing-box generate rand --hex 4)"

if [ -z "$singbox_uuid" ] || [ -z "$private_key" ] || [ -z "$public_key" ] || [ -z "$short_id" ]; then
    echo "错误：密钥生成失败，请检查 sing-box generate 的输出。"
    exit 1
fi

# --- 4. 生成配置文件 ---
CONFIG_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${CONFIG_DIR}/config.json"
mkdir -p "$CONFIG_DIR"

echo "正在写入配置..."
# 路由策略与 Xray 模板保持一致：嗅探 + 拦 BT/广告/国内域名 + 拦私有和国内 IP，其余直连
jq -n \
  --arg uuid "$singbox_uuid" \
  --arg domain "$FALLBACK_DOMAIN" \
  --arg pk "$private_key" \
  --arg sid "$short_id" \
  --argjson port "$LISTEN_PORT" \
  '{
    log: { level: "warn", timestamp: true },
    inbounds: [{
      type: "vless",
      tag: "vless-in",
      listen: "::",
      listen_port: $port,
      users: [{ uuid: $uuid, flow: "xtls-rprx-vision" }],
      tls: {
        enabled: true,
        server_name: $domain,
        reality: {
          enabled: true,
          handshake: { server: $domain, server_port: 443 },
          private_key: $pk,
          short_id: [$sid]
        }
      }
    }],
    outbounds: [{ type: "direct", tag: "direct" }],
    route: {
      rules: [
        { action: "sniff" },
        { protocol: "bittorrent", action: "reject" },
        { rule_set: ["geosite-ads"], action: "reject" },
        { rule_set: ["geosite-cn"], action: "reject" },
        { ip_is_private: true, action: "reject" },
        { rule_set: ["geoip-cn"], action: "reject" }
      ],
      rule_set: [
        {
          type: "remote", tag: "geosite-ads", format: "binary",
          url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
        },
        {
          type: "remote", tag: "geosite-cn", format: "binary",
          url: "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
        },
        {
          type: "remote", tag: "geoip-cn", format: "binary",
          url: "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
        }
      ],
      final: "direct",
      auto_detect_interface: true
    }
  }' > "$CONFIG_FILE"

# --- 4.1 配置自检（不通过就不要启动服务）---
if ! /usr/local/bin/sing-box check -c "$CONFIG_FILE"; then
    echo "错误：配置文件未通过 sing-box 自检，请检查上面的报错。"
    exit 1
fi
chmod 600 "$CONFIG_FILE"
echo "配置自检通过。"

# --- 5. 配置 systemd 服务 ---
echo "正在配置 systemd 服务..."
mkdir -p /var/lib/sing-box
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sing-box >/dev/null 2>&1
systemctl restart sing-box
if systemctl is-active --quiet sing-box; then
    echo "sing-box 启动成功！"
else
    echo "sing-box 启动失败，请检查配置或运行 journalctl -u sing-box -e 查看日志。"
    exit 1
fi

# --- 6. 生成分享链接并保存 ---
LINK_FILE="${CONFIG_DIR}/share_link.txt"
VLESS_LINK="vless://${singbox_uuid}@${SERVER_ADDR}:${LISTEN_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${FALLBACK_DOMAIN}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#singbox-${SERVER_ADDR}"

echo "$VLESS_LINK" > "$LINK_FILE"
chmod 600 "$LINK_FILE"

cat > /usr/local/bin/sblink <<EOF
#!/bin/bash
echo "========================================================"
echo " sing-box 配置信息 (读取自: $LINK_FILE)"
echo " 核心版本: ${installed_version}"
echo "========================================================"
echo "地址 (Address): $SERVER_ADDR"
echo "端口 (Port)   : ${LISTEN_PORT}"
echo "用户ID (UUID) : $singbox_uuid"
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
chmod +x /usr/local/bin/sblink

# --- 7. 显示结果 ---
sblink
echo ""
echo "安装完成！"
echo "以后如果忘记了链接，直接在终端输入命令: sblink 即可查看。"
echo "服务管理: systemctl {status|restart|stop} sing-box ；日志: journalctl -u sing-box -e"
