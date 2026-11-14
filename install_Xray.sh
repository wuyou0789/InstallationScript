#!/bin/bash
# ============================================================================
#  Xray REALITY 极简安装脚本（核心版本锁定 v26.6.27）
# ----------------------------------------------------------------------------
#  为什么必须锁版本：
#    Xray-core 从 v26.7.x 开始收紧 REALITY 对 ClientHello 的校验，v26.9.8 起
#    服务端强制要求 key_share 里必须带 X25519MLKEM768（且必须在 X25519 之前）。
#    而 mihomo（Clash.Meta）默认会剥掉 MLKEM，sing-box 系客户端（Karing 的
#    sing-box 内核）也不发 MLKEM —— 握手不会被当成 REALITY，直接回落到伪装
#    网站，症状就是「节点连上了但上不了网 / 像连到真网站」。
#    参考：https://github.com/MetaCubeX/mihomo/issues/3193
#    v26.6.27 是最后一个不强制 MLKEM 的稳定版：Karing / mihomo / v2rayN /
#    Xray（新老版本）客户端都能正常握手。
#    注意：以后不要手工执行不带 --version 的安装命令，否则会被升级到最新版。
# ============================================================================

set -o pipefail

readonly XRAY_PIN_VERSION="v26.6.27"
readonly INSTALL_SCRIPT_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# --- 1. 基础检查与环境准备 ---
if [ "$EUID" -ne 0 ]; then
    echo "错误：必须使用 root 权限运行此脚本。"
    exit 1
fi

echo "正在安装依赖 (curl, jq, openssl)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y && apt-get install -y curl jq openssl
elif [ -f /etc/redhat-release ]; then
    yum install -y curl jq openssl
fi

for cmd in curl jq openssl; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "错误：缺少依赖 $cmd"; exit 1; }
done

# --- 2. 安装/更新 Xray 核心（锁定版本）---
echo "正在安装 Xray 核心 ${XRAY_PIN_VERSION}（锁定版本，勿升级）..."
bash -c "$(curl -fsSL ${INSTALL_SCRIPT_URL})" @ install --version "${XRAY_PIN_VERSION}"
systemctl enable xray >/dev/null 2>&1

# --- 2.1 版本校验：不是锁定版本就直接退出 ---
installed_version="$(/usr/local/bin/xray -version 2>/dev/null | awk 'NR==1 {print $2}')"
# xray -version 输出形如 "Xray 26.6.27 (...)"，取到的版本不带 v 前缀，统一去掉再比
if [ "${installed_version#v}" != "${XRAY_PIN_VERSION#v}" ]; then
    echo "错误：当前 Xray 版本为 ${installed_version:-未知}，不是锁定版本 ${XRAY_PIN_VERSION}。"
    echo "      >= v26.7 的新版要求 ClientHello 携带 X25519MLKEM768，"
    echo "      mihomo / sing-box(Karing) 等客户端会 REALITY 握手失败。"
    echo "      请重新执行：bash -c \"\$(curl -L ${INSTALL_SCRIPT_URL})\" @ install --version ${XRAY_PIN_VERSION}"
    exit 1
fi
echo "Xray 版本校验通过：${installed_version}"

# --- 3. 交互式配置 ---
echo "=========================================="
echo "       Xray REALITY 极简安装向导"
echo "       (核心版本: ${XRAY_PIN_VERSION} 已锁定)"
echo "=========================================="

TEMPLATE_URL="https://raw.githubusercontent.com/wuyou0789/InstallationScript/main/config_template.json"

# 获取服务器地址
default_ip=$(curl -s4m8 ip.sb)
read -p "请输入服务器IP或绑定的域名[默认: $default_ip]: " SERVER_ADDR
SERVER_ADDR=${SERVER_ADDR:-$default_ip}

# 获取回落域名
read -p "请输入伪装回落域名 (例: www.apple.com)[默认: www.amazon.com]: " FALLBACK_DOMAIN
FALLBACK_DOMAIN=${FALLBACK_DOMAIN:-"www.amazon.com"}

# 生成密钥和 UUID
echo "正在生成密钥和 UUID..."
xray_uuid=$(/usr/local/bin/xray uuid)
keys=$(/usr/local/bin/xray x25519)

# 兼容新旧两种输出格式：
#   旧: Private key: xxx / Public key: yyy
#   新: PrivateKey: xxx / Password (PublicKey): yyy / Hash32: zzz
private_key=$(echo "$keys" | grep -E -i "Private key|PrivateKey" | head -1 | awk '{print $NF}')
public_key=$(echo "$keys" | grep -E -i "Public key|Password" | head -1 | awk '{print $NF}')
short_id=$(openssl rand -hex 4)

if [ -z "$private_key" ] || [ -z "$public_key" ] || [ -z "$xray_uuid" ]; then
    echo "错误：密钥生成失败，请检查 xray x25519 / xray uuid 的输出。"
    exit 1
fi

# --- 4. 下载并动态生成配置文件 ---
CONFIG_DIR="/usr/local/etc/xray"
CONFIG_FILE="${CONFIG_DIR}/config.json"
mkdir -p "$CONFIG_DIR"

echo "正在从远程下载配置模板..."
TMP_TEMPLATE="$(mktemp)"
if ! curl -fsSL "$TEMPLATE_URL" -o "$TMP_TEMPLATE"; then
    echo "错误：下载配置模板失败，请检查 URL: $TEMPLATE_URL"
    rm -f "$TMP_TEMPLATE"
    exit 1
fi

if ! jq . "$TMP_TEMPLATE" >/dev/null 2>&1; then
    echo "错误：配置模板 JSON 格式不正确！"
    rm -f "$TMP_TEMPLATE"
    exit 1
fi

echo "正在将您的专属参数写入配置..."
jq --arg uuid "$xray_uuid" \
   --arg domain "$FALLBACK_DOMAIN" \
   --arg pk "$private_key" \
   --arg sid "$short_id" \
   '.inbounds[0].settings.clients[0].id = $uuid |
    .inbounds[0].settings.clients[0].flow = "xtls-rprx-vision" |
    .inbounds[0].streamSettings.network = "tcp" |
    .inbounds[0].streamSettings.realitySettings.dest = ($domain + ":443") |
    del(.inbounds[0].streamSettings.realitySettings.target) |
    .inbounds[0].streamSettings.realitySettings.serverNames = [$domain] |
    .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
    .inbounds[0].streamSettings.realitySettings.shortIds = [$sid]' \
   "$TMP_TEMPLATE" > "$CONFIG_FILE"

rm -f "$TMP_TEMPLATE"

# --- 4.1 配置自检（不通过就不要重启服务）---
if ! /usr/local/bin/xray run -test -c "$CONFIG_FILE" >/dev/null 2>&1; then
    echo "错误：配置文件未通过 Xray 自检，详情："
    /usr/local/bin/xray run -test -c "$CONFIG_FILE"
    exit 1
fi
chmod 600 "$CONFIG_FILE"
echo "配置自检通过。"

# --- 5. 重启服务 ---
echo "正在重启 Xray 服务..."
systemctl restart xray
if systemctl is-active --quiet xray; then
    echo "Xray 启动成功！"
else
    echo "Xray 启动失败，请检查配置或运行 journalctl -u xray -e 查看日志。"
    exit 1
fi

# --- 6. 生成分享链接并保存 ---
LINK_FILE="${CONFIG_DIR}/share_link.txt"
VLESS_LINK="vless://${xray_uuid}@${SERVER_ADDR}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${FALLBACK_DOMAIN}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#Xray-${SERVER_ADDR}"

echo "$VLESS_LINK" > "$LINK_FILE"
chmod 600 "$LINK_FILE"

cat > /usr/local/bin/link <<EOF
#!/bin/bash
echo "========================================================"
echo " Xray 配置信息 (读取自: $LINK_FILE)"
echo " 核心版本: ${XRAY_PIN_VERSION} (已锁定，勿升级到 >= v26.7)"
echo "========================================================"
echo "地址 (Address): $SERVER_ADDR"
echo "端口 (Port)   : 443"
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
CURRENT="\$(/usr/local/bin/xray -version 2>/dev/null | awk 'NR==1 {print \$2}')"
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

# --- 7. 显示结果 ---
link
echo ""
echo "安装完成！"
echo "以后如果忘记了链接，直接在终端输入命令: link 即可查看。"
echo "想确认核心版本有没有被意外升级，执行: xray-version-check"
