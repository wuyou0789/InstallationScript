#!/bin/bash

# --- 1. 基础检查与环境准备 ---
if [[ $EUID -ne 0 ]]; then
    echo "错误：必须使用 root 权限运行此脚本。"
    exit 1
fi

echo "正在安装依赖 (curl, jq, openssl)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y && apt-get install -y curl jq openssl
elif[ -f /etc/redhat-release ]; then
    yum install -y curl jq openssl
fi

# --- 2. 安装/更新 Xray 核心 ---
echo "正在安装/更新 Xray 核心..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray

# --- 3. 交互式配置 ---
echo "=========================================="
echo "       Xray REALITY 极简安装向导"
echo "=========================================="

# >>> 请在这里填入您刚才上传的 JSON 模板的 Raw 链接 <<<
TEMPLATE_URL="https://raw.githubusercontent.com/wuyou0789/xray/main/config_template.json"

# 获取服务器地址
default_ip=$(curl -s4m8 ip.sb)
read -p "请输入服务器IP或绑定的域名[默认: $default_ip]: " SERVER_ADDR
SERVER_ADDR=${SERVER_ADDR:-$default_ip}

# 获取回落域名
read -p "请输入伪装回落域名 (例: www.apple.com)[默认: www.amazon.com]: " FALLBACK_DOMAIN
FALLBACK_DOMAIN=${FALLBACK_DOMAIN:-"www.amazon.com"}

# 生成密钥和 UUID
echo "正在生成密钥和 UUID..."
xray_uuid=$(xray uuid)
keys=$(xray x25519)
private_key=$(echo "$keys" | awk '/Private key/ {print $3}')
public_key=$(echo "$keys" | awk '/Public key/ {print $3}')
short_id=$(openssl rand -hex 4)

# --- 4. 下载并动态生成配置文件 ---
CONFIG_FILE="/usr/local/etc/xray/config.json"
echo "正在从远程下载配置模板..."
curl -sL "$TEMPLATE_URL" -o /tmp/config_template.json

if[ ! -f /tmp/config_template.json ] || ! jq . /tmp/config_template.json >/dev/null 2>&1; then
    echo "错误：下载配置模板失败或 JSON 格式不正确，请检查 URL！"
    exit 1
fi

echo "正在将您的专属参数写入配置..."
# 核心魔法：使用 jq 替换模板中的对应字段
jq --arg uuid "$xray_uuid" \
   --arg domain "$FALLBACK_DOMAIN" \
   --arg pk "$private_key" \
   --arg sid "$short_id" \
   '.inbounds[0].settings.clients[0].id = $uuid |
    .inbounds[0].streamSettings.realitySettings.target = ($domain + ":443") |
    .inbounds[0].streamSettings.realitySettings.serverNames = [$domain] |
    .inbounds[0].streamSettings.realitySettings.privateKey = $pk |
    .inbounds[0].streamSettings.realitySettings.shortIds =[$sid]' \
   /tmp/config_template.json > "$CONFIG_FILE"

# 删掉临时模板文件
rm -f /tmp/config_template.json

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
LINK_FILE="/usr/local/etc/xray/share_link.txt"
VLESS_LINK="vless://${xray_uuid}@${SERVER_ADDR}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${FALLBACK_DOMAIN}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#Xray-${SERVER_ADDR}"

echo "$VLESS_LINK" > "$LINK_FILE"

cat > /usr/local/bin/link <<EOF
#!/bin/bash
echo "========================================================"
echo " Xray 配置信息 (读取自: $LINK_FILE)"
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

# --- 7. 显示结果 ---
link
echo ""
echo "安装完成！"
echo "以后如果忘记了链接，直接在终端输入命令: link 即可查看。"
