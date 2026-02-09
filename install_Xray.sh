#!/bin/bash

# --- 1. 基础检查与环境准备 ---
if [[ $EUID -ne 0 ]]; then
    echo "错误：必须使用 root 权限运行此脚本。"
    exit 1
fi

echo "正在安装依赖 (curl, jq, openssl)..."
if [ -f /etc/debian_version ]; then
    apt-get update -y && apt-get install -y curl jq openssl
elif [ -f /etc/redhat_version ]; then
    yum install -y curl jq openssl
fi

# --- 2. 安装/更新 Xray 核心 (使用官方脚本) ---
echo "正在安装/更新 Xray 核心..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
systemctl enable xray

# --- 3. 交互式配置 (这里就是你要的功能) ---
echo "=========================================="
echo "       Xray REALITY 极简安装向导"
echo "=========================================="

# 3.1 获取服务器地址
default_ip=$(curl -s4m8 ip.sb)
read -p "请输入服务器IP或绑定的域名 [默认: $default_ip]: " SERVER_ADDR
SERVER_ADDR=${SERVER_ADDR:-$default_ip}

# 3.2 获取回落域名
read -p "请输入伪装回落域名 (例: www.amazon.com、learn.microsoft.com、) [默认: www.amazon.com]: " FALLBACK_DOMAIN
FALLBACK_DOMAIN=${FALLBACK_DOMAIN:-"www.amazon.com"}

# 3.3 生成密钥和 UUID
echo "正在生成密钥和 UUID..."
xray_uuid=$(xray uuid)
keys=$(xray x25519)
private_key=$(echo "$keys" | awk '/Private key/ {print $3}')
public_key=$(echo "$keys" | awk '/Public key/ {print $3}')
short_id=$(openssl rand -hex 4)

# --- 4. 生成配置文件 (带防偷跑限速) ---
CONFIG_FILE="/usr/local/etc/xray/config.json"
echo "正在写入配置文件到 $CONFIG_FILE ..."

cat > $CONFIG_FILE <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$xray_uuid",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${FALLBACK_DOMAIN}:443",
          "xver": 0,
          "serverNames": [
            "${FALLBACK_DOMAIN}"
          ],
          "privateKey": "$private_key",
          "shortIds": [
            "$short_id"
          ],
          "limitFallbackUpload": {
            "afterBytes": 10240,
            "bytesPerSec": 5120,
            "burstBytesPerSec": 5120
          },
          "limitFallbackDownload": {
            "afterBytes": 1048576,
            "bytesPerSec": 15360,
            "burstBytesPerSec": 20480
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "fakedns"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "block",
        "protocol": ["bittorrent"]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": ["geosite:cn", "category-ads-all"]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": ["geoip:cn", "geoip:private"]
      }
    ]
  }
}
EOF

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

# 保存到文件
echo "$VLESS_LINK" > "$LINK_FILE"

# 创建快捷命令 link
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
# 直接调用刚才创建的快捷命令
link

echo ""
echo "安装完成！"
echo "以后如果忘记了链接，直接在终端输入命令: link 即可查看。"
