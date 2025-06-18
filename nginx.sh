#!/bin/bash

# ==============================================================================
# Nginx 静态网站 & 私密下载服务器配置脚本 (最终版)
#
# 适用于: Debian 11/12, Ubuntu 20.04/22.04
#
# 特点:
# 1. 交互式引导输入域名和邮箱。
# 2. 禁止任何形式的目录索引/浏览，只允许通过直接链接下载文件。
# 3. 完美适配您提供的 "www" 目录结构 (Clean URLs, Custom 404)。
# 4. 采用安全的证书申请流程，避免错误。
#
# ==============================================================================

# --- [步骤 1/7] 获取用户信息 ---
clear
echo "=================================================="
echo "    Nginx 静态网站服务器自动配置脚本"
echo "=================================================="
echo ""

read -p "请输入您的域名 : " DOMAIN
if [[ -z "$DOMAIN" ]]; then
    echo -e "\n错误：域名不能为空。脚本已中止。"
    exit 1
fi

read -p "请输入您的邮箱 (用于 Let's Encrypt 证书通知): " EMAIL
if [[ -z "$EMAIL" || ! "$EMAIL" == *@* ]]; then
    echo -e "\n错误：邮箱不能为空或格式不正确。脚本已中止。"
    exit 1
fi

echo -e "\n-------------------------------------------"
echo "配置信息确认:"
echo "  - 域名: ${DOMAIN}"
echo "  - 邮箱: ${EMAIL}"
echo "-------------------------------------------"
read -p "信息确认无误，请按 Enter键 继续，或按 Ctrl+C 中止..."
echo ""

# --- 变量定义 ---
SITE_ROOT_PARENT="/var/www"
USERNAME_TO_OWN_DIR=$(logname)

# --- 权限检查 ---
if [ "$(id -u)" -ne 0 ]; then
  echo "错误：此脚本需要使用 sudo 权限执行。" >&2
  exit 1
fi

# --- [步骤 2/7] 系统更新与安装依赖 ---
echo "--- [2/7] 系统更新与安装依赖 ---"
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y nginx certbot python3-certbot-nginx curl

# --- [步骤 3/7] 配置防火墙 (UFW) ---
echo "--- [3/7] 配置防火墙 (UFW) ---"
ufw allow 'OpenSSH'
ufw allow 'Nginx Full'
ufw --force enable

# --- [步骤 4/7] 创建目录和临时 Nginx 配置 ---
echo "--- [4/7] 创建目录和临时 Nginx 配置 ---"
chown -R ${USERNAME_TO_OWN_DIR}:${USERNAME_TO_OWN_DIR} "${SITE_ROOT_PARENT}"
chmod -R 755 "${SITE_ROOT_PARENT}"

# Phase 1: 创建临时配置用于 Certbot 验证
cat > /etc/nginx/sites-available/${DOMAIN} <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${SITE_ROOT_PARENT};
    index index.html;
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -s -f /etc/nginx/sites-available/${DOMAIN} /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# --- [步骤 5/7] 获取 SSL 证书 ---
echo "--- [步骤 5/7] 获取 SSL 证书 ---"
certbot --nginx --agree-tos --redirect --hsts --staple-ocsp --email ${EMAIL} -d ${DOMAIN}
if [ $? -ne 0 ]; then
    echo "错误：Certbot 证书申请失败。脚本中止。"
    exit 1
fi

# --- [步骤 6/7] 创建最终版 Nginx 配置 ---
echo "--- [步骤 6/7] 创建最终版 Nginx 配置 ---"
# Phase 2: 创建最终配置文件 (已移除所有 autoindex)
cat > /etc/nginx/sites-available/${DOMAIN} <<EOF
# HTTP (端口 80) -> HTTPS (端口 443) 由 Certbot 自动配置

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    # 证书路径由 Certbot 管理
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    root ${SITE_ROOT_PARENT};
    index index.html;

    error_page 404 /404.html;
    location = /404.html {
        internal;
    }

    # 安全与性能头部
    server_tokens off;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # 核心路由规则：尝试文件、HTML文件、目录索引（但会因缺少index.html而404）
    location / {
        try_files \$uri \$uri.html \$uri/ =404;
    }

    # 为静态资源设置长缓存
    location ~* \.(?:css|js|jpg|jpeg|gif|png|ico|svg|webp|woff|woff2|zip|conf|json|txt|md)$ {
        expires 1M;
        access_log off;
        add_header Cache-Control "public, no-transform";
    }

    # 禁止访问隐藏文件
    location ~ /\. {
        deny all;
    }
}
EOF

# --- [步骤 7/7] 重启 Nginx 使所有配置生效 ---
echo "--- [步骤 7/7] 重启 Nginx 使所有配置生效 ---"
nginx -t
if [ $? -ne 0 ]; then
    echo "错误：最终 Nginx 配置测试失败，请检查 /etc/nginx/sites-available/${DOMAIN}"
    exit 1
fi
systemctl restart nginx

# --- 完成 ---
echo ""
echo "=================================================="
echo "          配置完成！"
echo "=================================================="
echo ""
echo "重要提示：请将您的网站文件上传到以下目录："
echo "   ${SITE_ROOT_PARENT}"
echo ""
echo "您的服务器现在已配置为："
echo " - 提供静态 HTML 页面 (例如 /windows -> /windows.html)"
echo " - 禁止所有目录的列表浏览"
echo " - 允许通过直接链接下载文件"
echo ""
echo "网站域名: https://${DOMAIN}"
echo ""
