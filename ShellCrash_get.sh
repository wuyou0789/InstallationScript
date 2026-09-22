#!/bin/sh
# ==============================================================================
# ShellCrash 配置文件自动化拉取与部署脚本
# ==============================================================================

# 1. 在这里填写你在 GitHub 上存放 config.json 的 Raw 地址（修改为你的用户名和仓库名）
RAW_CONFIG_URL="https://raw.githubusercontent.com/wuyou0789/InstallationScript/refs/heads/main/ShellCrash_config.json"

CORE="/tmp/ShellCrash/CrashCore"
CONF_DIR="/jffs/ShellCrash/jsons"
RUNTIME_DIR="/tmp/ShellCrash/jsons"
SANDBOX="/tmp/test_jsons"

echo "=== 开始拉取远程配置文件 ==="

# 创建临时沙盒
rm -rf "$SANDBOX" && mkdir -p "$SANDBOX"
if [ -d "$CONF_DIR" ]; then
    cp -r "$CONF_DIR/"* "$SANDBOX/" 2>/dev/null
fi

# 尝试下载（带国内加速镜像容灾）
download_success=0
for URL in "$RAW_CONFIG_URL" "https://ghfast.top/$RAW_CONFIG_URL"; do
    echo "正在尝试从: $URL 下载..."
    if curl -sSL -k --connect-timeout 5 -m 15 "$URL" -o "$SANDBOX/config.json"; then
        if [ -s "$SANDBOX/config.json" ] && grep -q '"outbounds"' "$SANDBOX/config.json"; then
            download_success=1
            echo "✅ 配置文件下载成功！"
            break
        fi
    fi
done

if [ "$download_success" -ne 1 ]; then
    echo "❌ 错误: 配置文件下载失败，请检查 URL 是否正确或网络是否连通！"
    rm -rf "$SANDBOX"
    exit 1
fi

# 2. 内核沙盒校验
echo "🔍 正在进行内核语法与完整性校验..."
if [ -x "$CORE" ]; then
    if "$CORE" check -C "$SANDBOX/"; then
        echo "✅ 校验 100% 通过！"
    else
        echo "❌ 校验失败！下载的文件存在 JSON 语法或节点引用错误，已放弃部署。"
        rm -rf "$SANDBOX"
        exit 1
    fi
else
    echo "⚠️ 未找到 CrashCore 执行文件，尝试使用 jq 语法校验..."
    if jq empty "$SANDBOX/config.json" 2>/dev/null; then
        echo "✅ jq 校验 JSON 格式通过！"
    else
        echo "❌ JSON 格式损坏！已放弃部署。"
        rm -rf "$SANDBOX"
        exit 1
    fi
fi

# 3. 备份旧配置并应用新配置
echo "📦 备份当前配置并部署新文件..."
cp "$CONF_DIR/config.json" "$CONF_DIR/config.json.bak_$(date +%Y%m%d_%H%M%S)" 2>/dev/null
cp "$SANDBOX/config.json" "$CONF_DIR/config.json"
[ -d "$RUNTIME_DIR" ] && cp "$SANDBOX/config.json" "$RUNTIME_DIR/config.json" 2>/dev/null

# 4. 重启 ShellCrash
echo "🚀 正在平滑重启 ShellCrash 服务..."
if [ -f "/jffs/ShellCrash/start.sh" ]; then
    /jffs/ShellCrash/start.sh restart >/dev/null 2>&1
    echo "🎉 部署完成！服务已平滑重启并应用新规则！"
else
    echo "⚠️ 未找到 start.sh，请手动重启 ShellCrash 服务。"
fi

# 清理沙盒
rm -rf "$SANDBOX"
