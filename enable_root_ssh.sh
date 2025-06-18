#!/bin/bash

# 脚本：为Oracle Cloud服务器启用root用户SSH密码登录
# 警告：以root用户密码登录会增加服务器的安全风险。请谨慎使用，并确保密码足够复杂。
#        强烈建议优先使用密钥登录。

# 确保以root用户运行
if [ "$(id -u)" -ne 0 ]; then
   echo "错误：请以root用户或使用 'sudo bash $0' 运行此脚本。"
   exit 1
fi

echo "开始配置SSH以允许root密码登录..."
echo "--------------------------------------------------"

# 1. 修改 /root/.ssh/authorized_keys
#    删除 'ssh-rsa' 前面的所有限制性命令 (如 Oracle Cloud 默认的 command="...")
AUTHORIZED_KEYS_FILE="/root/.ssh/authorized_keys"
echo "步骤 1: 修改 $AUTHORIZED_KEYS_FILE"
if [ -f "$AUTHORIZED_KEYS_FILE" ]; then
    # 创建备份
    cp "$AUTHORIZED_KEYS_FILE" "${AUTHORIZED_KEYS_FILE}.bak_$(date +%F_%T)"
    echo "  已创建备份: ${AUTHORIZED_KEYS_FILE}.bak_$(date +%F_%T)"

    # 这个sed命令会查找包含 "ssh-rsa" 的行，并删除该行中 "ssh-rsa" 之前的所有内容
    # 注意：这假设 "ssh-rsa" 是密钥本身的开始部分，并且你希望保留从 "ssh-rsa" 开始的整个密钥。
    # Oracle Cloud 通常的格式是：no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="..." ssh-rsa ...
    # 以下命令会移除类似 "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command=\"...\" " 的前缀
    sed -i -E 's/^(no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="[^"]*")\s+//g' "$AUTHORIZED_KEYS_FILE"
    # 如果上述命令没有生效，可以尝试一个更通用的（但可能稍微不那么精确）版本：
    # sed -i 's/.* \(ssh-rsa .*\)/\1/' "$AUTHORIZED_KEYS_FILE"
    
    echo "  $AUTHORIZED_KEYS_FILE 修改完成。"
else
    echo "  警告: $AUTHORIZED_KEYS_FILE 文件不存在。跳过此步骤。"
fi
echo "--------------------------------------------------"

# 2. 设置root用户密码
echo "步骤 2: 设置root用户密码"
echo "  您将被提示输入新的root密码并确认。"
passwd root
echo "  root密码设置完成。"
echo "--------------------------------------------------"

# 3. 删除 /etc/ssh/sshd_config.d/ 目录下的 .conf 文件
SSHD_CONFIG_D_DIR="/etc/ssh/sshd_config.d"
echo "步骤 3: 删除 $SSHD_CONFIG_D_DIR/*.conf 文件"
if [ -d "$SSHD_CONFIG_D_DIR" ]; then
    if [ -n "$(ls -A ${SSHD_CONFIG_D_DIR}/*.conf 2>/dev/null)" ]; then
        rm -f ${SSHD_CONFIG_D_DIR}/*.conf
        echo "  $SSHD_CONFIG_D_DIR/*.conf 文件已删除。"
    else
        echo "  $SSHD_CONFIG_D_DIR/ 中没有 .conf 文件需要删除。"
    fi
else
    echo "  目录 $SSHD_CONFIG_D_DIR 不存在。跳过删除。"
fi
echo "--------------------------------------------------"

# 4. 修改 /etc/ssh/sshd_config
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
echo "步骤 4: 修改 $SSHD_CONFIG_FILE"
if [ -f "$SSHD_CONFIG_FILE" ]; then
    # 创建备份
    cp "$SSHD_CONFIG_FILE" "${SSHD_CONFIG_FILE}.bak_$(date +%F_%T)"
    echo "  已创建备份: ${SSHD_CONFIG_FILE}.bak_$(date +%F_%T)"

    # 允许root登录
    # s/^#\?PermitRootLogin.*/PermitRootLogin yes/g
    #   ^#\?            匹配行首，可选的 '#' (注释符)
    #   PermitRootLogin  匹配字面字符串
    #   .*              匹配该行余下的任何字符
    #   PermitRootLogin yes 替换为的内容
    #   g               全局替换 (如果一行有多个匹配，虽然在此场景下不太可能)
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' "$SSHD_CONFIG_FILE"
    echo "  PermitRootLogin 已设置为 yes."

    # 启用密码认证
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' "$SSHD_CONFIG_FILE"
    echo "  PasswordAuthentication 已设置为 yes."

    # 注释掉 Include /etc/ssh/sshd_config.d/*.conf
    # 使用不同的分隔符 (比如 |) 避免路径中的 / 冲突
    # s|^Include /etc/ssh/sshd_config.d/\*.conf|#Include /etc/ssh/sshd_config.d/\*.conf|g
    #   ^Include...     匹配未注释的Include行
    #   #Include...     替换为注释掉的行
    sed -i 's|^Include /etc/ssh/sshd_config.d/\*.conf|#Include /etc/ssh/sshd_config.d/\*.conf|g' "$SSHD_CONFIG_FILE"
    echo "  Include /etc/ssh/sshd_config.d/*.conf 行已注释。"

    echo "  $SSHD_CONFIG_FILE 修改完成。"
else
    echo "  错误: $SSHD_CONFIG_FILE 文件不存在！无法进行配置。"
    exit 1
fi
echo "--------------------------------------------------"

# 5. 重启SSH服务
echo "步骤 5: 重启SSH服务"
if command -v systemctl > /dev/null; then
    systemctl restart sshd
    echo "  使用 systemctl 重启 sshd 服务。"
elif command -v service > /dev/null; then
    service ssh restart  # 对于一些较旧的系统，可能是 sshd
    echo "  使用 service 重启 ssh 服务。"
else
    echo "  错误: 无法找到 systemctl 或 service 命令来重启SSH服务。请手动重启。"
    exit 1
fi

# 检查sshd服务状态 (可选)
if command -v systemctl > /dev/null; then
    if systemctl is-active --quiet sshd; then
        echo "  sshd 服务正在运行。"
    else
        echo "  警告: sshd 服务似乎没有成功启动。请检查日志: journalctl -u sshd"
    fi
elif command -v service > /dev/null; then
    if service ssh status > /dev/null 2>&1; then # 或 service sshd status
         echo "  ssh 服务正在运行。"
    else
        echo "  警告: ssh 服务似乎没有成功启动。请检查日志，如 /var/log/auth.log 或 /var/log/secure。"
    fi
fi

echo "--------------------------------------------------"
echo "配置完成！"
echo "您现在应该可以使用root用户和新设置的密码通过SSH登录了。"
echo ""
echo "重要安全提示："
echo "1. 确保您为root设置了一个非常强大且唯一的密码。"
echo "2. 允许root密码登录会显著增加服务器的安全风险，因为它是自动化攻击的常见目标。"
echo "3. 如果可能，请优先考虑加强默认用户的权限 (例如通过sudo)，并继续使用密钥登录，或为root用户也配置密钥登录并禁用密码登录。"
echo "4. 定期审查服务器日志，监控异常登录尝试。"
echo "5. 确保您的防火墙 (如 Oracle Cloud 的安全列表或 NSG) 配置正确，只允许受信任的IP地址访问SSH端口 (默认为22)。"
echo "--------------------------------------------------"

exit 0
