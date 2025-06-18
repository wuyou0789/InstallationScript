#!/bin/bash

# 脚本：为Oracle Cloud服务器启用root用户SSH密码登录并可选安装常用工具
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
AUTHORIZED_KEYS_FILE="/root/.ssh/authorized_keys"
echo "步骤 1: 修改 $AUTHORIZED_KEYS_FILE"
if [ -f "$AUTHORIZED_KEYS_FILE" ]; then
    cp "$AUTHORIZED_KEYS_FILE" "${AUTHORIZED_KEYS_FILE}.bak_$(date +%F_%T)"
    echo "  已创建备份: ${AUTHORIZED_KEYS_FILE}.bak_$(date +%F_%T)"
    sed -i -E 's/^(no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="[^"]*")\s+//g' "$AUTHORIZED_KEYS_FILE"
    echo "  $AUTHORIZED_KEYS_FILE 修改完成。"
else
    echo "  警告: $AUTHORIZED_KEYS_FILE 文件不存在。跳过此步骤。"
fi
echo "--------------------------------------------------"

# 2. 设置root用户密码
echo "步骤 2: 设置root用户密码"
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
    cp "$SSHD_CONFIG_FILE" "${SSHD_CONFIG_FILE}.bak_$(date +%F_%T)"
    echo "  已创建备份: ${SSHD_CONFIG_FILE}.bak_$(date +%F_%T)"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' "$SSHD_CONFIG_FILE"
    echo "  PermitRootLogin 已设置为 yes."
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' "$SSHD_CONFIG_FILE"
    echo "  PasswordAuthentication 已设置为 yes."
    sed -i 's|^Include /etc/ssh/sshd_config.d/\*.conf|#Include /etc/ssh/sshd_config.d/\*.conf|g' "$SSHD_CONFIG_FILE"
    echo "  Include /etc/ssh/sshd_config.d/\*.conf 行已注释。"
    echo "  $SSHD_CONFIG_FILE 修改完成。"
else
    echo "  错误: $SSHD_CONFIG_FILE 文件不存在！无法进行配置。"
    exit 1
fi
echo "--------------------------------------------------"

# 5. 安装常用工具 (可选)
echo "步骤 5: 安装常用工具 (可选)"
COMMON_TOOLS="curl wget unzip"
# shellcheck disable=SC2155
read -r -p "是否要安装常用工具 (包含: ${COMMON_TOOLS})? (y/N): " INSTALL_TOOLS_CHOICE

if [[ "$INSTALL_TOOLS_CHOICE" =~ ^[Yy]$ ]]; then
    echo "  正在更新软件包列表..."
    if apt update -y; then
        echo "  软件包列表更新成功。"
        echo "  正在安装常用工具: ${COMMON_TOOLS}..."
        if apt install -y ${COMMON_TOOLS}; then
            echo "  常用工具安装成功。"
            if command -v ufw > /dev/null && dpkg -s ufw &> /dev/null; then
                echo "--------------------------------------------------"
                echo "  检测到 UFW (防火墙) 已安装。"
                read -r -p "  是否要启用 UFW 并默认允许 SSH (端口 22)? (y/N): " CONFIGURE_UFW_CHOICE
                if [[ "$CONFIGURE_UFW_CHOICE" =~ ^[Yy]$ ]]; then
                    echo "    正在配置 UFW..."
                    ufw allow ssh
                    yes | ufw enable
                    echo "    UFW 已启用并已允许 SSH。"
                    echo "    当前 UFW 状态:"
                    ufw status verbose
                else
                    echo "    跳过 UFW 配置。您之后可以手动配置: sudo ufw allow ssh && sudo ufw enable"
                fi
            fi
        else
            echo "  部分或全部常用工具安装失败。请检查错误信息。"
        fi
    else
        echo "  错误：软件包列表更新失败 (apt update)。跳过安装常用工具。"
    fi
else
    echo "  跳过安装常用工具。"
fi
echo "--------------------------------------------------"

# 6. 重启SSH服务
echo "步骤 6: 重启SSH服务"
SSH_SERVICE_TO_USE="" # Will be set to 'ssh' or 'sshd'
SSH_RESTARTED_SUCCESSFULLY=false

if command -v systemctl > /dev/null; then
    # 对于 Ubuntu/Debian, 服务名通常是 'ssh'. 对于 RHEL/CentOS, 是 'sshd'.
    # 优先尝试 'ssh'
    if systemctl restart ssh > /dev/null 2>&1; then
        echo "  使用 systemctl 重启 ssh 服务。"
        SSH_SERVICE_TO_USE="ssh"
    elif systemctl restart sshd > /dev/null 2>&1; then
        echo "  使用 systemctl 重启 sshd 服务。"
        SSH_SERVICE_TO_USE="sshd"
    else
        echo "  警告: 使用 systemctl 尝试重启 ssh 和 sshd 服务均失败。"
    fi
elif command -v service > /dev/null; then
    # Fallback to 'service' for older systems
    if service ssh restart > /dev/null 2>&1; then
        echo "  使用 service 重启 ssh 服务。"
        SSH_SERVICE_TO_USE="ssh"
    elif service sshd restart > /dev/null 2>&1; then
        echo "  使用 service 重启 sshd 服务。"
        SSH_SERVICE_TO_USE="sshd"
    else
        echo "  错误: systemctl 未找到，且使用 service 命令重启 ssh(d) 服务失败。请手动重启。"
    fi
else
    echo "  错误: 无法找到 systemctl 或 service 命令来重启SSH服务。请手动重启。"
fi

# 检查SSH服务状态
echo "  检查 SSH 服务状态..."
if [ -n "$SSH_SERVICE_TO_USE" ]; then # If a restart was attempted with a specific service name
    if command -v systemctl > /dev/null; then
        if systemctl is-active --quiet "$SSH_SERVICE_TO_USE"; then
            echo "  $SSH_SERVICE_TO_USE 服务正在运行。"
            SSH_RESTARTED_SUCCESSFULLY=true
        else
            echo "  警告: $SSH_SERVICE_TO_USE 服务似乎没有成功启动。请检查日志: journalctl -u $SSH_SERVICE_TO_USE"
        fi
    elif command -v service > /dev/null; then # systemctl not present, 'service' was used for restart
        if service "$SSH_SERVICE_TO_USE" status > /dev/null 2>&1; then
             echo "  $SSH_SERVICE_TO_USE 服务正在运行 (通过 'service' 命令检查)。"
             SSH_RESTARTED_SUCCESSFULLY=true
        else
            echo "  警告: $SSH_SERVICE_TO_USE 服务似乎没有成功启动 (通过 'service' 命令检查)。请检查日志，如 /var/log/auth.log 或 /var/log/secure。"
        fi
    fi
else
    # This means neither systemctl nor service commands were available or successful in identifying a service for restart.
    echo "  警告: 未能通过 systemctl 或 service 尝试重启 SSH 服务。无法自动确认服务状态。"
    echo "  请手动检查并重启。常见的服务名有 'ssh' 或 'sshd'。"
    echo "  日志检查命令: 'journalctl -u ssh', 'journalctl -u sshd', 或查看 '/var/log/auth.log', '/var/log/secure'."
fi

echo "--------------------------------------------------"
echo "配置完成！"
if ${SSH_RESTARTED_SUCCESSFULLY}; then
    echo "您现在应该可以使用root用户和新设置的密码通过SSH登录了。"
else
    echo "SSH服务可能没有成功重启或状态未知。请检查上述日志并尝试手动重启SSH服务后，再尝试用root密码登录。"
fi
echo ""
echo "重要安全提示："
echo "1. 确保您为root设置了一个非常强大且唯一的密码。"
echo "2. 允许root密码登录会显著增加服务器的安全风险。"
echo "3. 优先考虑使用密钥登录，并使用sudo提升权限，或为root配置密钥并禁用密码登录。"
echo "4. 定期审查服务器日志。"
echo "5. 正确配置防火墙 (如 Oracle Cloud 安全列表/NSG, 以及本地 UFW)。"
echo "--------------------------------------------------"

exit 0
