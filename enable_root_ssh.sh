#!/bin/bash

# 脚本：为Oracle Cloud服务器启用root用户SSH密码登录并可选安装常用工具
# 警告：以root用户密码登录会增加服务器的安全风险。请谨慎使用，并确保密码足够复杂。
# 确保以root用户运行
# Version: 1.7.0
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
COMMON_TOOLS="curl wget unzip rsync"
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

# 6. 重启并确保SSH服务已启用
echo "步骤 6: 重启并确保SSH服务已启用"
SSH_SERVICE_TO_USE=""
SSH_RESTARTED_SUCCESSFULLY=false
SERVICE_MANAGEMENT_CMD="" # Will be 'systemctl' or 'service'

# Determine service management command
if command -v systemctl > /dev/null; then
    SERVICE_MANAGEMENT_CMD="systemctl"
elif command -v service > /dev/null; then
    SERVICE_MANAGEMENT_CMD="service"
else
    echo "  错误: 无法找到 systemctl 或 service 命令来管理SSH服务。请手动操作。"
fi

if [ "$SERVICE_MANAGEMENT_CMD" == "systemctl" ]; then
    echo "  尝试使用 systemctl 重启 SSH 服务..."
    if systemctl restart ssh > /dev/null 2>&1; then
        echo "    已使用 systemctl 重启 ssh 服务。"
        SSH_SERVICE_TO_USE="ssh"
    elif systemctl restart sshd > /dev/null 2>&1; then
        echo "    已使用 systemctl 重启 sshd 服务。"
        SSH_SERVICE_TO_USE="sshd"
    else
        echo "  警告: 使用 systemctl 尝试重启 ssh 和 sshd 服务均失败。"
    fi
elif [ "$SERVICE_MANAGEMENT_CMD" == "service" ]; then
    echo "  尝试使用 service 重启 SSH 服务..."
    if service ssh restart > /dev/null 2>&1; then
        echo "    已使用 service 重启 ssh 服务。"
        SSH_SERVICE_TO_USE="ssh"
    elif service sshd restart > /dev/null 2>&1; then
        echo "    已使用 service 重启 sshd 服务。"
        SSH_SERVICE_TO_USE="sshd"
    else
        echo "  警告: 使用 service 命令重启 ssh(d) 服务失败。"
    fi
fi

# 如果服务被成功识别并重启，则尝试启用并检查状态
if [ -n "$SSH_SERVICE_TO_USE" ]; then
    if [ "$SERVICE_MANAGEMENT_CMD" == "systemctl" ]; then
        echo "  确保 $SSH_SERVICE_TO_USE 服务已启用 (自动启动)..."
        if systemctl enable "$SSH_SERVICE_TO_USE" > /dev/null 2>&1; then
            echo "    $SSH_SERVICE_TO_USE 服务已启用。"
        else
            echo "  警告: 未能启用 $SSH_SERVICE_TO_USE 服务。它可能不会在下次启动时自动运行。"
        fi

        echo "  检查 $SSH_SERVICE_TO_USE 服务状态..."
        if systemctl is-active --quiet "$SSH_SERVICE_TO_USE"; then
            echo "    $SSH_SERVICE_TO_USE 服务正在运行。"
            SSH_RESTARTED_SUCCESSFULLY=true
        else
            echo "  警告: $SSH_SERVICE_TO_USE 服务似乎没有成功启动。请检查日志: journalctl -u $SSH_SERVICE_TO_USE"
        fi
    elif [ "$SERVICE_MANAGEMENT_CMD" == "service" ]; then # 'service' doesn't have a direct 'enable' equivalent for all init systems
        echo "  检查 $SSH_SERVICE_TO_USE 服务状态 (使用 'service')..."
        if service "$SSH_SERVICE_TO_USE" status > /dev/null 2>&1; then
             echo "    $SSH_SERVICE_TO_USE 服务正在运行。"
             SSH_RESTARTED_SUCCESSFULLY=true
             # For 'service', enabling is typically handled by 'update-rc.d' or 'chkconfig'
             # This script won't try to handle those for simplicity here, assuming install handled enabling.
        else
            echo "  警告: $SSH_SERVICE_TO_USE 服务似乎没有成功启动。请检查日志，如 /var/log/auth.log 或 /var/log/secure。"
        fi
    fi
else
    if [ -n "$SERVICE_MANAGEMENT_CMD" ]; then # If a command was found but restart failed for both names
        echo "  警告: 未能重启 'ssh' 或 'sshd' 服务。请手动检查SSH服务配置和状态。"
    fi
    # If SERVICE_MANAGEMENT_CMD was empty, the initial error message already covered it.
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
