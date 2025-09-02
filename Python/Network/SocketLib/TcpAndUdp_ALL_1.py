import socket
import os

def tcp_listens(host, port, max=5):
    """创建一个服务端socket，并绑定到指定的host和port上，开始监听连接请求。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(max)
    return s

def tcp_connect(host, port):
    """创建一个客户端socket，并连接到指定的host和port。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def tcp_send(s, content):  # 发送信息，并编码
    """发送信息
    """
    s.send(content.encode(encoding='utf-8'))

def tcp_receive(s, buffer_size=1024):  # 接收信息，并解码
    """接收信息
    """
    return s.recv(buffer_size).decode(encoding="utf-8")

def tcp_send_file(s, file_path):
    """通过TCP发送文件
    :param s: 套接字传递
    :param file_path: 要发送的文件路径
    """
    if os.path.isfile(file_path):
        file_size = os.path.getsize(file_path)
        s.send(f"{file_size}".encode(encoding='utf-8'))  # 先发送文件大小
        with open(file_path, 'rb') as f:
            bytes_sent = 0
            while bytes_sent < file_size:
                data = f.read(1024)  # 每次读取1KB
                s.send(data)
                bytes_sent += len(data)
    else:
        return (False,"NOT_FOUND_FILE")

def tcp_receive_file(s, save_path):
    """通过TCP接收文件
    :param s: 套接字传递
    :param save_path: 要保存的文件路径
    """
    file_size = int(tcp_receive(s))  # 接收文件大小
    received_size = 0
    with open(save_path, 'wb') as f:
        while received_size < file_size:
            data = s.recv(1024)  # 每次接收1KB
            if not data:
                break
            f.write(data)
            received_size += len(data)

def close(s):  # 关闭连接
    s.close()

# UDP支持

def udp_listen(host, port):
    """创建一个UDP服务器socket，并绑定到指定的host和port上。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    return s

def udp_send(s, host, port, content):
    """通过UDP发送信息。
    """
    s.sendto(content.encode(), (host, port))

def udp_receive(s, buffer_size=1024):
    """通过UDP接收信息。
    """
    data, addr = s.recvfrom(buffer_size)
    return data.decode(), addr
