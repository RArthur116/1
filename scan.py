import socket
from concurrent.futures import ThreadPoolExecutor
import requests
from urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求警告
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def scan_port(ip, port, open_ports):
    """尝试连接给定IP地址和端口。
    
    如果连接成功，则表示端口是开放的；否则，端口可能是关闭的或被防火墙阻止。
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                # 记录开放的端口
                open_ports.append(port)
                print(f"Port {port} is open")
    except socket.error as e:
        print(f"Error scanning port {port}: {e}")

def identify_service(ip, port, service_type, service_results):
    """尝试通过发送数据包并分析响应来识别服务类型和版本。"""
    try:
        if service_type == "http":
            url = f"http://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            server_header = response.headers.get('Server', 'Unknown')
            service_results[port] = (f"HTTP: {server_header}", "HTTP Request Method")
            print(f"Service on port {port}: {server_header} (Detected by HTTP Request)")
        elif service_type == "https":
            url = f"https://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            server_header = response.headers.get('Server', 'Unknown')
            service_results[port] = (f"HTTPS: {server_header}", "HTTPS Request Method")
            print(f"Service on port {port}: {server_header} (Detected by HTTPS Request)")
        elif service_type == "ftp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                s.send(b'FEAT\r\n')
                response = s.recv(1024).decode()
                if "211-Features" in response:
                    service_results[port] = ("FTP", "FTP FEAT Command")
                    print(f"Service on port {port}: FTP (Detected by FTP FEAT Command)")
                else:
                    service_results[port] = ("Unknown (FTP-like)", "FTP FEAT Command")
                    print(f"Service on port {port}: Unknown (FTP-like) (Detected by FTP FEAT Command)")
        elif service_type == "smtp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                response = s.recv(1024).decode()
                if "220" in response:
                    service_results[port] = ("SMTP", "SMTP Banner Grabbing")
                    print(f"Service on port {port}: SMTP (Detected by SMTP Banner Grabbing)")
                else:
                    service_results[port] = ("Unknown (SMTP-like)", "SMTP Banner Grabbing")
                    print(f"Service on port {port}: Unknown (SMTP-like) (Detected by SMTP Banner Grabbing)")
        elif service_type == "ssh":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((ip, port))
                banner = s.recv(1024).decode()
                if "SSH" in banner:
                    service_results[port] = ("SSH", "SSH Banner Grabbing")
                    print(f"Service on port {port}: SSH (Detected by SSH Banner Grabbing)")
                else:
                    service_results[port] = ("Unknown (SSH-like)", "SSH Banner Grabbing")
                    print(f"Service on port {port}: Unknown (SSH-like) (Detected by SSH Banner Grabbing)")
        else:
            service_results[port] = ("Unknown (No specific detection implemented)", "Default Scan")
            print(f"Service on port {port}: Unknown (No specific detection implemented) (Default Scan)")
    except Exception as e:
        service_results[port] = (f"Failed to identify service: {e}", "Exception")
        print(f"Failed to identify service on port {port}: {e} (Exception)")

def main():
    ip = input("Enter the target IP address: ")
    start_port = int(input("Enter the starting port number: "))
    end_port = int(input("Enter the ending port number: "))

    open_ports = []  # 用于存储所有发现的开放端口
    http_results = {}  # 用于存储HTTP服务识别结果
    https_results = {}  # 用于存储HTTPS服务识别结果
    ftp_results = {}  # 用于存储FTP服务识别结果
    smtp_results = {}  # 用于存储SMTP服务识别结果
    ssh_results = {}  # 用于存储SSH服务识别结果
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port, open_ports)

    # 对每个开放端口进行服务识别
    for port in open_ports:
        if port == 80:
            identify_service(ip, port, "http", http_results)
        elif port == 443:
            identify_service(ip, port, "https", https_results)
        elif port == 21:
            identify_service(ip, port, "ftp", ftp_results)
        elif port == 25:
            identify_service(ip, port, "smtp", smtp_results)
        elif port == 22:
            identify_service(ip, port, "ssh", ssh_results)
        else:
            identify_service(ip, port, "default", {})

    # 显示每个方法的扫描结果
    def display_results(results, service_name):
        if results:
            print(f"\n{service_name} Results:")
            for port, (service, method) in results.items():
                print(f"Port {port}: {service} (Detected by: {method})")
        else:
            print(f"No {service_name} services found.")

    display_results(http_results, "HTTP")
    display_results(https_results, "HTTPS")
    display_results(ftp_results, "FTP")
    display_results(smtp_results, "SMTP")
    display_results(ssh_results, "SSH")

if __name__ == "__main__":
    main()