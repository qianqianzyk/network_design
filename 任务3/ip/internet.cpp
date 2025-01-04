#include "winsock2.h"
#include "mstcpip.h"
#include <iostream>
#include <cstring>
#include <ws2tcpip.h>
#include <unistd.h>
#include <thread>

using namespace std;
#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_BUFLEN 65535   // 定义默认缓冲区大小为 65535 字节
#define CUSTOM_PROTOCOL 222   // 自定义运输层协议号
#define DEFAULT_NAMELEN 512  // 定义默认名称长度为 512 字节

// 自定义协议头部
struct CustomHeader {
    uint16_t id;     // 自定义标识
    uint16_t length; // 数据长度
};

// IP 头部
struct ip {
    uint8_t ip_hl : 4, ip_v : 4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

// 计算IP首部校验和
unsigned short calculate_checksum(unsigned short *buffer, int size)
{
    unsigned long checksum = 0;
    // 逐块累加
    while (size > 0)
    {
        checksum += *buffer++;
        size -= 2; // 每次读取两个字节
    }
    // 处理溢出（高 16 位加回低 16 位）
    while (checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    // 取反得到最终校验和
    return ~checksum;
}

// 创建并发送自定义IP包
void send_custom_packet(const char *src_ip, const char *dest_ip, const char *payload)
{
    // 创建原始套接字（AF_INET：IPv4 地址家族；SOCK_RAW：原始套接字，允许操作完整的数据包（包括 IP 头）；IPPROTO_RAW：表示发送数据时不会指定协议，需完全构造 IP 包）
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0)
    {
        cout << "Socket creation failed" << endl;
        exit(EXIT_FAILURE);
    }
    // 设置 IP_HDRINCL 选项，表示自己构造 IP 首部（IPPROTO_IP：IP 层（适用于与 IP 协议相关的选项，如设置 IP 地址、IP 路由等）；IP_HDRINCL：告诉内核自己将构造IP首部；&opt：1表示启用该选项；sizeof(opt)：表示opt的大小）
    int opt = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, reinterpret_cast<const char *>(&opt), sizeof(opt)) < 0)
    {
        cout << "Failed to set IP_HDRINCL" << endl;
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 声明 sockaddr_in 结构体变量 dest_addr,用来存储 IPv4 地址的结构体
    struct sockaddr_in dest_addr;
    // 地址族标识符，告诉系统使用 IPv4 地址
    dest_addr.sin_family = AF_INET;
    // 表明不需要为原始 IP 数据包指定端口号
    dest_addr.sin_port = 0;
    // 将点分十进制格式的 IP 地址字符串转换为网络字节顺序的二进制形式
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) != 1)
    {
        cout << "Invalid address" << endl;
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    // 构造 IP 首部
    char packet[DEFAULT_BUFLEN];
    memset(packet, 0, DEFAULT_BUFLEN);

    struct ip* ip_header = reinterpret_cast<struct ip*>(packet);
    ip_header->ip_hl = 5;               // IP 首部长度（20字节）
    ip_header->ip_v = 4;                // IPv4 版本
    ip_header->ip_tos = 0;              // 服务类型
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(CustomHeader) + strlen(payload)); // 总长度
    ip_header->ip_id = htons(54321);    // 标识
    ip_header->ip_off = 0;              // 无分片
    ip_header->ip_ttl = 64;             // 生存时间
    ip_header->ip_p = CUSTOM_PROTOCOL;  // 自定义协议号
    inet_pton(AF_INET, src_ip, &ip_header->ip_src); // 源地址
    inet_pton(AF_INET, dest_ip, &ip_header->ip_dst); // 目的地址
    ip_header->ip_sum = calculate_checksum(reinterpret_cast<unsigned short*>(ip_header), ip_header->ip_hl * 2);

    // 构造自定义协议头部
    CustomHeader* custom_header = reinterpret_cast<CustomHeader*>(packet + sizeof(struct ip));
    custom_header->id = htons(1234);                // 自定义标识
    custom_header->length = htons(strlen(payload)); // 数据长度

    // 添加数据
    char* data = packet + sizeof(struct ip) + sizeof(CustomHeader);
    strcpy(data, payload);

    // 发送数据包
    if (sendto(sockfd, packet, ntohs(ip_header->ip_len), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        cout << "Packet sending failed" << endl;
    } else {
        cout << "Packet sent successfully!" << endl;
    }

    // 关闭套接字
    close(sockfd);
}

// 接收并解析自定义协议的数据包
void receive_custom_packets() {
    SOCKET SnifferSocket = INVALID_SOCKET; // 定义原始套接字，用于捕获网络数据包
    char HostName[DEFAULT_NAMELEN];        // 存储本地主机名
    HOSTENT* local;                        // 用于存储本地网络接口信息
    SOCKADDR_IN LocalAddr;                 // 本地地址结构(IPV4)
    char recvbuf[DEFAULT_BUFLEN];          // 数据接收缓冲区
    int addrlen = sizeof(SOCKADDR_IN);     // 地址长度
    SOCKADDR_IN RemoteAddr;                // 远程地址结构
    int iResult;                           // 存储接收结果
    int in = 0, i = 0;                     // 用户选择的接口序号
    DWORD Optval = 1;                      // 开启捕获所有数据包选项
    DWORD dwBytesReturned = 0;             // 接收 WSAIoctl 返回的字节数


    // 创建原始套接字（AF_INET：IPv4；SOCK_RAW：原始套接字；CUSTOM_PROTOCOL：指定自定义协议）
    SnifferSocket = socket(AF_INET, SOCK_RAW, CUSTOM_PROTOCOL);
    if (INVALID_SOCKET == SnifferSocket) {
        cout << "套接字创建失败：" << WSAGetLastError() << endl;
        return;
    }

    // 用 memset 初始化 HostName 数组，清空数组内容
    memset(HostName, 0, DEFAULT_NAMELEN);
    // 调用 gethostname 函数获取本机名称
    if (gethostname(HostName, sizeof(HostName)) == SOCKET_ERROR) {
        cout << "获取本机名称失败：" << WSAGetLastError() << endl;
        closesocket(SnifferSocket);
        return;
    }

    // 通过主机名获取本机所有网络接口的 IP 地址信息
    local = gethostbyname(HostName);
    if (NULL == local) {
        cout << "获取 IP 地址失败：" << WSAGetLastError() << endl;
        closesocket(SnifferSocket);
        return;
    }
    cout << "本机可用的 IP 地址：" << endl;
    // 遍历本机的 IP 地址列表（h_addr_list 是指针数组，保存了本机所有网络接口的 IP 地址）
    while (local->h_addr_list[i] != 0) {
        IN_ADDR addr;  // 定义一个 IN_ADDR 结构体变量，用于存储单个 IP 地址
        addr.s_addr = *(u_long*)local->h_addr_list[i++];  // 将 IP 地址从列表中取出，并存储到 addr.s_addr 中
        cout << "\t" << i << ": " << inet_ntoa(addr) << endl;  // 使用 inet_ntoa 将 IP 地址转换为点分十进制字符串并输出
    }

    // 用户选择接口
    cout << "请选择捕获数据包的接口号：";
    cin >> in;

    // 检查用户输入是否合法
    if (in <= 0 || in > i) {
        cout << "接口号无效！" << endl;
        closesocket(SnifferSocket); // 清理资源
        return;
    }

    // 配置本地地址绑定到选定的接口
    memset(&LocalAddr, 0, sizeof(LocalAddr));
    // 将用户选择的 IP 地址复制到 LocalAddr 的 sin_addr 成员中
    // S_un.S_addr 是其中的一个成员，表示 IPv4 地址的二进制形式（以 uint32_t 存储的 32 位地址，网络字节序）
    memcpy(&LocalAddr.sin_addr.S_un.S_addr, local->h_addr_list[in - 1], sizeof(LocalAddr.sin_addr.S_un.S_addr));
    LocalAddr.sin_family = AF_INET;   // 使用 IPv4
    LocalAddr.sin_port = 0;            // 不绑定端口号

    // 绑定套接字到本地接口
    if (bind(SnifferSocket, (SOCKADDR*)&LocalAddr, sizeof(LocalAddr)) == SOCKET_ERROR) {
        cout << "绑定失败：" << WSAGetLastError() << endl;
        closesocket(SnifferSocket);
        return;
    }
    cout << "成功绑定到接口 " << in << endl;

    // 设置套接字接受所有数据包
    // 调用 WSAIoctl 函数，将套接字设置为混杂模式（promiscuous mode），以便接收所有流经该接口的数据包
    // SnifferSocket：要设置的原始套接字
    // SIO_RCVALL：命令码，表示设置套接字为接收所有数据包模式
    // &Optval：设置值，1 表示启用接收所有数据包的模式
    // sizeof(Optval)：Optval 的大小
    // NULL, 0：没有附加的输入或输出缓冲区
    // &dwBytesReturned：输出的字节数，通常未使用
    // NULL, NULL：未使用的事件和重叠 I/O 参数
    if (WSAIoctl(SnifferSocket, SIO_RCVALL, &Optval, sizeof(Optval), NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
        cout << "套接字设置失败：" << WSAGetLastError() << endl;
        closesocket(SnifferSocket);
        return;
    }

    cout << "开始接受数据..." << endl;
    do {
        // 接收数据
        iResult = recvfrom(SnifferSocket, recvbuf, DEFAULT_BUFLEN, 0, (SOCKADDR*)&RemoteAddr, &addrlen);
        if (iResult > 0) {
            cout << "收到来自 " << inet_ntoa(RemoteAddr.sin_addr) << " 的数据包，长度：" << iResult << " 字节" << endl;

            // 解析 IP 头部
            struct ip* ip_header = reinterpret_cast<struct ip*>(recvbuf);
            // INET_ADDRSTRLEN 表示存储 IPv4 地址字符串所需的缓冲区长度
            char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);

            // 输出 IP 头部信息
            cout << "源 IP: " << src_ip << "，目的 IP: " << dest_ip << endl;
            cout << "版本号: " << (int)ip_header->ip_v << endl;
            cout << "总长度: " << ntohs(ip_header->ip_len) << " 字节" << endl;
            cout << "标识: " << ntohs(ip_header->ip_id) << endl;
            cout << "标志位: " << ((ip_header->ip_off & 0xE000) >> 13) << endl;  // 高 3 位是标志位
            cout << "片偏移: " << (ip_header->ip_off & 0x1FFF) << endl; // 低 13 位是偏移量
            cout << "协议: " << (int)ip_header->ip_p << endl;

            // 检查协议是否为自定义协议
            if (ip_header->ip_p == CUSTOM_PROTOCOL) {
                // 解析自定义协议头部
                CustomHeader* custom_header = reinterpret_cast<CustomHeader*>(recvbuf + ip_header->ip_hl * 4);
                uint16_t payload_length = ntohs(custom_header->length);
                uint16_t id = ntohs(custom_header->id);

                cout << "自定义协议 ID: " << id << ", 数据长度: " << payload_length << endl;

                // 解析有效载荷
                char* payload = recvbuf + ip_header->ip_hl * 4 + sizeof(CustomHeader);
                cout << "数据内容: " << string(payload, payload_length) << endl;
            } else {
                cout << "非自定义协议数据包，协议号: " << int(ip_header->ip_p) << endl;
            }
            cout << "---------------------------------------------" << endl;
        } else {
            cout << "接收失败，错误代码: " << WSAGetLastError() << endl;
        }
    } while (iResult > 0);

    // 关闭套接字
    closesocket(SnifferSocket);
    cout << "接收结束，套接字已关闭。" << endl;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cout << "WSAStartup failed" << endl;
        return 1;
    }

    int choice;
    cout << "1. Send Custom Packet" << endl;
    cout << "2. Receive Custom Packet" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    if (choice == 1) {
        send_custom_packet("192.168.72.1", "192.168.72.1", "qianqianzyk:Hello World!");
    } else if (choice == 2) {
        receive_custom_packets();
    } else {
        cout << "Invalid choice!" << endl;
    }

    WSACleanup();

    return 0;
}
