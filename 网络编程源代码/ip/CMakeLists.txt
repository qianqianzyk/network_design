cmake_minimum_required(VERSION 3.10)

project(ip)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)

# 设置源文件
set(SOURCE_FILES ./internet.cpp)

# 创建可执行文件
add_executable(ip ${SOURCE_FILES})

# 链接必要的库
# 在 Windows 上，可能需要链接 ws2_32.lib 来使用 WinSock
target_link_libraries(ip ws2_32)
