#include "Utils.h"
#include <fstream>
#include <sstream>
#include <cstdarg>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <random>
#include <chrono>

namespace Utils {

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    
    auto size = file.tellg();
    file.seekg(0);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

bool writeFile(const std::string& path, const void* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(static_cast<const char*>(data), size);
    return file.good();
}

pid_t getProcessPid(const std::string& processName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    
    pid_t result = -1;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        // 检查是否为数字目录
        char* end;
        pid_t pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0') continue;
        
        // 读取 cmdline
        std::string cmdlinePath = format("/proc/%d/cmdline", pid);
        std::ifstream cmdline(cmdlinePath);
        std::string name;
        std::getline(cmdline, name, '\0');
        
        if (name == processName) {
            result = pid;
            break;
        }
    }
    
    closedir(dir);
    return result;
}

std::vector<MapEntry> parseMaps(pid_t pid) {
    std::vector<MapEntry> maps;
    std::string path = format("/proc/%d/maps", pid);
    std::ifstream file(path);
    
    std::string line;
    while (std::getline(file, line)) {
        MapEntry entry{};
        char perms[5] = {0};
        char pathBuf[512] = {0};
        
        int n = sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*s %511[^\n]",
                       &entry.start, &entry.end, perms, &entry.offset, pathBuf);
        
        if (n >= 4) {
            entry.prot = 0;
            if (perms[0] == 'r') entry.prot |= 0x1;
            if (perms[1] == 'w') entry.prot |= 0x2;
            if (perms[2] == 'x') entry.prot |= 0x4;
            entry.path = pathBuf;
            
            // 去除路径前的空格
            size_t start = entry.path.find_first_not_of(' ');
            if (start != std::string::npos) {
                entry.path = entry.path.substr(start);
            }
            
            maps.push_back(entry);
        }
    }
    
    return maps;
}

MapEntry findMapByName(pid_t pid, const std::string& name) {
    auto maps = parseMaps(pid);
    
    // 优先查找 offset=0 的段（ELF header 所在位置）
    for (const auto& map : maps) {
        if (map.path.find(name) != std::string::npos && map.offset == 0) {
            return map;
        }
    }
    
    // 如果没有 offset=0 的段，返回第一个可读段
    for (const auto& map : maps) {
        if (map.path.find(name) != std::string::npos && map.isReadable()) {
            return map;
        }
    }
    
    // 最后返回第一个匹配的
    for (const auto& map : maps) {
        if (map.path.find(name) != std::string::npos) {
            return map;
        }
    }
    
    return {};
}

std::string format(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return buf;
}

std::string getErrorString(int err) {
    return strerror(err);
}

bool fileExists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

std::string randomString(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

} // namespace Utils
