#include "Types.h"
#include "Utils.h"
#include "Injector.h"
#include "ProcessMonitor.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>

void printUsage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\nRequired:\n");
    printf("  -p, --pkg <name>     Target package name\n");
    printf("  -l, --lib <path>     Library path to inject\n");
    printf("\nOptional:\n");
    printf("  -i, --pid <pid>      Target PID (if known)\n");
    printf("  -m, --memfd          Use memfd injection\n");
    printf("  -H, --hide-maps      Hide from /proc/[pid]/maps\n");
    printf("  -S, --hide-solist    Hide from linker solist\n");
    printf("  -w, --watch          Watch for process start\n");
    printf("  -d, --delay <us>     Delay before injection (microseconds)\n");
    printf("  -t, --timeout <ms>   Watch timeout (milliseconds)\n");
    printf("  -n, --no-copy        Don't copy lib to private dir (use original path)\n");
    printf("  -h, --help           Show this help\n");
}

int main(int argc, char* argv[]) {
    // 禁用缓冲
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    
    // 参数
    std::string pkgName;
    std::string libPath;
    pid_t targetPid = 0;
    bool useMemfd = false;
    bool hideMaps = false;
    bool hideSolist = false;
    bool watchMode = false;
    bool copyToPrivate = true;  // 默认启用复制到私有目录
    unsigned int delay = 0;
    int timeout = -1;
    
    // 解析命令行
    static struct option longOpts[] = {
        {"pkg",         required_argument, nullptr, 'p'},
        {"lib",         required_argument, nullptr, 'l'},
        {"pid",         required_argument, nullptr, 'i'},
        {"memfd",       no_argument,       nullptr, 'm'},
        {"hide-maps",   no_argument,       nullptr, 'H'},
        {"hide-solist", no_argument,       nullptr, 'S'},
        {"watch",       no_argument,       nullptr, 'w'},
        {"delay",       required_argument, nullptr, 'd'},
        {"timeout",     required_argument, nullptr, 't'},
        {"no-copy",     no_argument,       nullptr, 'n'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:i:mHSwd:t:nh", longOpts, nullptr)) != -1) {
        switch (opt) {
            case 'p': pkgName = optarg; break;
            case 'l': libPath = optarg; break;
            case 'i': targetPid = atoi(optarg); break;
            case 'm': useMemfd = true; break;
            case 'H': hideMaps = true; break;
            case 'S': hideSolist = true; break;
            case 'w': watchMode = true; break;
            case 'd': delay = atoi(optarg); break;
            case 't': timeout = atoi(optarg); break;
            case 'n': copyToPrivate = false; break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    // 验证参数
    if (pkgName.empty() || libPath.empty()) {
        LOGE("Missing required arguments");
        printUsage(argv[0]);
        return 1;
    }
    
    // 检查库文件
    if (!Utils::fileExists(libPath)) {
        LOGE("Library not found: %s", libPath.c_str());
        return 1;
    }
    
    LOGI("=== NewInjector ===");
    LOGI("Package: %s", pkgName.c_str());
    LOGI("Library: %s", libPath.c_str());
    LOGI("Use memfd: %s", useMemfd ? "yes" : "no");
    LOGI("Hide maps: %s", hideMaps ? "yes" : "no");
    LOGI("Hide solist: %s", hideSolist ? "yes" : "no");
    LOGI("Watch mode: %s", watchMode ? "yes" : "no");
    LOGI("Copy to private: %s", copyToPrivate ? "yes" : "no");
    
    // 获取目标 PID
    if (targetPid <= 0) {
        if (watchMode) {
            // 检查进程是否已经运行
            pid_t existingPid = Utils::getProcessPid(pkgName);
            if (existingPid > 0) {
                LOGE("Process already running (pid=%d), cannot use watch mode", existingPid);
                return 1;
            }
            
            LOGI("Waiting for process %s to start...", pkgName.c_str());
            
            ProcessMonitor monitor;
            targetPid = monitor.waitForProcess(pkgName, timeout);
            
            if (targetPid <= 0) {
                LOGE("Timeout waiting for process");
                return 1;
            }
            
            LOGI("Process started with PID: %d", targetPid);
        } else {
            targetPid = Utils::getProcessPid(pkgName);
            if (targetPid <= 0) {
                LOGE("Cannot find process: %s", pkgName.c_str());
                return 1;
            }
        }
    }
    
    LOGI("Target PID: %d", targetPid);
    
    // 延迟
    if (delay > 0) {
        LOGI("Waiting %u microseconds...", delay);
        usleep(delay);
    }
    
    // 创建注入器
    Injector injector(targetPid);
    
    if (!injector.init()) {
        LOGE("Failed to initialize injector: %s", injector.lastError().c_str());
        return 1;
    }
    
    // 配置
    InjectorConfig config;
    config.libPath = libPath;
    config.pkgName = pkgName;
    config.useMemfd = useMemfd;
    config.hideMaps = hideMaps;
    config.hideSolist = hideSolist;
    config.dlFlags = RTLD_NOW;
    config.copyToPrivate = copyToPrivate;
    
    // 执行注入
    LOGI("Starting injection...");
    auto result = injector.inject(config);
    
    if (result.success) {
        LOGI("=== Injection successful ===");
        LOGI("Handle: %p", (void*)result.handle);
        LOGI("Base: %p", (void*)result.base);
        return 0;
    } else {
        LOGE("=== Injection failed ===");
        LOGE("Error: %s", result.error.c_str());
        return 1;
    }
}
