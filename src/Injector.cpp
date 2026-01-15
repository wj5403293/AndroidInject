#include "Injector.h"
#include "Utils.h"
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <linux/memfd.h>
#include <cstring>
#include <libgen.h>
#include <fstream>

// dlopen flags
#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif

// android_dlopen_ext flags
#ifndef ANDROID_DLEXT_USE_LIBRARY_FD
#define ANDROID_DLEXT_USE_LIBRARY_FD 0x10
#endif

Injector::Injector(pid_t pid) : m_pid(pid) {}

Injector::~Injector() {
    cleanupAllocations();
}

bool Injector::init() {
    m_remote = std::make_unique<RemoteProcess>(m_pid);
    
    // 查找远程 dlopen 等函数
    m_remoteDlopen = m_remote->findRemoteSymbol("dlopen", 
        reinterpret_cast<uintptr_t>(&dlopen));
    if (!m_remoteDlopen) {
        m_lastError = "Cannot find remote dlopen";
        return false;
    }
    LOGI("Remote dlopen: %p", (void*)m_remoteDlopen);
    
    m_remoteDlerror = m_remote->findRemoteSymbol("dlerror",
        reinterpret_cast<uintptr_t>(&dlerror));
    LOGI("Remote dlerror: %p", (void*)m_remoteDlerror);
    
    m_remoteDlclose = m_remote->findRemoteSymbol("dlclose",
        reinterpret_cast<uintptr_t>(&dlclose));
    
    // android_dlopen_ext 可选
    void* dlopenExt = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (dlopenExt) {
        m_remoteDlopenExt = m_remote->findRemoteSymbol("android_dlopen_ext",
            reinterpret_cast<uintptr_t>(dlopenExt));
        LOGI("Remote android_dlopen_ext: %p", (void*)m_remoteDlopenExt);
    }
    
    return true;
}

void Injector::cleanupAllocations() {
    if (!m_remote) return;
    
    for (const auto& alloc : m_allocations) {
        m_remote->remoteFree(alloc.first, alloc.second);
    }
    m_allocations.clear();
}

InjectionResult Injector::inject(const InjectorConfig& config) {
    InjectionResult result;
    
    // 检查库文件
    if (!Utils::fileExists(config.libPath)) {
        result.error = "Library file not found: " + config.libPath;
        return result;
    }
    
    // 验证是 ARM64 ELF
    ElfParser libElf;
    if (!libElf.loadFromFile(config.libPath)) {
        result.error = "Invalid ELF file or not ARM64";
        return result;
    }
    
    // 设置默认 caller（参考原项目使用 libRS.so 的基地址）
    // 需要找一个有效但不可执行的地址，函数返回后跳转到该地址会触发 SIGSEGV
    auto maps = Utils::parseMaps(m_pid);
    uintptr_t defaultCaller = 0;
    
    // 优先查找 libRS.so
    for (const auto& map : maps) {
        if (map.path.find("libRS.so") != std::string::npos && map.offset == 0) {
            defaultCaller = map.start;
            LOGI("Default caller (libRS.so): %p", (void*)defaultCaller);
            break;
        }
    }
    
    // 如果没有 libRS.so，使用 libc.so 的只读段（offset=0）
    if (!defaultCaller) {
        for (const auto& map : maps) {
            if (map.path.find("libc.so") != std::string::npos && map.offset == 0) {
                defaultCaller = map.start;
                LOGI("Default caller (libc.so): %p", (void*)defaultCaller);
                break;
            }
        }
    }
    
    m_remote->setDefaultCaller(defaultCaller);
    
    // 附加到进程（PTRACE_ATTACH 会自动停止进程）
    if (!m_remote->attach()) {
        result.error = "Failed to attach to process";
        return result;
    }
    
    // 选择注入方式
    if (config.useMemfd && m_remoteDlopenExt) {
        result = injectWithMemfd(config.libPath, config.dlFlags);
        if (!result.success) {
            LOGW("Memfd injection failed, falling back to dlopen");
            result = injectWithDlopen(config.libPath, config.dlFlags);
        }
    } else {
        // 常规 dlopen 模式
        std::string targetLibPath = config.libPath;
        
        // 如果启用了复制到私有目录，先复制文件
        if (config.copyToPrivate && !config.pkgName.empty()) {
            std::string copiedPath = copyLibToPrivateDir(config.libPath, config.pkgName);
            if (!copiedPath.empty()) {
                targetLibPath = copiedPath;
                m_copiedLibPath = copiedPath;
                LOGI("Using copied library: %s", targetLibPath.c_str());
            } else {
                LOGW("Failed to copy library to private dir, using original path");
            }
        }
        
        result = injectWithDlopen(targetLibPath, config.dlFlags);
        
        // 无论成功与否，删除复制的文件
        if (!m_copiedLibPath.empty()) {
            if (unlink(m_copiedLibPath.c_str()) == 0) {
                LOGI("Deleted copied library: %s", m_copiedLibPath.c_str());
            } else {
                LOGW("Failed to delete copied library: %s (errno=%d)", m_copiedLibPath.c_str(), errno);
            }
            m_copiedLibPath.clear();
        }
    }
    
    if (result.success) {
        // 获取加载后的 ELF 信息
        ElfParser injectedElf;
        if (injectedElf.loadFromMemory(m_pid, result.base)) {
            // 隐藏处理
            if (config.hideMaps) {
                hideFromMaps(injectedElf);
            }
            if (config.hideSolist) {
                hideFromSolist(injectedElf);
            }
            
            // 调用 JNI_OnLoad（在 detach 之前）
            callEntryPoint(result.handle, injectedElf);
        } else {
            LOGW("Failed to parse injected library, skipping entry point call");
        }
    } else {
        // 获取错误信息
        std::string err = getDlerror();
        if (!err.empty()) {
            result.error = err;
        }
    }
    
    // 清理
    cleanupAllocations();
    m_remote->detach();
    
    // 恢复进程执行
    kill(m_pid, SIGCONT);
    
    return result;
}

InjectionResult Injector::injectWithDlopen(const std::string& libPath, int flags) {
    InjectionResult result;
    
    LOGI("Injecting with dlopen: %s", libPath.c_str());
    
    // 在远程进程分配路径字符串
    uintptr_t remotePathAddr = m_remote->remoteAllocString(libPath);
    if (!remotePathAddr) {
        result.error = "Failed to allocate remote memory for path";
        return result;
    }
    m_allocations.push_back({remotePathAddr, libPath.size() + 1});
    
    // 调用 dlopen(path, flags)
    uintptr_t handle = m_remote->callFunctionFrom(0, m_remoteDlopen, 2, 
        remotePathAddr, (uintptr_t)flags);
    
    if (!handle || handle == static_cast<uintptr_t>(-1)) {
        result.error = "dlopen returned NULL";
        return result;
    }
    
    result.handle = handle;
    result.success = true;
    
    // 查找加载的库基址
    auto map = Utils::findMapByName(m_pid, libPath);
    if (map.start) {
        result.base = map.start;
    }
    
    LOGI("Library loaded at %p, handle: %p", (void*)result.base, (void*)result.handle);
    return result;
}

std::string Injector::copyLibToPrivateDir(const std::string& libPath, const std::string& pkgName) {
    // 构建目标私有目录路径: /data/user/0/<pkg>/files/
    // 注意: /data/data/<pkg> 是 /data/user/0/<pkg> 的符号链接
    std::string privateDir = Utils::format("/data/user/0/%s/files", pkgName.c_str());
    
    // 检查目录是否存在，如果不存在尝试创建
    struct stat st;
    if (stat(privateDir.c_str(), &st) != 0) {
        LOGW("Private directory does not exist: %s", privateDir.c_str());
        // 尝试使用 /data/data/<pkg>/files 作为备选
        privateDir = Utils::format("/data/data/%s/files", pkgName.c_str());
        if (stat(privateDir.c_str(), &st) != 0) {
            LOGE("Cannot access private directory for package: %s", pkgName.c_str());
            return "";
        }
    }
    
    // 提取库文件名
    std::string libName;
    size_t lastSlash = libPath.rfind('/');
    if (lastSlash != std::string::npos) {
        libName = libPath.substr(lastSlash + 1);
    } else {
        libName = libPath;
    }
    
    // 为避免冲突，添加随机后缀
    std::string randomSuffix = Utils::randomString(6);
    std::string targetPath = Utils::format("%s/.%s_%s", 
        privateDir.c_str(), randomSuffix.c_str(), libName.c_str());
    
    LOGI("Copying library to private directory:");
    LOGI("  Source: %s", libPath.c_str());
    LOGI("  Target: %s", targetPath.c_str());
    
    // 读取源文件
    auto libData = Utils::readFile(libPath);
    if (libData.empty()) {
        LOGE("Failed to read source library: %s", libPath.c_str());
        return "";
    }
    
    // 写入目标文件
    if (!Utils::writeFile(targetPath, libData.data(), libData.size())) {
        LOGE("Failed to write library to: %s", targetPath.c_str());
        return "";
    }
    
    // 设置文件权限为可读可执行 (0755)
    if (chmod(targetPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        LOGW("Failed to set permissions on: %s (errno=%d)", targetPath.c_str(), errno);
        // 继续尝试，可能仍然可以工作
    }
    
    // 获取目标进程的 UID 并尝试修改文件所有者
    // 这样目标进程就有权限访问该文件
    std::string statusPath = Utils::format("/proc/%d/status", m_pid);
    std::ifstream statusFile(statusPath);
    if (statusFile) {
        std::string line;
        while (std::getline(statusFile, line)) {
            if (line.find("Uid:") == 0) {
                uid_t uid;
                if (sscanf(line.c_str(), "Uid:\t%u", &uid) == 1) {
                    if (chown(targetPath.c_str(), uid, uid) != 0) {
                        LOGW("Failed to chown to uid %u: %s", uid, strerror(errno));
                    } else {
                        LOGI("Changed owner to uid: %u", uid);
                    }
                }
                break;
            }
        }
    }
    
    LOGI("Library copied successfully to: %s", targetPath.c_str());
    return targetPath;
}

InjectionResult Injector::injectWithMemfd(const std::string& libPath, int flags) {
    InjectionResult result;
    
    LOGI("Injecting with memfd: %s", libPath.c_str());
    
    // 生成随机名称
    std::string memfdName = Utils::randomString(8);
    
    // 创建远程 memfd
    int remoteFd = m_remote->remoteMemfdCreate(memfdName, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (remoteFd < 0) {
        result.error = "memfd_create failed";
        return result;
    }
    
    LOGI("Remote memfd created: %d", remoteFd);
    
    // 通过 /proc/[pid]/fd/[fd] 写入库内容
    std::string fdPath = Utils::format("/proc/%d/fd/%d", m_pid, remoteFd);
    
    // 读取库文件
    auto libData = Utils::readFile(libPath);
    if (libData.empty()) {
        result.error = "Failed to read library file";
        return result;
    }
    
    // 写入到远程 memfd
    int fd = open(fdPath.c_str(), O_RDWR);
    if (fd < 0) {
        result.error = "Failed to open remote memfd";
        return result;
    }
    
    ssize_t written = write(fd, libData.data(), libData.size());
    close(fd);
    
    if (written != static_cast<ssize_t>(libData.size())) {
        result.error = "Failed to write to memfd";
        return result;
    }
    
    // 封印 memfd
    m_remote->syscall(Syscall::FCNTL, remoteFd, F_ADD_SEALS,
                      F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
    
    // 构造 android_dlextinfo
    struct android_dlextinfo {
        uint64_t flags;
        void* reserved_addr;
        size_t reserved_size;
        int relro_fd;
        int library_fd;
        off64_t library_fd_offset;
        void* library_namespace;
    };
    
    android_dlextinfo extinfo{};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;  // ANDROID_DLEXT_USE_LIBRARY_FD
    extinfo.library_fd = remoteFd;
    
    // 分配远程内存存储 extinfo
    uintptr_t remoteExtinfo = m_remote->remoteAlloc(sizeof(extinfo), PROT_READ | PROT_WRITE);
    if (!remoteExtinfo) {
        result.error = "Failed to allocate memory for dlextinfo";
        return result;
    }
    m_allocations.push_back({remoteExtinfo, sizeof(extinfo)});
    
    m_remote->writeMemory(remoteExtinfo, &extinfo, sizeof(extinfo));
    
    // 分配名称字符串
    uintptr_t remoteNameAddr = m_remote->remoteAllocString(memfdName);
    if (!remoteNameAddr) {
        result.error = "Failed to allocate memory for name";
        return result;
    }
    m_allocations.push_back({remoteNameAddr, memfdName.size() + 1});
    
    // 调用 android_dlopen_ext(name, flags, extinfo)
    uintptr_t handle = m_remote->callFunctionFrom(0, m_remoteDlopenExt, 3,
        remoteNameAddr, 
        (uintptr_t)flags, 
        remoteExtinfo
    );
    
    if (!handle || handle == static_cast<uintptr_t>(-1)) {
        result.error = "android_dlopen_ext returned NULL";
        return result;
    }
    
    result.handle = handle;
    result.success = true;
    
    // 查找加载的库基址
    std::string memfdPath = "/memfd:" + memfdName;
    auto map = Utils::findMapByName(m_pid, memfdPath);
    if (map.start) {
        result.base = map.start;
    }
    
    LOGI("Library loaded via memfd at %p, handle: %p", (void*)result.base, (void*)result.handle);
    return result;
}

std::string Injector::getDlerror() {
    if (!m_remoteDlerror) return "";
    
    uintptr_t errPtr = m_remote->callFunctionFrom(0, m_remoteDlerror, 0);
    
    if (errPtr && errPtr != static_cast<uintptr_t>(-1)) {
        return m_remote->readString(errPtr);
    }
    return "";
}

uintptr_t Injector::getJavaVM() {
    // 查找 libart.so - 需要找到包含 ELF header 的段
    auto maps = Utils::parseMaps(m_pid);
    MapEntry artMap{};
    
    // 遍历所有 libart.so 的映射，找到包含有效 ELF header 的
    for (const auto& map : maps) {
        if (map.path.find("libart.so") == std::string::npos) continue;
        if (!map.isReadable()) continue;
        
        // 检查是否包含 ELF 魔数
        char magic[4] = {0};
        if (m_remote->readMemory(map.start, magic, sizeof(magic)) == sizeof(magic)) {
            if (memcmp(magic, "\x7f" "ELF", 4) == 0) {
                artMap = map;
                break;
            }
        }
    }
    
    if (artMap.start == 0) {
        LOGE("Cannot find libart.so with valid ELF header");
        return 0;
    }
    
    LOGI("Found libart.so at %p (path: %s)", (void*)artMap.start, artMap.path.c_str());
    
    // 解析 libart
    ElfParser artElf;
    if (!artElf.loadFromMemory(m_pid, artMap.start)) {
        LOGE("Failed to parse libart.so at %p", (void*)artMap.start);
        return 0;
    }
    
    LOGI("Parsed libart.so: base=%p, dynstr=%p, dynsym=%p", 
         (void*)artElf.base(), (void*)artElf.stringTable(), (void*)artElf.symbolTable());
    
    // 查找 JNI_GetCreatedJavaVMs
    uintptr_t getJavaVMs = artElf.findSymbol("JNI_GetCreatedJavaVMs");
    if (!getJavaVMs) {
        LOGE("Cannot find JNI_GetCreatedJavaVMs");
        return 0;
    }
    
    LOGI("JNI_GetCreatedJavaVMs: %p", (void*)getJavaVMs);
    
    // 分配缓冲区: JavaVM* + jsize
    size_t bufSize = sizeof(uintptr_t) + sizeof(int);
    uintptr_t remoteBuf = m_remote->remoteAlloc(bufSize, PROT_READ | PROT_WRITE);
    if (!remoteBuf) {
        return 0;
    }
    m_allocations.push_back({remoteBuf, bufSize});
    
    // 调用 JNI_GetCreatedJavaVMs(vmBuf, 1, &nVMs)
    uintptr_t status = m_remote->callFunctionFrom(0, getJavaVMs, 3,
        remoteBuf,                          // vmBuf
        (uintptr_t)1,                       // bufLen
        remoteBuf + sizeof(uintptr_t)       // nVMs
    );
    
    if (status != 0) {
        LOGE("JNI_GetCreatedJavaVMs failed: %lu", status);
        return 0;
    }
    
    // 读取结果
    uintptr_t jvm = 0;
    m_remote->readMemory(remoteBuf, &jvm, sizeof(jvm));
    
    LOGI("JavaVM: %p", (void*)jvm);
    return jvm;
}

bool Injector::callEntryPoint(uintptr_t handle, const ElfParser& elf) {
    // 获取 JavaVM
    uintptr_t jvm = getJavaVM();
    if (!jvm) {
        LOGW("Cannot get JavaVM, skipping JNI_OnLoad");
        return false;
    }
    
    // 查找 JNI_OnLoad
    uintptr_t jniOnLoad = elf.findSymbol("JNI_OnLoad");
    if (!jniOnLoad) {
        LOGI("JNI_OnLoad not found in library");
        return true;  // 不是错误
    }
    
    LOGI("Calling JNI_OnLoad at %p", (void*)jniOnLoad);
    
    // 调用 JNI_OnLoad(JavaVM*, secretKey)
    // secretKey = 1337 用于被注入库识别
    // 使用默认 caller（会触发 SIGSEGV）
    constexpr uintptr_t SECRET_KEY = 1337;
    
    uintptr_t ret = m_remote->callFunctionFrom(0, jniOnLoad, 2, jvm, SECRET_KEY);
    LOGI("JNI_OnLoad returned: 0x%lx", ret);
    
    return true;
}

bool Injector::hideFromMaps(const ElfParser& elf) {
    LOGI("Hiding library from maps...");
    
    auto maps = Utils::parseMaps(m_pid);
    
    for (const auto& map : maps) {
        // 查找属于注入库的映射
        if (map.start < elf.base() || map.start >= elf.base() + elf.loadSize()) {
            continue;
        }
        
        if (map.path.empty()) continue;
        
        LOGI("Hiding segment: %lx-%lx", map.start, map.end);
        
        // 备份内容
        size_t size = map.size();
        std::vector<uint8_t> backup(size);
        if (m_remote->readMemory(map.start, backup.data(), size) != static_cast<ssize_t>(size)) {
            LOGE("Failed to backup segment");
            continue;
        }
        
        // 解除映射
        m_remote->syscall(Syscall::MUNMAP, map.start, size, 0, 0, 0, 0);
        
        // 重新映射为匿名内存（使用 MAP_FIXED）
        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        uintptr_t newAddr = m_remote->syscall(Syscall::MMAP, map.start, size, 
                                              (uintptr_t)map.prot, (uintptr_t)flags, 0, 0);
        
        if (newAddr != map.start) {
            LOGE("Failed to remap segment at original address: got %p", (void*)newAddr);
            return false;
        }
        
        // 恢复内容
        m_remote->writeMemory(map.start, backup.data(), size);
    }
    
    return true;
}

bool Injector::hideFromSolist(const ElfParser& elf) {
    LOGI("Hiding library from solist...");
    
    if (!m_solistHider) {
        m_solistHider = std::make_unique<SolistHider>(m_remote.get());
        if (!m_solistHider->init()) {
            LOGW("Failed to initialize SolistHider");
            return false;
        }
    }
    
    return m_solistHider->removeFromSolist(elf);
}
