#include "SolistHider.h"
#include "Utils.h"
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <fstream>

SolistHider::SolistHider(RemoteProcess* remote) : m_remote(remote) {}

bool SolistHider::init() {
    // 查找 linker
    auto linkerMap = Utils::findMapByName(m_remote->pid(), "/linker64");
    if (linkerMap.start == 0) {
        linkerMap = Utils::findMapByName(m_remote->pid(), "/linker");
    }
    
    if (linkerMap.start == 0) {
        LOGE("Cannot find linker in target process");
        return false;
    }
    
    if (!m_linkerElf.loadFromMemory(m_remote->pid(), linkerMap.start)) {
        LOGE("Failed to parse linker ELF");
        return false;
    }
    
    LOGI("Linker base: %p", (void*)m_linkerElf.base());
    
    return findLinkerSymbols();
}

bool SolistHider::findLinkerSymbols() {
    // 尝试查找 __dl__ZL6solist 和 __dl__ZL6sonext
    // 这些是 linker 内部符号，可能需要通过其他方式获取
    
    // 方法1: 直接查找符号（可能被 strip）
    m_solistAddr = m_linkerElf.findSymbol("__dl__ZL6solist");
    m_sonextAddr = m_linkerElf.findSymbol("__dl__ZL6sonext");
    
    if (m_solistAddr && m_sonextAddr) {
        LOGI("Found solist: %p, sonext: %p", (void*)m_solistAddr, (void*)m_sonextAddr);
        
        // 读取实际的 solist 指针
        uintptr_t solist = 0;
        m_remote->readMemory(m_solistAddr, &solist, sizeof(solist));
        
        if (solist) {
            return findSoinfoOffsets(solist);
        }
    }
    
    // 方法2: 通过内存扫描查找
    // 这需要更复杂的实现，暂时跳过
    LOGW("Cannot find linker symbols, solist hiding may not work");
    return false;
}

bool SolistHider::findSoinfoOffsets(uintptr_t soinfo) {
    if (!soinfo) return false;
    
    // 读取 soinfo 结构的前 256 字节
    uint8_t buf[256];
    if (m_remote->readMemory(soinfo, buf, sizeof(buf)) != sizeof(buf)) {
        return false;
    }
    
    // soinfo 结构大致布局:
    // - 旧版本: char name[128], phdr*, phnum, entry, base, size, ...
    // - 新版本: 可能有变化
    
    // 尝试找到 base 字段（应该是一个有效的 ELF 基址）
    for (size_t i = 0; i < sizeof(buf) - sizeof(uintptr_t); i += sizeof(uintptr_t)) {
        uintptr_t value = *reinterpret_cast<uintptr_t*>(&buf[i]);
        
        // 检查是否是有效的 ELF 基址
        if (value > 0x10000 && value < 0x800000000000ULL) {
            // 验证是否是 ELF
            uint8_t magic[4];
            if (m_remote->readMemory(value, magic, 4) == 4) {
                if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
                    m_offsets.base = i;
                    LOGI("Found soinfo->base offset: 0x%x", m_offsets.base);
                    break;
                }
            }
        }
    }
    
    if (m_offsets.base == 0) {
        LOGE("Cannot find soinfo->base offset");
        return false;
    }
    
    // 查找 next 字段
    // next 通常在 base 之后不远处，且指向另一个 soinfo
    for (size_t i = m_offsets.base + sizeof(uintptr_t); i < sizeof(buf) - sizeof(uintptr_t); i += sizeof(uintptr_t)) {
        uintptr_t value = *reinterpret_cast<uintptr_t*>(&buf[i]);
        
        if (value == 0) continue;
        
        // 检查是否指向另一个 soinfo（通过检查其 base 字段）
        uintptr_t nextBase = 0;
        if (m_remote->readMemory(value + m_offsets.base, &nextBase, sizeof(nextBase)) == sizeof(nextBase)) {
            // 验证 nextBase 是否是有效的 ELF
            uint8_t magic[4];
            if (m_remote->readMemory(nextBase, magic, 4) == 4) {
                if (memcmp(magic, ELFMAG, SELFMAG) == 0) {
                    m_offsets.next = i;
                    LOGI("Found soinfo->next offset: 0x%x", m_offsets.next);
                    m_offsets.valid = true;
                    return true;
                }
            }
        }
    }
    
    LOGE("Cannot find soinfo->next offset");
    return false;
}

template<typename T>
T SolistHider::readSoinfoField(uintptr_t soinfo, uint32_t offset) {
    T value = 0;
    m_remote->readMemory(soinfo + offset, &value, sizeof(value));
    return value;
}

template<typename T>
bool SolistHider::writeSoinfoField(uintptr_t soinfo, uint32_t offset, T value) {
    return m_remote->writeMemory(soinfo + offset, &value, sizeof(value)) == sizeof(value);
}

bool SolistHider::removeFromSolist(const ElfParser& elf) {
    if (!m_offsets.valid) {
        LOGE("SolistHider not properly initialized");
        return false;
    }
    
    LOGI("Removing ELF %p from solist...", (void*)elf.base());
    
    // 读取 solist 头
    uintptr_t solist = 0;
    if (m_remote->readMemory(m_solistAddr, &solist, sizeof(solist)) != sizeof(solist)) {
        LOGE("Failed to read solist");
        return false;
    }
    
    LOGI("solist head: %p", (void*)solist);
    
    // 遍历链表查找目标 soinfo
    uintptr_t prev = 0;
    uintptr_t curr = solist;
    
    while (curr) {
        uintptr_t base = readSoinfoField<uintptr_t>(curr, m_offsets.base);
        
        if (base == elf.base()) {
            // 找到了
            LOGI("Found target soinfo: %p", (void*)curr);
            
            // 获取 next
            uintptr_t next = readSoinfoField<uintptr_t>(curr, m_offsets.next);
            
            if (prev == 0) {
                // 是链表头，不能直接移除
                LOGE("Target is solist head, cannot remove");
                return false;
            }
            
            // 修改前一个节点的 next 指针
            if (!writeSoinfoField(prev, m_offsets.next, next)) {
                LOGE("Failed to update prev->next");
                return false;
            }
            
            LOGI("Removed soinfo %p from solist", (void*)curr);
            
            // 检查是否需要更新 sonext
            uintptr_t sonext = 0;
            if (m_remote->readMemory(m_sonextAddr, &sonext, sizeof(sonext)) == sizeof(sonext)) {
                if (sonext == curr) {
                    // 更新 sonext 为 prev
                    m_remote->writeMemory(m_sonextAddr, &prev, sizeof(prev));
                    LOGI("Updated sonext to %p", (void*)prev);
                }
            }
            
            return true;
        }
        
        prev = curr;
        curr = readSoinfoField<uintptr_t>(curr, m_offsets.next);
    }
    
    LOGE("Target ELF not found in solist");
    return false;
}
