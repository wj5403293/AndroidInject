#pragma once

#include "Types.h"
#include "RemoteProcess.h"
#include "ElfParser.h"

// soinfo 结构偏移（需要动态查找）
struct SoinfoOffsets {
    uint32_t base = 0;      // soinfo->base
    uint32_t next = 0;      // soinfo->next
    uint32_t flags = 0;     // soinfo->flags
    bool valid = false;
};

class SolistHider {
public:
    explicit SolistHider(RemoteProcess* remote);
    
    // 初始化
    bool init();
    
    // 从 linker solist 中移除 ELF
    bool removeFromSolist(const ElfParser& elf);
    
private:
    // 查找 linker 中的 solist/sonext 地址
    bool findLinkerSymbols();
    
    // 动态查找 soinfo 结构偏移
    bool findSoinfoOffsets(uintptr_t soinfo);
    
    // 读取 soinfo 字段
    template<typename T>
    T readSoinfoField(uintptr_t soinfo, uint32_t offset);
    
    // 写入 soinfo 字段
    template<typename T>
    bool writeSoinfoField(uintptr_t soinfo, uint32_t offset, T value);
    
    RemoteProcess* m_remote;
    ElfParser m_linkerElf;
    
    uintptr_t m_solistAddr = 0;   // &solist
    uintptr_t m_sonextAddr = 0;   // &sonext
    SoinfoOffsets m_offsets;
};
