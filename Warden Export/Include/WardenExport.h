#pragma once
#pragma warning(disable : 4996)

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX  // ✅ Prevent macro pollution early!

#include "Windows.h"
#include <MemoryOperator.h>
#include <vector>
#include <string>
#include <iostream>
#include <wincrypt.h>
#include <map>
#include <set>

#pragma comment(lib, "advapi32.lib")

typedef unsigned char BYTE;


struct ImportPatch 
{
    std::string dll;
    std::string funcName;
    DWORD Address;
};

class WardenExport {
public:
    bool Load(const void* moduleDataRaw, size_t moduleSizeRaw, const std::string& path);
    static bool Hook();
    static std::string ComputeSHA256(const BYTE* data, size_t size);

private:
    bool ParseHeader();
    bool MapSections();
    bool ApplyRelocations();
    bool ResolveImports();
    bool SetProtections();
    bool BuildPEImage(const std::string& path);
    bool CreateImportTable(
        std::vector<ImportPatch> imports,
        BYTE* peData,
        DWORD& rawOffset,
        DWORD& highestVA,
        PIMAGE_SECTION_HEADER secHdrPtr,
        DWORD numSections,
        PIMAGE_NT_HEADERS32 nt
    );


private:
    DWORD highest_section_end_va = 0;
    BYTE* moduleData = nullptr;
    DWORD moduleSize = 0;
    BYTE* base = nullptr;
    DWORD numSections = 0;
    std::string dumpPath;
    DWORD ImportTablePTR;
    DWORD AlignTo(DWORD value, DWORD alignment);
};
