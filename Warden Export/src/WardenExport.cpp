#include "WardenExport.h"
#include <filesystem>


DWORD WardenExport::AlignTo(DWORD value, DWORD alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}


std::vector<ImportPatch> g_Imports;
DWORD ImportTablePtr;
std::vector<ImportPatch> ImportTable;

bool WardenExport::Load(const void* moduleDataRaw, size_t moduleSizeRaw, const std::string& path)
{
    this->moduleData = (BYTE*)moduleDataRaw;
    this->moduleSize = *(DWORD*)moduleData;
    this->dumpPath = path;

    if (moduleSize >= 0x80000000)
    {
        printf("[!] Invalid module header\n");
        return false;
    }

    std::cout << "\033[38;5;202m[+] SHA-256: " << WardenExport::ComputeSHA256(this->moduleData, this->moduleSize) << "\033[0m" << std::endl;



    if (!ParseHeader()) return false;
    if (!MapSections()) return false;
    if (!ApplyRelocations()) return false;
    if (!ResolveImports()) return false;
    if (!SetProtections()) return false;
    if (!BuildPEImage(path)) return false;

    return true;
}

std::string WardenExport::ComputeSHA256(const BYTE* data, size_t size)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32]; // SHA-256 produces 32 bytes
    DWORD hashSize = sizeof(hash);
    CHAR hexStr[65] = { 0 };

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("[!] CryptAcquireContext failed\n");
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("[!] CryptCreateHash failed\n");
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, data, (DWORD)size, 0)) {
        printf("[!] CryptHashData failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
        printf("[!] CryptGetHashParam failed\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Convert to hex string
    for (DWORD i = 0; i < hashSize; ++i) {
        sprintf_s(hexStr + i * 2, 3, "%02x", hash[i]);
    }

    return std::string(hexStr);
}

bool WardenExport::ParseHeader()
{
    numSections = *(DWORD*)(moduleData + 36);
    if (numSections == 0 || numSections > 0x1000) {
        printf("[!] Invalid section count: %u\n", numSections);
        return false;
    }

    base = (BYTE*)VirtualAlloc(nullptr, moduleSize, MEM_COMMIT, PAGE_READWRITE);
    if (!base) {
        printf("[!] VirtualAlloc failed\n");
        return false;
    }

    memcpy(base, moduleData, 0x28);
    return true;
}

bool WardenExport::MapSections() {
    BYTE* sectionTable = moduleData + 12 * numSections + 40;
    BYTE* writePtr = base + *(DWORD*)(moduleData + 40);
    BYTE* endPtr = base + *(DWORD*)base;

    bool toggle = true;
    while (writePtr < endPtr) {
        WORD blockSize = *(WORD*)sectionTable;
        sectionTable += 2;
        if (toggle) {
            memcpy(writePtr, sectionTable, blockSize);
            sectionTable += blockSize;
        }
        writePtr += blockSize;
        toggle = !toggle;
    }
    return true;
}

bool WardenExport::ApplyRelocations() {
    BYTE* relocPtr = base + *(DWORD*)(base + 8);
    DWORD numRelocs = *(DWORD*)(base + 12);
    DWORD offset = 0;

    for (DWORD i = 0; i < numRelocs; ++i) {
        BYTE first = relocPtr[0];
        if ((first & 0x80) == 0) {
            offset += relocPtr[1] + (first << 8);
            relocPtr += 2;
        }
        else {
            offset = relocPtr[3] + ((relocPtr[2] + ((relocPtr[1] + ((first & 0x7F) << 8)) << 8)) << 8);
            relocPtr += 4;
        }
        *(DWORD*)(base + offset) += (DWORD)base;
    }
    return true;
}

bool WardenExport::ResolveImports()
{
    DWORD importRVA = *(DWORD*)(base + 28);
    DWORD importCount = *(DWORD*)(base + 32);

    if (importCount == 0)
        return true;

    BYTE* importDesc = base + importRVA;

    for (DWORD i = 0; i < importCount; ++i) {
        LPCSTR dllName = (LPCSTR)(base + *(DWORD*)(importDesc + i * 8));
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            printf("[!] Failed to load DLL: %s\n", dllName);
            return false;
        }

        DWORD thunkRVA = *(DWORD*)(importDesc + i * 8 + 4);
        DWORD* thunk = (DWORD*)(base + thunkRVA);

        while (*thunk) {
            DWORD thunkVal = *thunk;

            if ((int)thunkVal >= 0) {
                LPCSTR funcName = (LPCSTR)(base + thunkVal);
                FARPROC proc = GetProcAddress(hMod, funcName);
                if (!proc)
                {
                    printf("[!] Failed to resolve %s!%s\n", dllName, funcName);
                    return false;
                }

                g_Imports.push_back({ dllName , funcName , (DWORD)proc });
                *thunk = (DWORD)(uintptr_t)proc;
            }
            else {
                WORD ordinal = (WORD)(thunkVal & 0x7FFFFFFF);
                FARPROC proc = GetProcAddress(hMod, (LPCSTR)(uintptr_t)ordinal);
                if (!proc) {
                    printf("[!] Failed to resolve ordinal %u from %s\n", ordinal, dllName);
                    return false;
                }
                *thunk = (DWORD)(uintptr_t)proc;
            }
            ++thunk;
        }
    }
    return true;
}

bool WardenExport::SetProtections() {
    for (DWORD i = 0; i < numSections; ++i) {
        BYTE* region = base + *(DWORD*)(moduleData + 12 * i + 40);
        SIZE_T regionSize = *(DWORD*)(moduleData + 12 * i + 44);
        DWORD protection = *(DWORD*)(moduleData + 12 * i + 48);
        DWORD oldProtect;

        VirtualProtect(region, regionSize, protection, &oldProtect);
        if (protection & 0xF0)
            FlushInstructionCache(GetCurrentProcess(), region, regionSize);
    }
    return true;
}

//need to get this to return the right address to the imporrt functions.
bool WardenExport::CreateImportTable(
    std::vector<ImportPatch> imports,
    BYTE* peData,
    DWORD& rawOffset,
    DWORD& highestVA,
    PIMAGE_SECTION_HEADER secHdrPtr,
    DWORD numSections,
    PIMAGE_NT_HEADERS32 nt
) {
    const DWORD sectionAlignment = nt->OptionalHeader.SectionAlignment;
    const DWORD fileAlignment = nt->OptionalHeader.FileAlignment;

    DWORD idataVA = AlignTo(highestVA, sectionAlignment);
    DWORD idataRaw = rawOffset;
    BYTE* idataPtr = peData + idataRaw;
    DWORD idataOffset = 0;

    // Group by DLL
    std::map<std::string, std::vector<std::string>> dllToFuncs;
    for (const auto& pair : imports)
        dllToFuncs[pair.dll].push_back(pair.funcName);

    DWORD importCount = (DWORD)dllToFuncs.size();
    IMAGE_IMPORT_DESCRIPTOR* importDescriptors = (IMAGE_IMPORT_DESCRIPTOR*)(idataPtr + idataOffset);
    idataOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR) * (importCount + 1);

    int i = 0;
    for (const auto& dllEntry : dllToFuncs) {
        const std::string& dllName = dllEntry.first;
        const std::vector<std::string>& funcs = dllEntry.second;

        DWORD nameOffset = idataOffset;
        DWORD nameVA = idataVA + nameOffset;
        strcpy((char*)(idataPtr + nameOffset), dllName.c_str());
        idataOffset += (DWORD)dllName.length() + 1;
        idataOffset = AlignTo(idataOffset, 2);

        DWORD intOffset = idataOffset;
        DWORD* intPtr = (DWORD*)(idataPtr + intOffset);
        idataOffset += sizeof(DWORD) * (funcs.size() + 1);

        DWORD iatOffset = idataOffset;
        DWORD* iatPtr = (DWORD*)(idataPtr + iatOffset);
        idataOffset += sizeof(DWORD) * (funcs.size() + 1);

        for (size_t j = 0; j < funcs.size(); ++j) {
            const std::string& funcName = funcs[j];

            DWORD hintOffset = idataOffset;
            DWORD hintRVA = idataVA + hintOffset;

            WORD* hint = (WORD*)(idataPtr + idataOffset);
            *hint = 0;
            idataOffset += 2;
            strcpy((char*)(idataPtr + idataOffset), funcName.c_str());
            idataOffset += (DWORD)funcName.length() + 1;
            idataOffset = AlignTo(idataOffset, 2);

            intPtr[j] = hintRVA;

            iatPtr[j] = (DWORD)(uintptr_t)GetProcAddress(LoadLibraryA(dllName.c_str()), funcName.c_str());


            DWORD iatVA = idataVA + iatOffset + j * sizeof(DWORD);
            ImportTable.push_back({ dllName, funcName, iatVA });
        }


        intPtr[funcs.size()] = 0;
        iatPtr[funcs.size()] = 0;

        importDescriptors[i].Name = nameVA;
        importDescriptors[i].OriginalFirstThunk = idataVA + intOffset;
        importDescriptors[i].FirstThunk = idataVA + iatOffset;
        ++i;
    }

    memset(&importDescriptors[importCount], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    DWORD idataSize = AlignTo(idataOffset, fileAlignment);
    memset(idataPtr + idataOffset, 0, idataSize - idataOffset);

    PIMAGE_SECTION_HEADER idataSec = &secHdrPtr[numSections];
    memcpy(idataSec->Name, ".idata", 6);
    idataSec->VirtualAddress = idataVA;
    idataSec->Misc.VirtualSize = idataOffset;
    idataSec->PointerToRawData = idataRaw;
    idataSec->SizeOfRawData = idataSize;
    idataSec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = idataVA;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idataOffset;

    DWORD imageBase = nt->OptionalHeader.ImageBase;

    ImportTablePtr = imageBase + idataSec->VirtualAddress;
    rawOffset += idataSize;
    highestVA = AlignTo(idataVA + idataOffset, sectionAlignment);


    printf("\033[38;5;211m[*] Import table created with %u DLL(s)\033[0m\n", importCount);
    return true;
}

void FindRawIATReferences(
    BYTE* peBase,
    PIMAGE_NT_HEADERS32 nt,
    const std::vector<ImportPatch>& imports)
{
    DWORD imageBase = nt->OptionalHeader.ImageBase;
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);

    // Build address → ImportPatch map from resolved imports
    std::map<DWORD, const ImportPatch*> addrToImport;
    for (const auto& imp : imports)
        addrToImport[imp.Address] = &imp;

    std::cout << "\033[38;5;153m[*] Import Patched\033[0m" << std::endl;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& sec = sections[i];

        if (memcmp(sec.Name, ".rdata", 6) != 0)
            continue;

        BYTE* sectionData = peBase + sec.PointerToRawData;
        DWORD sectionSize = sec.SizeOfRawData;
        DWORD sectionVA = imageBase + sec.VirtualAddress;

        for (DWORD offset = 0; offset + 4 <= sectionSize; offset += 4) {
            DWORD* valPtr = (DWORD*)(sectionData + offset);
            DWORD val = *valPtr;

            auto it = addrToImport.find(val);
            if (it != addrToImport.end()) {
                DWORD entryVA = sectionVA + offset;

                for (const auto& fixed : ImportTable) {
                    if (fixed.dll == it->second->dll &&
                        fixed.funcName == it->second->funcName)
                    {
                        DWORD newAddr = (ImportTablePtr & 0xFFFF0000) + (fixed.Address & 0x0000FFFF);
                        DWORD fileOffset = sec.PointerToRawData + offset;

                        if (val != newAddr) {
                            *(DWORD*)(peBase + fileOffset) = newAddr;

                            std::cout << "\033[38;5;153m  ->(" << fixed.dll << "!" << fixed.funcName << "): 0x"
                                << val << " → 0x" << newAddr << "\033[0m" << std::dec << std::endl;
                        }

                        break;
                    }
                }
            }
        }
    }
}

bool WardenExport::BuildPEImage(const std::string& path)
{
    const DWORD sectionAlignment = 0x1000;
    const DWORD fileAlignment = 0x200;
    DWORD headerSize = AlignTo(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32) + (numSections + 1) * sizeof(IMAGE_SECTION_HEADER), fileAlignment);
    DWORD peSize = headerSize;

    for (DWORD i = 0; i < numSections; ++i)
        peSize += AlignTo(*(DWORD*)(moduleData + 12 * i + 44), fileAlignment);

    BYTE* peData = new BYTE[peSize + 0x1000]();
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(peData + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.NumberOfSections = numSections + 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;

    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt->OptionalHeader.ImageBase = (DWORD)base;
    nt->OptionalHeader.SectionAlignment = sectionAlignment;
    nt->OptionalHeader.FileAlignment = fileAlignment;
    nt->OptionalHeader.SizeOfHeaders = headerSize;
    nt->OptionalHeader.AddressOfEntryPoint = *(DWORD*)(base + 4);
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    BYTE* secHdrPtr = (BYTE*)(nt + 1);
    DWORD rawOffset = headerSize;
    DWORD highest_va = 0;

    // Write original sections
    for (DWORD i = 0; i < numSections; ++i)
    {
        PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(secHdrPtr + i * sizeof(IMAGE_SECTION_HEADER));
        DWORD va = *(DWORD*)(moduleData + 12 * i + 40);
        DWORD vsize = *(DWORD*)(moduleData + 12 * i + 44);
        DWORD prot = *(DWORD*)(moduleData + 12 * i + 48);
        DWORD rsize = AlignTo(vsize, fileAlignment);

        if (prot == 0x20 || (prot & PAGE_EXECUTE))
            memcpy(sec->Name, ".text", 5);
        else if (prot & PAGE_READWRITE)
            memcpy(sec->Name, ".data", 5);
        else
            memcpy(sec->Name, ".rdata", 6);

        sec->VirtualAddress = va;
        sec->Misc.VirtualSize = vsize;
        sec->PointerToRawData = rawOffset;
        sec->SizeOfRawData = rsize;

        sec->Characteristics =
            (prot == 0x20 || (prot & PAGE_EXECUTE)) ? (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) :
            (prot & PAGE_READWRITE) ? (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) :
            (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);

        DWORD section_end = AlignTo(va + vsize, sectionAlignment);
        if (section_end > highest_va)
            highest_va = section_end;

        rawOffset += rsize;
    }



    for (DWORD i = 0; i <= numSections; ++i) {
        PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(secHdrPtr + i * sizeof(IMAGE_SECTION_HEADER));

        if (strcmp((char*)sec->Name, ".idata") == 0)
            continue;

        memcpy(peData + sec->PointerToRawData, base + sec->VirtualAddress, sec->Misc.VirtualSize);
        memset(peData + sec->PointerToRawData + sec->Misc.VirtualSize, 0, sec->SizeOfRawData - sec->Misc.VirtualSize);
    }

    DWORD importCount = *(DWORD*)(base + 32);

    if (importCount > 0)
    {
        CreateImportTable(
            g_Imports,
            peData,
            rawOffset,
            highest_va,
            (PIMAGE_SECTION_HEADER)secHdrPtr,
            numSections,
            nt);

        nt->OptionalHeader.SizeOfImage = AlignTo(highest_va, sectionAlignment);
        FindRawIATReferences(peData, nt, g_Imports);
    }


    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        perror("[!] fopen failed");
        delete[] peData;
        return false;
    }

    fwrite(peData, 1, rawOffset, f);
    fclose(f);
    delete[] peData;

    printf("\033[38;5;165m[*] Wrote PE: %s\033[0m\n", path.c_str());
    return true;
}

typedef bool(__thiscall* LoadWardenModule)(int this_ptr, const void* module_data, int module_size);
LoadWardenModule Original_LoadWardenModule = (LoadWardenModule)0x872350;

static int g_counter = 0;
std::string GetModulePath()
{
    char path[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    // Remove the filename (keep directory)
    std::string dir = path;
    size_t pos = dir.find_last_of("\\/");
    if (pos != std::string::npos)
        dir = dir.substr(0, pos);
    return dir;
}

bool __fastcall LoadWardenModulePudo(int this_ptr, void*, void* module_data, int module_size)
{
    try
    {
        std::string basePath = GetModulePath();
        std::string folder = basePath + "\\Warden Modules";

        std::error_code ec;
        if (!std::filesystem::exists(folder, ec))
        {
            if (!std::filesystem::create_directories(folder, ec))
            {
                std::printf("[!] Failed to create folder: %s (err: %s)\n", folder.c_str(), ec.message().c_str());
                return false;
            }
        }
        else if (ec)
        {
            std::printf("[!] Filesystem error checking folder %s (err: %s)\n", folder.c_str(), ec.message().c_str());
            return false;
        }

        std::string shaHex = WardenExport::ComputeSHA256((BYTE*)module_data, module_size);


        if (shaHex.empty())
        {
            std::printf("[!] ComputeSHA256 returned an empty string.\n");
            return false;
        }
        std::string path = folder + "\\" + shaHex + ".dll";

        WardenExport warden;
        if (!warden.Load(module_data, module_size, path.c_str()))
        {
            std::printf("[!] Module load and PE build failed for %s.\n", path.c_str());
            return false;
        }
        ++g_counter;
        return Original_LoadWardenModule(this_ptr, module_data, module_size);
    }
    catch (const std::exception& ex)
    {
        std::printf("[!] Exception in LoadWardenModulePudo: %s\n", ex.what());
        return false;
    }
    catch (...)
    {
        std::printf("[!] Unknown exception in LoadWardenModulePudo.\n");
        return false;
    }
}

bool WardenExport::Hook()
{
    auto openFrameHook = MemoryOperator::CreateDetour("LoadWardenModule", (uintptr_t)&Original_LoadWardenModule, (uintptr_t)LoadWardenModulePudo, false);

    return openFrameHook && openFrameHook->Apply();
    
}
