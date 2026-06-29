#include "packer.h"
#include "stub_bytes.h"

#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <cstdlib>

namespace packer {

using Bytes = std::vector<uint8_t>;

static Bytes read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open: " + path);
    auto sz = f.tellg();
    f.seekg(0);
    Bytes buf(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

static void write_file(const std::string& path, const Bytes& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static constexpr uint32_t ALIGN_UP(uint32_t v, uint32_t a) {
    return (v + a - 1) & ~(a - 1);
}

#pragma pack(push, 1)
struct BUNDLE_DLL_SLOT { uint32_t offset; uint32_t size; };
struct BUNDLE_HEADER {
    uint32_t        magic;
    uint32_t        oep_rva;
    uint32_t        dll_count;
    uint32_t        xor_key;
    BUNDLE_DLL_SLOT slots[16];
};
#pragma pack(pop)

static_assert(sizeof(BUNDLE_HEADER) == 0x90, "BundleHeader size mismatch - sync with stub.cpp");

static constexpr uint32_t BUNDLE_MAGIC    = 0x4C444E42;
static constexpr uint32_t HEADER_RESERVED = 0xA0; // sizeof(BUNDLE_HEADER) is 0x90, padded to 0xA0
static constexpr uint32_t MAX_DLLS        = 16;
static constexpr char     BNDL_NAME[8]    = { '.', 'b', 'n', 'd', 'l', 0, 0, 0 };

static uint32_t compute_pe_checksum(Bytes& pe) {
    PIMAGE_DOS_HEADER   dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe.data());
    PIMAGE_NT_HEADERS64 nt  = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe.data() + dos->e_lfanew);
    nt->OptionalHeader.CheckSum = 0;

    uint64_t sum = 0;
    const uint16_t* words = reinterpret_cast<const uint16_t*>(pe.data());
    size_t n = pe.size() / 2;
    for (size_t i = 0; i < n; i++) {
        sum += words[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (pe.size() & 1) {
        sum += pe.back();
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint32_t>((sum & 0xFFFF) + pe.size());
}

PackResult pack(const std::string& target_exe,
                const std::vector<std::string>& dll_paths,
                const std::vector<int>& manual_flags,
                const std::string& output_path,
                const PackOptions& opts)
{
    PackResult result;

    if (dll_paths.size() > MAX_DLLS) {
        result.message = "Too many DLLs (max 16).";
        return result;
    }

    srand((unsigned)GetTickCount());

    try {
        Bytes pe = read_file(target_exe);

        PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw std::runtime_error("Not a valid PE (bad DOS signature)");

        PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            pe.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            throw std::runtime_error("Not a valid PE (bad NT signature)");
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw std::runtime_error("Only 64-bit PEs are supported");

        const uint32_t sec_align  = nt->OptionalHeader.SectionAlignment;
        const uint32_t file_align = nt->OptionalHeader.FileAlignment;

        std::vector<Bytes> dlls;
        dlls.reserve(dll_paths.size());
        for (const auto& p : dll_paths) {
            Bytes d = read_file(p);
            PIMAGE_DOS_HEADER ddos = reinterpret_cast<PIMAGE_DOS_HEADER>(d.data());
            if (ddos->e_magic != IMAGE_DOS_SIGNATURE)
                throw std::runtime_error("DLL is not a valid PE: " + p);
            dlls.push_back(std::move(d));
        }

        uint32_t xor_key = 0;
        if (opts.encrypt_dlls) {
            xor_key = ((uint32_t)rand() << 17) ^ ((uint32_t)rand() << 3) ^ (uint32_t)GetTickCount();
            if (!xor_key) xor_key = 0xDEADBEEFu;
        }

        // Layout: [BUNDLE_HEADER padded to HEADER_RESERVED] [stub bytes] [dll0] [dll1] ...
        Bytes section_data;
        section_data.resize(HEADER_RESERVED, 0);

        section_data.insert(section_data.end(),
            g_stub_bytes, g_stub_bytes + g_stub_size);

        while (section_data.size() % 16) section_data.push_back(0x90);

        std::vector<uint32_t> dll_offsets;
        for (const auto& d : dlls) {
            while (section_data.size() % 16) section_data.push_back(0);
            dll_offsets.push_back(static_cast<uint32_t>(section_data.size()));
            if (xor_key) {
                uint32_t off = 0;
                for (uint8_t b : d) {
                    section_data.push_back(b ^ ((xor_key >> ((off & 3) * 8)) & 0xFF));
                    off++;
                }
            } else {
                section_data.insert(section_data.end(), d.begin(), d.end());
            }
        }

        while (section_data.size() % file_align) section_data.push_back(0);

        uint16_t num_sec = nt->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER first_sec = IMAGE_FIRST_SECTION(nt);

        for (int i = 0; i < num_sec; i++) {
            if (memcmp(first_sec[i].Name, BNDL_NAME, 8) == 0)
                throw std::runtime_error(".bndl section already exists in target PE");
        }

        PIMAGE_SECTION_HEADER last_sec = first_sec + (num_sec - 1);

        const uint32_t new_raw_offset = ALIGN_UP(
            last_sec->PointerToRawData + last_sec->SizeOfRawData, file_align);
        const uint32_t new_virt_addr  = ALIGN_UP(
            last_sec->VirtualAddress  + last_sec->Misc.VirtualSize, sec_align);
        const uint32_t new_raw_size   = static_cast<uint32_t>(section_data.size());
        const uint32_t new_virt_size  = ALIGN_UP(new_raw_size, sec_align);

        BUNDLE_HEADER hdr{};
        hdr.magic     = BUNDLE_MAGIC;
        hdr.oep_rva   = nt->OptionalHeader.AddressOfEntryPoint;
        hdr.dll_count = static_cast<uint32_t>(dlls.size());
        hdr.xor_key   = xor_key;
        for (size_t i = 0; i < dlls.size(); i++) {
            hdr.slots[i].offset = dll_offsets[i];
            hdr.slots[i].size   = static_cast<uint32_t>(dlls[i].size());
            bool manual = (i < manual_flags.size()) && manual_flags[i];
            if (manual) hdr.slots[i].size |= 0x80000000u; // bit 31: stub skips loading at startup
        }
        memcpy(section_data.data(), &hdr, sizeof(BUNDLE_HEADER));

        // Redirect PE entry point to stub_main; original OEP is saved in bundle header
        nt->OptionalHeader.AddressOfEntryPoint = new_virt_addr + HEADER_RESERVED + g_stub_entry;

        // section header table must not overlap the first section's raw data
        const uintptr_t sec_hdr_end = reinterpret_cast<uintptr_t>(last_sec + 2)
                                    - reinterpret_cast<uintptr_t>(pe.data());
        if (sec_hdr_end > first_sec[0].PointerToRawData)
            throw std::runtime_error("No room in PE header for a new section entry");

        IMAGE_SECTION_HEADER new_sec{};
        if (opts.randomize_section_name) {
            static const char* alpha = "abcdefghijklmnopqrstuvwxyz";
            new_sec.Name[0] = '.';
            for (int i = 1; i < 8; i++)
                new_sec.Name[i] = alpha[rand() % 26];
        } else {
            memcpy(new_sec.Name, BNDL_NAME, 8);
        }
        new_sec.Misc.VirtualSize    = new_virt_size;
        new_sec.VirtualAddress      = new_virt_addr;
        new_sec.SizeOfRawData       = new_raw_size;
        new_sec.PointerToRawData    = new_raw_offset;
        new_sec.Characteristics     = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
                                      IMAGE_SCN_CNT_CODE;

        memcpy(last_sec + 1, &new_sec, sizeof(IMAGE_SECTION_HEADER));

        nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe.data() + dos->e_lfanew); // re-resolve after resize
        nt->FileHeader.NumberOfSections++;
        nt->OptionalHeader.SizeOfImage =
            ALIGN_UP(new_virt_addr + new_virt_size, sec_align);

        if (pe.size() < new_raw_offset)
            pe.resize(new_raw_offset, 0);
        pe.insert(pe.end(), section_data.begin(), section_data.end());

        if (opts.update_checksum) {
            nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe.data() + dos->e_lfanew);
            nt->OptionalHeader.CheckSum = compute_pe_checksum(pe);
        }

        std::string out = output_path;
        if (out.empty()) {
            auto p = std::filesystem::path(target_exe);
            out = (p.parent_path() / (p.stem().string() + ".packed" + p.extension().string())).string();
        }
        write_file(out, pe);

        result.success  = true;
        result.out_path = out;
        result.message  = "Packed successfully -> " + out;
    }
    catch (const std::exception& e) {
        result.success = false;
        result.message = std::string("Error: ") + e.what();
    }

    return result;
}

} // namespace packer
