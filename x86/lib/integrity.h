#pragma once
#include <iostream>
#include <Windows.h>
#include <nmmintrin.h>

typedef struct _integrity_check
{
    struct section {
        std::uint8_t* name = {};
        void* address = {};
        std::uint32_t checksum = {};

        bool operator==(section& other)
        {
            return checksum == other.checksum;
        }
    }; section _cached;

    _integrity_check()
    {
        _cached = get_text_section(reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr)));
    }

    std::uint32_t crc32(void* data, std::size_t size)
    {
        std::uint32_t result = {};

        for (std::size_t index = {}; index < size; ++index)
            result = _mm_crc32_u32(result, reinterpret_cast<std::uint8_t*>(data)[index]);

        return result;
    }

    section get_text_section(std::uintptr_t module)
    {
        section text_section = {};

        PIMAGE_DOS_HEADER dosheader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(module + dosheader->e_lfanew);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);

        for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
        {
            std::string name(reinterpret_cast<char const*>(section->Name));
            if (name != ".text")
                continue;

            void* address = reinterpret_cast<void*>(module + section->VirtualAddress);
            text_section = { section->Name, address, crc32(address, section->Misc.VirtualSize) };
        }
        return text_section;
    }
    /// <summary>
    /// Checks .text integrity.
    /// </summary>
    /// <returns>Returns true if it has been changed.</returns>
    bool check_integrity()
    {
        section section2 = get_text_section(reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr)));
        return (!(_cached == section2));
    }
};