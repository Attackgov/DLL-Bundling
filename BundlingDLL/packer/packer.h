#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace packer {

    struct PackOptions {
        bool randomize_section_name = false;
        bool encrypt_dlls           = false;
        bool update_checksum        = false;
    };

    struct PackResult {
        bool        success  = false;
        std::string message;
        std::string out_path;
    };

    PackResult pack(const std::string& target_exe,
                    const std::vector<std::string>& dll_paths,
                    const std::vector<int>& manual_flags = {},
                    const std::string& output_path = "",
                    const PackOptions& opts = {});

}
