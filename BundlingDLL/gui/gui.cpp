#include "gui.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "../packer/packer.h"

#include <windows.h>
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>

static std::string              g_exe_path;
static std::string              g_out_path;
static std::vector<std::string> g_dlls;
static std::vector<int>         g_dll_manual;
static std::string              g_log;
static bool                     g_success = false;
static packer::PackOptions      g_opts;

static std::string open_dialog(const char* filter, const char* title) {
    char fn[MAX_PATH]{};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = fn;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_DONTADDTORECENT;
    if (GetOpenFileNameA(&ofn)) return fn;
    return {};
}

static std::string save_dialog(const char* filter, const char* title) {
    char fn[MAX_PATH]{};
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = fn;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_DONTADDTORECENT;
    if (GetSaveFileNameA(&ofn)) return fn;
    return {};
}

void gui::render() {
    const ImVec2 display = ImGui::GetIO().DisplaySize;
    ImGui::SetNextWindowPos({ 0, 0 });
    ImGui::SetNextWindowSize(display);
    ImGui::Begin("##main", nullptr,
        ImGuiWindowFlags_NoTitleBar  | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove      | ImGuiWindowFlags_NoScrollbar|
        ImGuiWindowFlags_NoBringToFrontOnFocus);

    const float half = (display.x - 32) * 0.5f;

    ImGui::BeginChild("##left", { half, display.y - 80 }, false);

    ImGui::TextDisabled("TARGET");
    ImGui::Spacing();

    auto set_exe = [&](const std::string& path) {
        g_exe_path = path;
        if (!path.empty()) {
            auto p = std::filesystem::path(path);
            g_out_path = (p.parent_path() / (p.stem().string() + "_packed" + p.extension().string())).string();
        }
    };

    ImGui::SetNextItemWidth(-1);
    char exe_buf[MAX_PATH];
    strncpy_s(exe_buf, g_exe_path.c_str(), MAX_PATH - 1);
    if (ImGui::InputText("##exe", exe_buf, MAX_PATH))
        set_exe(exe_buf);
    if (ImGui::Button("Browse##exe", { -1, 0 })) {
        auto p = open_dialog("Executables\0*.exe\0All Files\0*.*\0", "Select target EXE");
        if (!p.empty()) set_exe(p);
    }

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::TextDisabled("OUTPUT");
    ImGui::Spacing();

    ImGui::SetNextItemWidth(-1);
    char out_buf[MAX_PATH];
    strncpy_s(out_buf, g_out_path.c_str(), MAX_PATH - 1);
    if (ImGui::InputText("##out", out_buf, MAX_PATH))
        g_out_path = out_buf;
    if (ImGui::Button("Browse##out", { -1, 0 }))
        g_out_path = save_dialog("Executables\0*.exe\0All Files\0*.*\0", "Save packed EXE as");

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::TextDisabled("OPTIONS");
    ImGui::Spacing();
    ImGui::Checkbox("Randomize section name", &g_opts.randomize_section_name);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Gives the .bndl section a random name instead.\nThe stub finds it by magic so the name doesn't matter at runtime.");

    ImGui::Checkbox("Encrypt embedded DLLs",  &g_opts.encrypt_dlls);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("XORs each DLL's bytes with a random 32-bit key before embedding.\nThe key is stored in the bundle header and the stub decrypts at runtime.");

    ImGui::Checkbox("Update PE checksum",      &g_opts.update_checksum);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Recomputes the PE CheckSum field after packing.\nMost software ignores it but some AV and DRM tools verify it.");

    if (!g_log.empty()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextDisabled("LOG");
        ImGui::Spacing();
        ImGui::PushTextWrapPos(half - 12);
        if (g_success)
            ImGui::TextColored({ 0.5f, 0.9f, 0.5f, 1.0f }, "%s", g_log.c_str());
        else
            ImGui::TextColored({ 0.9f, 0.4f, 0.4f, 1.0f }, "%s", g_log.c_str());
        ImGui::PopTextWrapPos();
    }

    ImGui::EndChild();

    ImGui::SameLine(0, 12);

    ImGui::BeginChild("##right", { 0, display.y - 80 }, false);

    ImGui::TextDisabled("DLLS  (%zu / 16)", g_dlls.size());
    ImGui::Spacing();

    ImGui::BeginChild("##dlist", { -1, display.y - 160 }, true);
    if (g_dlls.empty())
        ImGui::TextDisabled("No DLLs added.");
    for (int i = 0; i < (int)g_dlls.size(); i++) {
        ImGui::PushID(i);
        auto name = std::filesystem::path(g_dlls[i]).filename().string();

        ImGui::Text("%d.  %s", i + 1, name.c_str());
        ImGui::Indent(16);
        const char* modes[] = { "Load at startup", "Nothing" };
        int mode = g_dll_manual[i];
        ImGui::SetNextItemWidth(150);
        if (ImGui::Combo("##mode", &mode, modes, 2))
            g_dll_manual[i] = mode;
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove")) {
            g_dlls.erase(g_dlls.begin() + i);
            g_dll_manual.erase(g_dll_manual.begin() + i);
            ImGui::Unindent(16);
            ImGui::PopID();
            break;
        }
        ImGui::Unindent(16);
        ImGui::Spacing();

        ImGui::PopID();
    }
    ImGui::EndChild();

    ImGui::Spacing();
    if (g_dlls.size() < 16) {
        if (ImGui::Button("Add DLL", { -1, 0 })) {
            char buf[32768]{};
            OPENFILENAMEA ofn{};
            ofn.lStructSize = sizeof(ofn);
            ofn.lpstrFilter = "DLLs\0*.dll\0All Files\0*.*\0";
            ofn.lpstrFile   = buf;
            ofn.nMaxFile    = sizeof(buf);
            ofn.lpstrTitle  = "Select DLLs";
            ofn.Flags       = OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_DONTADDTORECENT;
            if (GetOpenFileNameA(&ofn)) {
                char* dir = buf;
                char* file = buf + strlen(buf) + 1;
                if (*file == '\0') {
                    std::string p(dir);
                    if (std::find(g_dlls.begin(), g_dlls.end(), p) == g_dlls.end()) {
                        g_dlls.push_back(p);
                        g_dll_manual.push_back(0);
                    }
                } else {
                    std::string directory(dir);
                    while (*file && g_dlls.size() < 16) {
                        std::string p = directory + "\\" + file;
                        if (std::find(g_dlls.begin(), g_dlls.end(), p) == g_dlls.end()) {
                            g_dlls.push_back(p);
                            g_dll_manual.push_back(0);
                        }
                        file += strlen(file) + 1;
                    }
                }
            }
        }
    }
    if (!g_dlls.empty()) {
        if (ImGui::Button("Clear", { -1, 0 })) {
            g_dlls.clear();
            g_dll_manual.clear();
        }
    }

    ImGui::EndChild();

    ImGui::Separator();
    ImGui::Spacing();

    const bool can_pack = !g_exe_path.empty() &&
                          std::filesystem::exists(g_exe_path);

    if (!can_pack) ImGui::BeginDisabled();
    if (ImGui::Button("Pack", { 100, 0 })) {
        g_log.clear();
        auto r    = packer::pack(g_exe_path, g_dlls, g_dll_manual, g_out_path, g_opts);
        g_success = r.success;
        g_log     = r.message;
        if (r.success) g_out_path = r.out_path;
    }
    if (!can_pack) ImGui::EndDisabled();

    if (!can_pack) {
        ImGui::SameLine();
        ImGui::TextDisabled("Select a target EXE.");
    }

    ImGui::End();
}
