#include <windows.h>
#include <d3d11.h>
#include <dwmapi.h>
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")

#include "gui/imgui/imgui.h"
#include "gui/imgui/imgui_impl_win32.h"
#include "gui/imgui/imgui_impl_dx11.h"
#include "gui/gui.h"

static ID3D11Device*            g_device          = nullptr;
static ID3D11DeviceContext*     g_ctx             = nullptr;
static IDXGISwapChain*          g_swap            = nullptr;
static ID3D11RenderTargetView*  g_rtv             = nullptr;
static HWND                     g_hwnd            = nullptr;

static void create_rtv() {
    ID3D11Texture2D* bb = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&bb));
    g_device->CreateRenderTargetView(bb, nullptr, &g_rtv);
    bb->Release();
}

static void cleanup_rtv() {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

static bool create_device(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount          = 2;
    sd.BufferDesc.Width     = 0;
    sd.BufferDesc.Height    = 0;
    sd.BufferDesc.Format    = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage          = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow         = hwnd;
    sd.SampleDesc.Count     = 1;
    sd.Windowed             = TRUE;
    sd.SwapEffect           = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL lvl;
    UINT flags = 0;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
        nullptr, 0, D3D11_SDK_VERSION,
        &sd, &g_swap, &g_device, &lvl, &g_ctx);
    if (FAILED(hr)) return false;

    create_rtv();
    return true;
}

static void cleanup_device() {
    cleanup_rtv();
    if (g_swap)   { g_swap->Release();   g_swap   = nullptr; }
    if (g_ctx)    { g_ctx->Release();    g_ctx    = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return TRUE;

    switch (msg) {
    case WM_SIZE:
        if (g_device && wp != SIZE_MINIMIZED) {
            cleanup_rtv();
            g_swap->ResizeBuffers(0, (UINT)LOWORD(lp), (UINT)HIWORD(lp),
                DXGI_FORMAT_UNKNOWN, 0);
            create_rtv();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = wnd_proc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"BundlingDLL";
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(
        0, L"BundlingDLL", L"DLL Bundling - @govv1337", // whoever changes this is a faggot
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 860, 480,
        nullptr, nullptr, hInst, nullptr);

    RECT rc = {0, 0, 860, 480};
    AdjustWindowRect(&rc, GetWindowLong(g_hwnd, GWL_STYLE), FALSE);
    SetWindowPos(g_hwnd, nullptr, CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top, SWP_NOMOVE);

    if (!create_device(g_hwnd)) {
        cleanup_device();
        UnregisterClassW(wc.lpszClassName, hInst);
        return 1;
    }

    BOOL dark = TRUE;
    DwmSetWindowAttribute(g_hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_device, g_ctx);

    const ImVec4 clear_col = { 0.45f, 0.55f, 0.60f, 1.0f };

    MSG msg{};
    while (msg.message != WM_QUIT) {
        if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        gui::render();

        ImGui::Render();
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, &clear_col.x);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}
