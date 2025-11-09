#pragma once

#include <windows.h>
#include <string>

namespace modern_ui {

// Color palette
namespace colors {
    constexpr COLORREF background_dark = RGB(6, 10, 24);       // Deep navy
    constexpr COLORREF background_medium = RGB(12, 18, 38);    // Night indigo
    constexpr COLORREF background_light = RGB(24, 32, 58);     // Evening blue
    constexpr COLORREF surface = RGB(38, 50, 80);              // Graphite blue
    constexpr COLORREF border = RGB(75, 85, 120);              // Soft steel

    constexpr COLORREF text_primary = RGB(237, 242, 255);      // Off white
    constexpr COLORREF text_secondary = RGB(193, 201, 222);    // Mist gray
    constexpr COLORREF text_muted = RGB(150, 160, 190);        // Muted lavender

    constexpr COLORREF accent_blue = RGB(56, 189, 248);        // Neon sky
    constexpr COLORREF accent_purple = RGB(139, 92, 246);      // Electric violet
    constexpr COLORREF accent_green = RGB(52, 211, 153);       // Mint
    constexpr COLORREF accent_red = RGB(248, 113, 113);        // Coral red
    constexpr COLORREF accent_yellow = RGB(252, 211, 77);      // Glow amber
    constexpr COLORREF accent_orange = RGB(251, 146, 60);      // Modern orange

    constexpr COLORREF success = RGB(16, 185, 129);            // Emerald
    constexpr COLORREF warning = RGB(250, 204, 21);            // Solar yellow
    constexpr COLORREF error = RGB(239, 68, 68);               // Signal red
    constexpr COLORREF info = RGB(59, 130, 246);               // Azure

    constexpr COLORREF locked = RGB(82, 97, 133);              // Muted steel
    constexpr COLORREF unlocked = RGB(16, 185, 129);           // Emerald
}

// Helper functions
void draw_gradient_rect(HDC hdc, const RECT& rect, COLORREF color1, COLORREF color2, bool vertical);
void draw_rounded_rect(HDC hdc, const RECT& rect, int radius, COLORREF fill, COLORREF border, int border_width = 1);
void draw_text_centered(HDC hdc, const std::wstring& text, const RECT& rect, COLORREF color, HFONT font = nullptr);
void draw_status_icon(HDC hdc, int x, int y, int size, bool success);
void draw_lock_icon(HDC hdc, int x, int y, int size, bool locked);
void draw_progress_bar(HDC hdc, const RECT& rect, float progress, COLORREF color);

// Custom control creation
HWND create_modern_button(HWND parent, const wchar_t* text, int x, int y, int w, int h, int id, bool primary = false);
HWND create_modern_edit(HWND parent, const wchar_t* placeholder, int x, int y, int w, int h, bool password = false);

// Animation helpers
class Animation {
public:
    Animation(float duration_ms = 300.0f);
    void start();
    void reset();
    float progress() const;  // 0.0 to 1.0
    bool is_running() const;

private:
    DWORD start_time_;
    float duration_;
    bool running_;
};

// Easing functions
float ease_in_out_cubic(float t);
float ease_out_bounce(float t);
float ease_in_out_quad(float t);

COLORREF blend_colors(COLORREF c1, COLORREF c2, float ratio);
COLORREF lighten_color(COLORREF color, float amount);
COLORREF darken_color(COLORREF color, float amount);

}  // namespace modern_ui
