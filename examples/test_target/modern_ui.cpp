#include "modern_ui.hpp"
#include <cmath>
#include <algorithm>

namespace modern_ui {

void draw_gradient_rect(HDC hdc, const RECT& rect, COLORREF color1, COLORREF color2, bool vertical) {
    TRIVERTEX vertices[2];
    vertices[0].x = rect.left;
    vertices[0].y = rect.top;
    vertices[0].Red = GetRValue(color1) << 8;
    vertices[0].Green = GetGValue(color1) << 8;
    vertices[0].Blue = GetBValue(color1) << 8;
    vertices[0].Alpha = 0;

    vertices[1].x = rect.right;
    vertices[1].y = rect.bottom;
    vertices[1].Red = GetRValue(color2) << 8;
    vertices[1].Green = GetGValue(color2) << 8;
    vertices[1].Blue = GetBValue(color2) << 8;
    vertices[1].Alpha = 0;

    GRADIENT_RECT gRect = {0, 1};
    GradientFill(hdc, vertices, 2, &gRect, 1, vertical ? GRADIENT_FILL_RECT_V : GRADIENT_FILL_RECT_H);
}

void draw_rounded_rect(HDC hdc, const RECT& rect, int radius, COLORREF fill, COLORREF border, int border_width) {
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, border_width, border);
    HBRUSH old_brush = (HBRUSH)SelectObject(hdc, brush);
    HPEN old_pen = (HPEN)SelectObject(hdc, pen);

    RoundRect(hdc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);

    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void draw_text_centered(HDC hdc, const std::wstring& text, const RECT& rect, COLORREF color, HFONT font) {
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);

    HFONT old_font = nullptr;
    if (font) {
        old_font = (HFONT)SelectObject(hdc, font);
    }

    DrawTextW(hdc, text.c_str(), -1, const_cast<LPRECT>(&rect), DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    if (old_font) {
        SelectObject(hdc, old_font);
    }
}

void draw_status_icon(HDC hdc, int x, int y, int size, bool success) {
    COLORREF color = success ? colors::success : colors::error;

    // Draw circle background
    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HBRUSH old_brush = (HBRUSH)SelectObject(hdc, brush);
    HPEN old_pen = (HPEN)SelectObject(hdc, pen);

    Ellipse(hdc, x, y, x + size, y + size);

    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    DeleteObject(brush);
    DeleteObject(pen);

    // Draw checkmark or X
    pen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
    SelectObject(hdc, pen);

    int padding = size / 4;
    if (success) {
        // Checkmark
        MoveToEx(hdc, x + padding, y + size / 2, nullptr);
        LineTo(hdc, x + size / 2, y + size - padding);
        LineTo(hdc, x + size - padding, y + padding);
    } else {
        // X mark
        MoveToEx(hdc, x + padding, y + padding, nullptr);
        LineTo(hdc, x + size - padding, y + size - padding);
        MoveToEx(hdc, x + size - padding, y + padding, nullptr);
        LineTo(hdc, x + padding, y + size - padding);
    }

    SelectObject(hdc, old_pen);
    DeleteObject(pen);
}

void draw_lock_icon(HDC hdc, int x, int y, int size, bool locked) {
    COLORREF color = locked ? colors::locked : colors::unlocked;

    HPEN pen = CreatePen(PS_SOLID, 2, color);
    HPEN old_pen = (HPEN)SelectObject(hdc, pen);
    HBRUSH old_brush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));

    int body_height = size / 2;
    int body_y = y + size - body_height;

    // Lock body (rectangle)
    Rectangle(hdc, x + size / 4, body_y, x + size * 3 / 4, y + size);

    if (locked) {
        // Closed shackle (arc)
        Arc(hdc, x + size / 4, y, x + size * 3 / 4, y + size / 2,
            x + size * 3 / 4, y + size / 4, x + size / 4, y + size / 4);
    } else {
        // Open shackle (partial arc)
        Arc(hdc, x + size / 4, y, x + size * 3 / 4, y + size / 2,
            x + size / 2, y, x + size / 4, y + size / 4);
    }

    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    DeleteObject(pen);
}

void draw_progress_bar(HDC hdc, const RECT& rect, float progress, COLORREF color) {
    // Background
    draw_rounded_rect(hdc, rect, 4, colors::background_light, colors::border, 1);

    // Progress fill
    if (progress > 0.0f) {
        RECT fill_rect = rect;
        fill_rect.right = fill_rect.left + static_cast<int>((rect.right - rect.left) * std::min(1.0f, progress));
        fill_rect.left += 2;
        fill_rect.top += 2;
        fill_rect.bottom -= 2;
        fill_rect.right -= 2;

        if (fill_rect.right > fill_rect.left) {
            draw_rounded_rect(hdc, fill_rect, 3, color, color, 0);
        }
    }
}

Animation::Animation(float duration_ms)
    : start_time_(0), duration_(duration_ms), running_(false) {}

void Animation::start() {
    start_time_ = GetTickCount();
    running_ = true;
}

void Animation::reset() {
    running_ = false;
    start_time_ = 0;
}

float Animation::progress() const {
    if (!running_) return 0.0f;

    DWORD elapsed = GetTickCount() - start_time_;
    float p = elapsed / duration_;
    return std::min(1.0f, p);
}

bool Animation::is_running() const {
    return running_ && progress() < 1.0f;
}

float ease_in_out_cubic(float t) {
    return t < 0.5f
        ? 4.0f * t * t * t
        : 1.0f - std::pow(-2.0f * t + 2.0f, 3.0f) / 2.0f;
}

float ease_out_bounce(float t) {
    const float n1 = 7.5625f;
    const float d1 = 2.75f;

    if (t < 1.0f / d1) {
        return n1 * t * t;
    } else if (t < 2.0f / d1) {
        t -= 1.5f / d1;
        return n1 * t * t + 0.75f;
    } else if (t < 2.5f / d1) {
        t -= 2.25f / d1;
        return n1 * t * t + 0.9375f;
    } else {
        t -= 2.625f / d1;
        return n1 * t * t + 0.984375f;
    }
}

float ease_in_out_quad(float t) {
    return t < 0.5f
        ? 2.0f * t * t
        : 1.0f - std::pow(-2.0f * t + 2.0f, 2.0f) / 2.0f;
}

COLORREF blend_colors(COLORREF c1, COLORREF c2, float ratio) {
    ratio = std::max(0.0f, std::min(1.0f, ratio));
    return RGB(
        GetRValue(c1) + static_cast<int>((GetRValue(c2) - GetRValue(c1)) * ratio),
        GetGValue(c1) + static_cast<int>((GetGValue(c2) - GetGValue(c1)) * ratio),
        GetBValue(c1) + static_cast<int>((GetBValue(c2) - GetBValue(c1)) * ratio)
    );
}

COLORREF lighten_color(COLORREF color, float amount) {
    return blend_colors(color, RGB(255, 255, 255), amount);
}

COLORREF darken_color(COLORREF color, float amount) {
    return blend_colors(color, RGB(0, 0, 0), amount);
}

}  // namespace modern_ui
