#include "exloader/runtime/hooks/modules/mathmon_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <minhook.h>

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

MathMonHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using BinaryFn = double(__cdecl*)(double, double);
using UnaryFn = double(__cdecl*)(double);
using BinaryFloatFn = float(__cdecl*)(float, float);
using UnaryFloatFn = float(__cdecl*)(float);

BinaryFn g_orig_pow = nullptr;
UnaryFn g_orig_sqrt = nullptr;
UnaryFn g_orig_sin = nullptr;
UnaryFn g_orig_cos = nullptr;
UnaryFn g_orig_tan = nullptr;
UnaryFn g_orig_log = nullptr;
UnaryFn g_orig_exp = nullptr;
UnaryFn g_orig_atan = nullptr;
UnaryFn g_orig_floor = nullptr;
UnaryFn g_orig_ceil = nullptr;
UnaryFn g_orig_fabs = nullptr;
BinaryFn g_orig_atan2 = nullptr;

BinaryFloatFn g_orig_powf = nullptr;
UnaryFloatFn g_orig_sqrtf = nullptr;
UnaryFloatFn g_orig_sinf = nullptr;
UnaryFloatFn g_orig_cosf = nullptr;
UnaryFloatFn g_orig_tanf = nullptr;
UnaryFloatFn g_orig_logf = nullptr;
UnaryFloatFn g_orig_expf = nullptr;
UnaryFloatFn g_orig_atanf = nullptr;
UnaryFloatFn g_orig_floorf = nullptr;
UnaryFloatFn g_orig_ceilf = nullptr;
UnaryFloatFn g_orig_fabsf = nullptr;
BinaryFloatFn g_orig_atan2f = nullptr;

void log_math_event(const char* api, double a, double b, double result, bool unary) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", "math.call"},
        {"api", api},
        {"result", result}
    };
    json[unary ? "value" : "a"] = a;
    if (!unary) {
        json["b"] = b;
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

template <typename Fn>
bool hook_api(LPCWSTR module_name, LPCSTR proc_name, Fn detour, Fn* original) {
    HMODULE module = GetModuleHandleW(module_name);
    if (module == nullptr) {
        module = LoadLibraryW(module_name);
    }
    if (module == nullptr) {
        return false;
    }
    FARPROC proc = GetProcAddress(module, proc_name);
    if (proc == nullptr) {
        return false;
    }
    void* target = reinterpret_cast<void*>(proc);
    if (MH_CreateHook(target, reinterpret_cast<void*>(detour), reinterpret_cast<void**>(original)) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        return false;
    }
    g_hook_targets.push_back(target);
    return true;
}

double __cdecl binary_hook(double a, double b, BinaryFn original, const char* name) {
    double result = original(a, b);
    log_math_event(name, a, b, result, false);
    return result;
}

float __cdecl binary_hookf(float a, float b, BinaryFloatFn original, const char* name) {
    float result = original(a, b);
    log_math_event(name, a, b, result, false);
    return result;
}

double __cdecl unary_hook(double value, UnaryFn original, const char* name) {
    double result = original(value);
    log_math_event(name, value, 0.0, result, true);
    return result;
}

float __cdecl unary_hookf(float value, UnaryFloatFn original, const char* name) {
    float result = original(value);
    log_math_event(name, value, 0.0, result, true);
    return result;
}

double __cdecl pow_hook(double a, double b) { return binary_hook(a, b, g_orig_pow, "pow"); }
double __cdecl sqrt_hook(double value) { return unary_hook(value, g_orig_sqrt, "sqrt"); }
double __cdecl sin_hook(double value) { return unary_hook(value, g_orig_sin, "sin"); }
double __cdecl cos_hook(double value) { return unary_hook(value, g_orig_cos, "cos"); }
double __cdecl tan_hook(double value) { return unary_hook(value, g_orig_tan, "tan"); }
double __cdecl log_hook(double value) { return unary_hook(value, g_orig_log, "log"); }
double __cdecl exp_hook(double value) { return unary_hook(value, g_orig_exp, "exp"); }
double __cdecl atan_hook(double value) { return unary_hook(value, g_orig_atan, "atan"); }
double __cdecl floor_hook(double value) { return unary_hook(value, g_orig_floor, "floor"); }
double __cdecl ceil_hook(double value) { return unary_hook(value, g_orig_ceil, "ceil"); }
double __cdecl fabs_hook(double value) { return unary_hook(value, g_orig_fabs, "fabs"); }
double __cdecl atan2_hook(double a, double b) { return binary_hook(a, b, g_orig_atan2, "atan2"); }

float __cdecl powf_hook(float a, float b) { return binary_hookf(a, b, g_orig_powf, "powf"); }
float __cdecl sqrtf_hook(float value) { return unary_hookf(value, g_orig_sqrtf, "sqrtf"); }
float __cdecl sinf_hook(float value) { return unary_hookf(value, g_orig_sinf, "sinf"); }
float __cdecl cosf_hook(float value) { return unary_hookf(value, g_orig_cosf, "cosf"); }
float __cdecl tanf_hook(float value) { return unary_hookf(value, g_orig_tanf, "tanf"); }
float __cdecl logf_hook(float value) { return unary_hookf(value, g_orig_logf, "logf"); }
float __cdecl expf_hook(float value) { return unary_hookf(value, g_orig_expf, "expf"); }
float __cdecl atanf_hook(float value) { return unary_hookf(value, g_orig_atanf, "atanf"); }
float __cdecl floorf_hook(float value) { return unary_hookf(value, g_orig_floorf, "floorf"); }
float __cdecl ceilf_hook(float value) { return unary_hookf(value, g_orig_ceilf, "ceilf"); }
float __cdecl fabsf_hook(float value) { return unary_hookf(value, g_orig_fabsf, "fabsf"); }
float __cdecl atan2f_hook(float a, float b) { return binary_hookf(a, b, g_orig_atan2f, "atan2f"); }

}  // namespace

bool MathMonHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void MathMonHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool MathMonHook::install_hooks() {
    LPCWSTR runtime = L"msvcrt.dll";
    bool required_ok = true;
    auto require = [&](bool success) { required_ok &= success; };
    auto optional = [&](bool success) { (void)success; };

    require(hook_api(runtime, "pow", &pow_hook, &g_orig_pow));
    require(hook_api(runtime, "sqrt", &sqrt_hook, &g_orig_sqrt));
    require(hook_api(runtime, "sin", &sin_hook, &g_orig_sin));
    require(hook_api(runtime, "cos", &cos_hook, &g_orig_cos));
    require(hook_api(runtime, "tan", &tan_hook, &g_orig_tan));
    require(hook_api(runtime, "log", &log_hook, &g_orig_log));
    require(hook_api(runtime, "exp", &exp_hook, &g_orig_exp));
    require(hook_api(runtime, "atan", &atan_hook, &g_orig_atan));
    require(hook_api(runtime, "atan2", &atan2_hook, &g_orig_atan2));
    require(hook_api(runtime, "floor", &floor_hook, &g_orig_floor));
    require(hook_api(runtime, "ceil", &ceil_hook, &g_orig_ceil));
    require(hook_api(runtime, "fabs", &fabs_hook, &g_orig_fabs));

    optional(hook_api(runtime, "powf", &powf_hook, &g_orig_powf));
    optional(hook_api(runtime, "sqrtf", &sqrtf_hook, &g_orig_sqrtf));
    optional(hook_api(runtime, "sinf", &sinf_hook, &g_orig_sinf));
    optional(hook_api(runtime, "cosf", &cosf_hook, &g_orig_cosf));
    optional(hook_api(runtime, "tanf", &tanf_hook, &g_orig_tanf));
    optional(hook_api(runtime, "logf", &logf_hook, &g_orig_logf));
    optional(hook_api(runtime, "expf", &expf_hook, &g_orig_expf));
    optional(hook_api(runtime, "atanf", &atanf_hook, &g_orig_atanf));
    optional(hook_api(runtime, "atan2f", &atan2f_hook, &g_orig_atan2f));
    optional(hook_api(runtime, "floorf", &floorf_hook, &g_orig_floorf));
    optional(hook_api(runtime, "ceilf", &ceilf_hook, &g_orig_ceilf));
    optional(hook_api(runtime, "fabsf", &fabsf_hook, &g_orig_fabsf));

    hooks_installed_ = required_ok;
    if (!hooks_installed_) {
        uninstall_hooks();
    }
    return hooks_installed_;
}

void MathMonHook::uninstall_hooks() {
    if (!hooks_installed_) {
        return;
    }
    for (void* target : g_hook_targets) {
        MH_DisableHook(target);
        MH_RemoveHook(target);
    }
    g_hook_targets.clear();
    hooks_installed_ = false;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool MathMonHook::initialize(const PluginContext&) { return false; }
void MathMonHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
