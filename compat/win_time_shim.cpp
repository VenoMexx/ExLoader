#if defined(_WIN32)

// Only compile this shim for older MinGW versions that don't have nanosleep32/clock_gettime32
// Modern MinGW (GCC 8+) already has these functions in libwinpthread
#if defined(__MINGW32__) && defined(__GNUC__) && (__GNUC__ < 8)

#include <winsock2.h>
#include <windows.h>
#include <time.h>

namespace {

DWORD timespec32_to_millis(const _timespec32* req) {
    if (req == nullptr) {
        return 0;
    }
    const long long total_ms =
        static_cast<long long>(req->tv_sec) * 1000LL + static_cast<long long>(req->tv_nsec) / 1000000LL;
    if (total_ms <= 0) {
        return 0;
    }
    if (total_ms > MAXDWORD) {
        return MAXDWORD;
    }
    return static_cast<DWORD>(total_ms);
}

void clear_remainder32(_timespec32* rem) {
    if (rem != nullptr) {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
}

}  // namespace

extern "C" int nanosleep32(const struct _timespec32* req32, struct _timespec32* rem32) {
    if (req32 == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    Sleep(timespec32_to_millis(req32));
    clear_remainder32(rem32);
    return 0;
}

extern "C" int clock_gettime32(int clock_id, struct _timespec32* tp) {
    if (tp == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }
    // Only CLOCK_REALTIME (0) is supported.
    if (clock_id != 0) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return -1;
    }

    FILETIME ft{};
    ::GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    constexpr unsigned long long kUnixEpochDiff = 11644473600ULL;  // seconds between 1601 and 1970
    const unsigned long long total_100ns = uli.QuadPart;
    const unsigned long long total_seconds = total_100ns / 10000000ULL;
    const unsigned long long rem_100ns = total_100ns % 10000000ULL;

    tp->tv_sec = static_cast<long>(total_seconds - kUnixEpochDiff);
    tp->tv_nsec = static_cast<long>(rem_100ns * 100ULL);
    return 0;
}

#endif  // __MINGW32__ && __GNUC__ < 8
#endif  // _WIN32
