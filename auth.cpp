#ifndef UNICODE
#define UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <auth.hpp>
#include <strsafe.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#include <shellapi.h>

#include <sstream> 
#include <iomanip> 
#include <xorstr.hpp>
#include <fstream> 
#include <http.h>
#include <stdlib.h>
#include <atlstr.h>
#include <windns.h>

#include <ctime>
#include <filesystem>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "dnsapi.lib")

#include <cstdio>
#include <iostream>
#include <memory>
#include <algorithm>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <cwctype>
#include <intrin.h>
#include <array>
#include <cstring>
#include <vector>
#include <utility>
#include <stdexcept>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <windns.h>
#include <tlhelp32.h>
#include <string>
#include <array>

#include <functional>
#include <vector>
#include <bitset>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )
#include <thread>

#include <cctype>
#include <algorithm>

#if __has_include("Security.hpp")
#include "Security.hpp"
#define KEYAUTH_HAVE_SECURITY 1
#else
#define KEYAUTH_HAVE_SECURITY 0
#endif

#if __has_include("killEmulator.hpp")
#include "killEmulator.hpp"
#define KEYAUTH_HAVE_KILLEMU 1
#else
#define KEYAUTH_HAVE_KILLEMU 0
#endif
#include <lazy_importer.hpp>
#include <QRCode/qrcode.hpp>
#include <QRCode/qr.png.h>

#define SHA256_HASH_SIZE 32

static std::string hexDecode(const std::string& hex);
std::string get_str_between_two_str(const std::string& s, const std::string& start_delim, const std::string& stop_delim);
int VerifyPayload(std::string signature, std::string timestamp, std::string body);
void checkInit();
std::string checksum();
void modify();
void runChecks();
void checkAtoms();
void checkFiles();
void checkRegistry();
void error(std::string message);
std::string generate_random_number();
std::string curl_escape(CURL* curl, const std::string& input);
auto check_section_integrity( const char *section_name, bool fix ) -> bool;
void integrity_check();
std::string extract_host(const std::string& url);
bool hosts_override_present(const std::string& host);
bool module_has_rwx_section(HMODULE mod);
bool core_modules_signed();
static std::wstring get_system_dir();
static std::wstring get_syswow_dir();
void snapshot_prologues();
static void snapshot_checkinit();
static bool checkinit_ok();
static void security_watchdog();
bool prologues_ok();
bool func_region_ok(const void* addr);
bool timing_anomaly_detected();
void start_heartbeat(KeyAuth::api* instance);
void heartbeat_thread(KeyAuth::api* instance);
void snapshot_text_hashes();
bool text_hashes_ok();
bool detour_suspect(const uint8_t* p);
static bool entry_is_jmp_or_call(const void* fn);
static bool entry_is_reg_jump(const void* fn);
bool import_addresses_ok();
void snapshot_text_page_protections();
bool text_page_protections_ok();
void snapshot_data_page_protections();
bool data_page_protections_ok();
static bool get_text_section_info(std::uintptr_t& base, size_t& size);
static uint32_t rolling_crc32(const uint8_t* data, size_t len, size_t window = 64, size_t stride = 16);
static bool get_export_address(HMODULE mod, const char* name, void*& out_addr);
 
inline void secure_zero(std::string& value) noexcept;
inline void securewipe(std::string& value) noexcept;
std::string seed;
void cleanUpSeedData(const std::string& seed);
std::string signature;
std::string signatureTimestamp;
bool initialized;
static constexpr uint8_t k_pubkey_xor1 = 0x5A;
static constexpr uint8_t k_pubkey_xor2 = 0xA5;
static constexpr uint64_t k_pubkey_fnv1a = 0x7553f24ca052d4b1ULL;
static const uint8_t k_pubkey_obf1[64] = {
    0x6f, 0x6f, 0x62, 0x6c, 0x38, 0x6e, 0x38, 0x39, 0x6c, 0x63, 0x39, 0x6d, 0x3b, 0x6e, 0x38, 0x6e,
    0x62, 0x6d, 0x3f, 0x6e, 0x6f, 0x6c, 0x69, 0x3b, 0x6e, 0x39, 0x3e, 0x63, 0x6c, 0x3b, 0x3c, 0x3e,
    0x69, 0x63, 0x6b, 0x6e, 0x6a, 0x3c, 0x63, 0x6b, 0x63, 0x38, 0x3e, 0x69, 0x6b, 0x39, 0x3f, 0x3b,
    0x6d, 0x3e, 0x6b, 0x39, 0x6c, 0x3b, 0x6b, 0x3f, 0x62, 0x6e, 0x69, 0x63, 0x6e, 0x68, 0x68, 0x38
};
static const uint8_t k_pubkey_obf2[64] = {
    0x90, 0x90, 0x9d, 0x93, 0xc7, 0x91, 0xc7, 0xc6, 0x93, 0x9c, 0xc6, 0x92, 0xc4, 0x91, 0xc7, 0x91,
    0x9d, 0x92, 0xc0, 0x91, 0x90, 0x93, 0x96, 0xc4, 0x91, 0xc6, 0xc1, 0x9c, 0x93, 0xc4, 0xc3, 0xc1,
    0x96, 0x9c, 0x94, 0x91, 0x95, 0xc3, 0x9c, 0x94, 0x9c, 0xc7, 0xc1, 0x96, 0x94, 0xc6, 0xc0, 0xc4,
    0x92, 0xc1, 0x94, 0xc6, 0x93, 0xc4, 0x94, 0xc0, 0x9d, 0x91, 0x96, 0x9c, 0x91, 0x97, 0x97, 0xc7
};
static std::atomic<uint64_t> pubkey_hash_seen{ 0 };
static std::atomic<bool> pubkey_protect_ready{ false };
static DWORD pubkey_protect_baseline = 0;
bool KeyAuth::api::debug = false;
std::atomic<bool> LoggedIn(false);
std::atomic<long long> last_integrity_check{ 0 };
std::atomic<int> integrity_fail_streak{ 0 };
std::atomic<long long> last_module_check{ 0 };
std::atomic<long long> last_periodic_check{ 0 };
std::atomic<bool> prologues_ready{ false };
std::atomic<bool> heartbeat_started{ false };
std::array<uint8_t, 16> pro_verify{};
std::array<uint8_t, 16> pro_checkinit{};
std::array<uint8_t, 16> pro_error{};
std::array<uint8_t, 16> pro_integrity{};
std::array<uint8_t, 16> pro_section{};
std::atomic<bool> text_hashes_ready{ false };
struct TextHash { size_t offset; size_t len; uint32_t hash; };
std::vector<TextHash> text_hashes;
std::atomic<bool> text_prot_ready{ false };
std::vector<std::pair<std::uintptr_t, DWORD>> text_protections;
std::atomic<bool> data_prot_ready{ false };
std::vector<std::pair<std::uintptr_t, DWORD>> data_protections;
std::atomic<int> heavy_fail_streak{ 0 };
static const char* kCriticalImports[] = {
    "WinVerifyTrust",
    "WinHttpGetDefaultProxyConfiguration",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "CryptVerifyMessageSignature",
};
static std::atomic<uint32_t> text_crc_baseline{ 0 };
static std::array<uint8_t, 16> checkinit_prologue{};
static std::atomic<bool> checkinit_ready{ false };
static std::atomic<bool> watchdog_started{ false };
static std::atomic<uint32_t> curl_crc_baseline{ 0 };
static std::atomic<uint32_t> sodium_crc_baseline{ 0 };


static inline void secure_zero(std::string& value) noexcept
{
    if (!value.empty()) {
        SecureZeroMemory(value.data(), value.size());
        value.clear();
        value.shrink_to_fit();
    }
}

static inline void securewipe(std::string& value) noexcept
{
    secure_zero(value);
}

static uint64_t fnv1a64_bytes(const uint8_t* data, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 0x100000001b3ULL;
    }
    return h;
}

static std::string decode_pubkey_hex(const uint8_t* obf, size_t len, uint8_t key)
{
    std::string out;
    out.resize(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<char>(obf[i] ^ key);
    }
    return out;
}

static std::string to_lower_ascii(std::string v)
{
    std::transform(v.begin(), v.end(), v.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v;
}

static std::string wide_to_utf8(const wchar_t* w)
{
    if (!w)
        return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

static bool list_contains_any(const std::string& hay, const std::vector<std::string>& needles)
{
    for (const auto& n : needles) {
        if (hay.find(n) != std::string::npos)
            return true;
    }
    return false;
}

static bool suspicious_processes_present()
{
    const std::vector<std::string> bad = {
        "fiddler", "mitmproxy", "charles", "httpdebugger", "proxifier",
        "burpsuite", "wireshark", "tshark", "x64dbg", "x32dbg",
        "ollydbg", "ida", "cheatengine", "processhacker"
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }
    do {
        std::string name = to_lower_ascii(wide_to_utf8(pe.szExeFile));
        if (list_contains_any(name, bad)) {
            CloseHandle(snap);
            return true;
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return false;
}

static bool suspicious_modules_present()
{
    const std::vector<std::string> bad = {
        "fiddlercore", "mitm", "charles", "httpdebugger", "proxifier",
        "detours"
    };
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return false;
    const size_t count = needed / sizeof(HMODULE);
    char name[MAX_PATH]{};
    for (size_t i = 0; i < count; ++i) {
        if (GetModuleFileNameA(mods[i], name, MAX_PATH)) {
            std::string lower = to_lower_ascii(name);
            if (list_contains_any(lower, bad))
                return true;
        }
    }
    return false;
}

static bool suspicious_windows_present()
{
    const std::vector<std::string> bad = {
        "fiddler", "mitmproxy", "charles", "burp", "http debugger",
        "x64dbg", "x32dbg", "ollydbg", "ida", "cheat engine",
        "process hacker"
    };
    struct Ctx { const std::vector<std::string>* bad; bool hit; };
    Ctx ctx{ &bad, false };
    auto cb = [](HWND hwnd, LPARAM lparam) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lparam);
        if (!IsWindowVisible(hwnd))
            return TRUE;
        char title[512]{};
        GetWindowTextA(hwnd, title, sizeof(title));
        if (title[0] == '\0')
            return TRUE;
        std::string t = to_lower_ascii(title);
        if (list_contains_any(t, *c->bad)) {
            c->hit = true;
            return FALSE;
        }
        return TRUE;
    };
    EnumWindows(cb, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hit;
}

static bool proxy_env_set()
{
    const char* p1 = std::getenv("HTTP_PROXY");
    const char* p2 = std::getenv("HTTPS_PROXY");
    const char* p3 = std::getenv("ALL_PROXY");
    return (p1 && *p1) || (p2 && *p2) || (p3 && *p3);
}

static bool url_points_to_loopback(const std::string& url)
{
    const std::string host = extract_host(url);
    if (host.empty())
        return false;
    std::string h = to_lower_ascii(host);
    if (h == "localhost" || h == "127.0.0.1" || h == "::1")
        return true;

    ADDRINFOA hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ADDRINFOA* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return false;
    bool loopback = false;
    for (auto* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* in = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if ((ntohl(in->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u) {
                loopback = true;
                break;
            }
        } else if (p->ai_family == AF_INET6) {
            auto* in6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) {
                loopback = true;
                break;
            }
        }
    }
    freeaddrinfo(res);
    return loopback;
}

static bool pubkey_memory_protect_ok()
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(k_pubkey_obf1, &mbi, sizeof(mbi)))
        return false;
    const DWORD p = mbi.Protect;
    if (p & PAGE_GUARD)
        return false;
    if ((p & PAGE_READWRITE) || (p & PAGE_WRITECOPY) ||
        (p & PAGE_EXECUTE_READWRITE) || (p & PAGE_EXECUTE_WRITECOPY)) {
        return false;
    }
    if (pubkey_protect_ready.load(std::memory_order_relaxed)) {
        if (pubkey_protect_baseline != p)
            return false;
    }
    return true;
}

static std::string get_public_key_hex()
{
    if (!pubkey_memory_protect_ok()) {
        error(XorStr("public key memory protection tampered."));
    }
    std::string a = decode_pubkey_hex(k_pubkey_obf1, sizeof(k_pubkey_obf1), k_pubkey_xor1);
    std::string b = decode_pubkey_hex(k_pubkey_obf2, sizeof(k_pubkey_obf2), k_pubkey_xor2);
    if (a != b) {
        error(XorStr("public key mismatch detected."));
    }
    const uint64_t h = fnv1a64_bytes(reinterpret_cast<const uint8_t*>(a.data()), a.size());
    pubkey_hash_seen.store(h, std::memory_order_relaxed);
    if (h != k_pubkey_fnv1a) {
        error(XorStr("public key integrity failed."));
    }
    return a;
}

static bool module_contains_ascii(const std::string& needle)
{
    if (needle.empty())
        return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return false;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll);
    const uint8_t* end = base + mi.SizeOfImage;
    const uint8_t* p = base;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)))
            break;
        const uint8_t* region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
        const uint8_t* region_end = region + mbi.RegionSize;
        if (region_end > end)
            region_end = end;
        const DWORD protect = mbi.Protect;
        const bool readable = (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) ||
            (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE) ||
            (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_WRITECOPY);
        if (mbi.State == MEM_COMMIT && readable) {
            const char* cbegin = reinterpret_cast<const char*>(region);
            const char* cend = reinterpret_cast<const char*>(region_end);
            auto it = std::search(cbegin, cend, needle.begin(), needle.end());
            if (it != cend)
                return true;
        }
        p = region_end;
    }
    return false;
}

struct ScopeWipe final {
    std::string* value;
    explicit ScopeWipe(std::string& v) noexcept : value(&v) {}
    ~ScopeWipe() noexcept { securewipe(*value); }
};

void KeyAuth::api::init()
{
    // harden dll search order to reduce current-dir hijacks
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
    SetDllDirectoryW(L"");
#if KEYAUTH_HAVE_SECURITY
    LockMemAccess();
#endif
    {
        wchar_t exe_path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
        std::wstring exe_dir = exe_path;
        const auto last_slash = exe_dir.find_last_of(L"\\/");
        if (last_slash != std::wstring::npos) {
            exe_dir = exe_dir.substr(0, last_slash);
            AddDllDirectory(exe_dir.c_str());
        }
    }
    std::thread(runChecks).detach();
    snapshot_prologues();
    snapshot_checkinit();
    (void)get_public_key_hex();
    seed = generate_random_number();
    std::atexit([]() { cleanUpSeedData(seed); });

    if (!watchdog_started.exchange(true)) {
        std::thread(security_watchdog).detach();
    }

    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)modify, 0, 0, 0);

    if (ownerid.length() != 10)
    {
        MessageBoxA(0, XorStr("Application Not Setup Correctly. Please Watch Video Linked in main.cpp").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    std::string hash = checksum();
    CURL* curl = curl_easy_init();
    auto data =
        XorStr("type=init") +
        XorStr("&ver=") + version +
        XorStr("&hash=") + hash +
        XorStr("&name=") + curl_escape(curl, name) +
        XorStr("&ownerid=") + ownerid;
    if (curl) {
        curl_easy_cleanup(curl); // avoid leak from escape helper. -nigel
        curl = nullptr;
    }

    // to ensure people removed secret from main.cpp (some people will forget to)
    if (path.find("https") != std::string::npos) {
        MessageBoxA(0, XorStr("You forgot to remove \"secret\" from main.cpp. Copy details from ").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    if (path != "" || !path.empty()) {

        if (!std::filesystem::exists(path)) {
            MessageBoxA(0, XorStr("File not found. Please make sure the file exists.").c_str(), NULL, MB_ICONERROR);
            LI_FN(exit)(0);
        }
        //get the contents of the file
        std::ifstream file(path);
        std::string token;
        std::string thash;
        std::getline(file, token);

        auto exec = [&](const char* cmd) -> std::string
            {
                uint16_t line = -1;
                std::array<char, 128> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
                if (!pipe) {
                    throw std::runtime_error(XorStr("popen() failed!"));
                }

                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result = buffer.data();
                }
                return result;
            };

        thash = exec(("certutil -hashfile \"" + path + XorStr("\" MD5 | find /i /v \"md5\" | find /i /v \"certutil\"")).c_str());

        data += XorStr("&token=").c_str() + token;
        data += XorStr("&thash=").c_str() + path;
    }
    // curl was only used for escape above

    auto response = req(data, url);

    if (response == XorStr("KeyAuth_Invalid").c_str()) {
        MessageBoxA(0, XorStr("Application not found. Please copy strings directly from dashboard.").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    std::hash<int> hasher;
    int expectedHash = hasher(42);

    // 4 lines down, used for debug
    /*std::cout << "[DEBUG] Preparing to verify payload..." << std::endl;
    std::cout << "[DEBUG] Signature: " << signature << std::endl;
    std::cout << "[DEBUG] Timestamp: " << signatureTimestamp << std::endl;
    std::cout << "[DEBUG] Raw body: " << response << std::endl;*/

    if (signature.empty() || signatureTimestamp.empty()) { // used for debug
        std::cerr << "[ERROR] Signature or timestamp is empty. Cannot verify." << std::endl;
        MessageBoxA(0, "Missing signature headers in response", "KeyAuth", MB_ICONERROR);
        exit(99); // Temporary debug exit code
    }


    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);

        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        load_response_data(json);

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            if (json[(XorStr("success"))])
            {
                if (json[(XorStr("newSession"))]) {
                    Sleep(100);
                }
                sessionid = json[(XorStr("sessionid"))];
                initialized = true;
                load_app_data(json[(XorStr("appinfo"))]);
            }
            else if (json[(XorStr("message"))] == XorStr("invalidver"))
            {
                std::string dl = json[(XorStr("download"))];
                api::app_data.downloadLink = json[XorStr("download")];
                if (dl == "")
                {
                    MessageBoxA(0, XorStr("Version in the loader does match the one on the dashboard, and the download link on dashboard is blank.\n\nTo fix this, either fix the loader so it matches the version on the dashboard. Or if you intended for it to have different versions, update the download link on dashboard so it will auto-update correctly.").c_str(), NULL, MB_ICONERROR);
                }
                else
                {
                    ShellExecuteA(0, XorStr("open").c_str(), dl.c_str(), 0, 0, SW_SHOWNORMAL);
                }
                LI_FN(exit)(0);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Callback function to handle headers
size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t totalSize = size * nitems;

    std::string header(buffer, totalSize);
    if (header.empty())
        return totalSize;
    // trim CRLF
    while (!header.empty() && (header.back() == '\r' || header.back() == '\n')) {
        header.pop_back();
    }
    const auto colon = header.find(':');
    if (colon == std::string::npos)
        return totalSize;
    std::string key = header.substr(0, colon);
    std::string value = header.substr(colon + 1);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.erase(value.begin());
    }
    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

    if (key == "x-signature-ed25519") {
        signature = value;
    }
    if (key == "x-signature-timestamp") {
        signatureTimestamp = value;
    }

    return totalSize;
}


void KeyAuth::api::login(std::string username, std::string password, std::string code)
{
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_pass(password);
    ScopeWipe wipe_code(code);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=login") +
        XorStr("&username=") + username +
        XorStr("&pass=") + password +
        XorStr("&code=") + code +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    //std::cout << "[DEBUG] Login response: " << response << std::endl;
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        //std::cout << "[DEBUG] Login response:" << response << std::endl;

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                std::ofstream file(file_path);
                if (file.is_open()) {
                    file << seed;
                    file.close();
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
		start_heartbeat(this);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::chatget(std::string channel)
{
    checkInit();
    ScopeWipe wipe_channel(channel);

    auto data =
        XorStr("type=chatget") +
        XorStr("&channel=") + channel +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    load_channel_data(json);
}

bool KeyAuth::api::chatsend(std::string message, std::string channel)
{
    checkInit();
    ScopeWipe wipe_message(message);
    ScopeWipe wipe_channel(channel);

    auto data =
        XorStr("type=chatsend") +
        XorStr("&message=") + message +
        XorStr("&channel=") + channel +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    load_response_data(json);
    return json[XorStr("success")];
}

void KeyAuth::api::changeUsername(std::string newusername)
{
    checkInit();
    ScopeWipe wipe_user(newusername);

    auto data =
        XorStr("type=changeUsername") +
        XorStr("&newUsername=") + newusername +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

KeyAuth::api::Tfa& KeyAuth::api::enable2fa(std::string code)
{
    checkInit();

   KeyAuth::api::activate = true;

    auto data =
        XorStr("type=2faenable") +
        XorStr("&code=") + code +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);

    if (json.contains("2fa")) {

        api::response.success = json[XorStr("success")];
        api::tfa.secret = json["2fa"]["secret_code"];
        api::tfa.link = json["2fa"]["QRCode"];
    }
    else {
        load_response_data(json);
    }
    
    return api::tfa;
}

KeyAuth::api::Tfa& KeyAuth::api::disable2fa(std::string code)
{
    checkInit();
    
    KeyAuth::api::activate = false;

    if (code.empty()) {
        return this->tfa.handleInput(*this);
    }


    auto data =
        XorStr("type=2fadisable") +
        XorStr("&code=") + code +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);

    auto json = response_decoder.parse(response);

    load_response_data(json);

    return api::tfa;
}

void KeyAuth::api::Tfa::QrCode() {
    auto qrcode = QrToPng("QRCode.png", 300, 3, KeyAuth::api::Tfa::link, true, qrcodegen::QrCode::Ecc::MEDIUM);
    qrcode.writeToPNG();
}

KeyAuth::api::Tfa& KeyAuth::api::Tfa::handleInput(KeyAuth::api& instance) {

    if (instance.activate) {
        QrCode();

        ShellExecuteA(0, XorStr("open").c_str(), XorStr("QRCode.png").c_str(), 0, 0, SW_SHOWNORMAL);

        system("cls");
        std::cout << XorStr("Press enter when you have scanned the QR code");
        std::cin.get();

        // remove the QR code
        remove("QRCode.png");

        system("cls");

        std::cout << XorStr("Enter the code: ");

        std::string code;
        std::cin >> code;

        instance.enable2fa(code);
    }
    else {

        LI_FN(system)(XorStr("cls").c_str());

        std::cout << XorStr("Enter the code to disable 2FA: ");

		std::string code;
		std::cin >> code;

		instance.disable2fa(code);
	}

}

void KeyAuth::api::web_login()
{
    checkInit();

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "The Flags parameter contains an unsupported value.", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }
    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for Initialize", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create server session.
    HTTP_SERVER_SESSION_ID serverSessionId;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Version for session invalid", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "pServerSessionId parameter is null", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateServerSession", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create URL group.
    HTTP_URL_GROUP_ID groupId;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Url group create parameter error", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateUrlGroup", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create request queue.
    HANDLE requestQueueHandle;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Wrong version", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Byte length exceeded", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "pName already used", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, "queue access denied", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_DLL_INIT_FAILED) {
        MessageBoxA(NULL, "Initialize not called", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateRequestQueue", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info;
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("Invalid parameter").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpSetUrlGroupProperty").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Add URLs to URL group.
    PCWSTR url = L"http://localhost:1337/handshake";
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, XorStr("No permissions to run web server").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, XorStr("You are running this program already").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("ERROR_INVALID_PARAMETER for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_SHARING_VIOLATION) {
        MessageBoxA(NULL, XorStr("Another program is using the webserver. Close Razer Chroma mouse software if you use that. Try to restart computer.").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/handshake?user=mak&token=2f3e9eccc22ee583cf7bad86c751d865
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 4096;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        auto buffer = std::make_unique<BYTE[]>(requestSize);
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer.get();
        RtlZeroMemory(buffer.get(), requestSize);
        ULONG bytesReturned;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        std::wstring ws(pRequest->CookedUrl.pQueryString);
        std::string myVarS = std::string(ws.begin(), ws.end());
        std::string user = get_str_between_two_str(myVarS, "?user=", "&");
        std::string token = get_str_between_two_str(myVarS, "&token=", "");

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // break if preflight request from browser
        if (pRequest->Verb == HttpVerbOPTIONS)
        {
            // Respond to the request.
            HTTP_RESPONSE response;
            RtlZeroMemory(&response, sizeof(response));

            response.StatusCode = 200;
            response.pReason = static_cast<PCSTR>(XorStr("OK").c_str());
            response.ReasonLength = (USHORT)strlen(response.pReason);

            // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
            HTTP_UNKNOWN_HEADER  accessControlHeader;
            const char testCustomHeader[] = "Access-Control-Allow-Origin";
            const char testCustomHeaderVal[] = "*";
            accessControlHeader.pName = testCustomHeader;
            accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
            accessControlHeader.pRawValue = testCustomHeaderVal;
            accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
            response.Headers.pUnknownHeaders = &accessControlHeader;
            response.Headers.UnknownHeaderCount = 1;
            // Add an entity chunk to the response.
            // PSTR pEntityString = "Hello from C++";
            HTTP_DATA_CHUNK dataChunk;
            dataChunk.DataChunkType = HttpDataChunkFromMemory;

            result = HttpSendHttpResponse(
                requestQueueHandle,
                pRequest->RequestId,
                0,
                &response,
                NULL,
                NULL,   // &bytesSent (optional)
                NULL,
                0,
                NULL,
                NULL
            );

            continue;
        }

        // keyauth request
        std::string hwid = utils::get_hwid();
        auto data =
            XorStr("type=login") +
            XorStr("&username=") + user +
            XorStr("&token=") + token +
            XorStr("&hwid=") + hwid +
            XorStr("&sessionid=") + sessionid +
            XorStr("&name=") + name +
            XorStr("&ownerid=") + ownerid;
        auto resp = req(data, api::url);

        std::hash<int> hasher;
        int expectedHash = hasher(42);
        int result = VerifyPayload(signature, signatureTimestamp, resp.data());
        if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
        {
            auto json = response_decoder.parse(resp);
            if (json[(XorStr("ownerid"))] != ownerid) {
                LI_FN(exit)(8);
            }

            std::string message = json[(XorStr("message"))];

            std::hash<int> hasher;
            size_t expectedHash = hasher(68);
            size_t resultCode = hasher(json[(XorStr("code"))]);

            if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
                if (api::response.message != XorStr("Initialized").c_str()) {
                    LI_FN(GlobalAddAtomA)(seed.c_str());

                    std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                    std::ofstream file(file_path);
                    if (file.is_open()) {
                        file << seed;
                        file.close();
                    }

                    std::string regPath = XorStr("Software\\").c_str() + seed;
                    HKEY hKey;
                    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                    if (result == ERROR_SUCCESS) {
                        LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                        LI_FN(RegCloseKey)(hKey);
                    }

                    LI_FN(GlobalAddAtomA)(ownerid.c_str());
		    LoggedIn.store(true);
		    start_heartbeat(this);
                }
                else {
                    LI_FN(exit)(12);
                }

                // Respond to the request.
                HTTP_RESPONSE response;
                RtlZeroMemory(&response, sizeof(response));

                bool success = true;
                if (json[(XorStr("success"))])
                {
                    load_user_data(json[(XorStr("info"))]);

                    response.StatusCode = 420;
                    response.pReason = XorStr("SHEESH").c_str();
                    response.ReasonLength = (USHORT)strlen(response.pReason);
                }
                else
                {
                    response.StatusCode = 200;
                    response.pReason = static_cast<std::string>(json[(XorStr("message"))]).c_str();
                    response.ReasonLength = (USHORT)strlen(response.pReason);
                    success = false;
                }
                // end keyauth request

                // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
                HTTP_UNKNOWN_HEADER  accessControlHeader;
                const char testCustomHeader[] = "Access-Control-Allow-Origin";
                const char testCustomHeaderVal[] = "*";
                accessControlHeader.pName = testCustomHeader;
                accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
                accessControlHeader.pRawValue = testCustomHeaderVal;
                accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
                response.Headers.pUnknownHeaders = &accessControlHeader;
                response.Headers.UnknownHeaderCount = 1;
                // Add an entity chunk to the response.
                // PSTR pEntityString = "Hello from C++";
                HTTP_DATA_CHUNK dataChunk;
                dataChunk.DataChunkType = HttpDataChunkFromMemory;

                result = HttpSendHttpResponse(
                    requestQueueHandle,
                    pRequest->RequestId,
                    0,
                    &response,
                    NULL,
                    NULL,   // &bytesSent (optional)
                    NULL,
                    0,
                    NULL,
                    NULL
                );

                if (result == NO_ERROR) {
                    going = false;
                }

                if (!success)
                    LI_FN(exit)(0);
            }
            else {
                LI_FN(exit)(9);
            }
        }
        else {
            LI_FN(exit)(7);
        }
    }
}

void KeyAuth::api::button(std::string button)
{
    checkInit();
    ScopeWipe wipe_button(button);

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

    // Create server session.
    HTTP_SERVER_SESSION_ID serverSessionId;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    // Create URL group.
    HTTP_URL_GROUP_ID groupId;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    // Create request queue.
    HANDLE requestQueueHandle;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info;
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    // Add URLs to URL group.
    std::wstring output;
    output = std::wstring(button.begin(), button.end());
    output = std::wstring(L"http://localhost:1337/") + output;
    PCWSTR url = output.c_str();
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/buttonvaluehere
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 4096;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        auto buffer = std::make_unique<BYTE[]>(requestSize);
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer.get();
        RtlZeroMemory(buffer.get(), requestSize);
        ULONG bytesReturned;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );

        going = false;

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // Break from the loop if it's the poison pill (a DELETE request).
        // if (pRequest->Verb == HttpVerbDELETE)
        // {
        //     wprintf(L"Asked to stop.\n");
        //     break;
        // }

        // Respond to the request.
        HTTP_RESPONSE response;
        RtlZeroMemory(&response, sizeof(response));
        response.StatusCode = 420;
        response.pReason = XorStr("SHEESH").c_str();
        response.ReasonLength = (USHORT)strlen(response.pReason);

        // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
        HTTP_UNKNOWN_HEADER  accessControlHeader;
        const char testCustomHeader[] = "Access-Control-Allow-Origin";
        const char testCustomHeaderVal[] = "*";
        accessControlHeader.pName = testCustomHeader;
        accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
        accessControlHeader.pRawValue = testCustomHeaderVal;
        accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
        response.Headers.pUnknownHeaders = &accessControlHeader;
        response.Headers.UnknownHeaderCount = 1;
        // Add an entity chunk to the response.
        // PSTR pEntityString = "Hello from C++";
        HTTP_DATA_CHUNK dataChunk;
        dataChunk.DataChunkType = HttpDataChunkFromMemory;

        result = HttpSendHttpResponse(
            requestQueueHandle,
            pRequest->RequestId,
            0,
            &response,
            NULL,
            NULL,   // &bytesSent (optional)
            NULL,
            0,
            NULL,
            NULL
        );

    }
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key, std::string email) {
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_pass(password);
    ScopeWipe wipe_key(key);
    ScopeWipe wipe_email(email);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=register") +
        XorStr("&username=") + username +
        XorStr("&pass=") + password +
        XorStr("&key=") + key +
        XorStr("&email=") + email +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                std::ofstream file(file_path);
                if (file.is_open()) {
                    file << seed;
                    file.close();
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else
    {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::upgrade(std::string username, std::string key) {
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_key(key);

    auto data =
        XorStr("type=upgrade") +
        XorStr("&username=") + username +
        XorStr("&key=") + key +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            json[(XorStr("success"))] = false;
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string generate_random_number() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist_length(5, 10); // Random length between 5 and 10 digits
    std::uniform_int_distribution<> dist_digit(0, 9);   // Random digit

    int length = dist_length(gen);
    std::string random_number;
    for (int i = 0; i < length; ++i) {
        random_number += std::to_string(dist_digit(gen));
    }
    return random_number;
}

void KeyAuth::api::license(std::string key, std::string code) {
    checkInit();
    ScopeWipe wipe_key(key);
    ScopeWipe wipe_code(code);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=license") +
        XorStr("&key=") + key +
        XorStr("&code=") + code +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                std::ofstream file(file_path);
                if (file.is_open()) {
                    file << seed;
                    file.close();
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::setvar(std::string var, std::string vardata) {
    checkInit();
    ScopeWipe wipe_var(var);
    ScopeWipe wipe_data(vardata);

    auto data =
        XorStr("type=setvar") +
        XorStr("&var=") + var +
        XorStr("&data=") + vardata +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    load_response_data(json);
}

std::string KeyAuth::api::getvar(std::string var) {
    checkInit();
    ScopeWipe wipe_var(var);

    auto data =
        XorStr("type=getvar") +
        XorStr("&var=") + var +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::ban(std::string reason) {
    checkInit();
    ScopeWipe wipe_reason(reason);

    auto data =
        XorStr("type=ban") +
        XorStr("&reason=") + reason +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else
    {
        LI_FN(exit)(7);
    }
}

bool KeyAuth::api::checkblack() {
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=checkblacklist") +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            return json[XorStr("success")];
        }
        LI_FN(exit)(9);
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::check(bool check_paid) {
    checkInit();

    auto data =
        XorStr("type=check") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    std::string endpoint = url;
    if (check_paid) {
        endpoint += "?check_paid=1";
    }

    auto response = req(data, endpoint);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string KeyAuth::api::var(std::string varid) {
    checkInit();

    auto data =
        XorStr("type=var") +
        XorStr("&varid=") + varid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return json[(XorStr("message"))];
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::log(std::string message) {
    checkInit();
    ScopeWipe wipe_message(message);

    char acUserName[100];
    DWORD nUserName = sizeof(acUserName);
    GetUserNameA(acUserName, &nUserName);
    std::string UsernamePC = acUserName;

    auto data =
        XorStr("type=log") +
        XorStr("&pcuser=") + UsernamePC +
        XorStr("&message=") + message +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    req(data, url);
}

std::vector<unsigned char> KeyAuth::api::download(std::string fileid) {
    checkInit();
    ScopeWipe wipe_fileid(fileid);

    auto to_uc_vector = [](std::string value) {
        return std::vector<unsigned char>(value.data(), value.data() + value.length() );
    };


    auto data =
        XorStr("type=file") +
        XorStr("&fileid=") + fileid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    load_response_data(json);
    if (json[ XorStr( "success" ) ])
    {
        auto file = hexDecode(json[ XorStr( "contents" )]);
        return to_uc_vector(file);
    }
    return {};
}


std::string KeyAuth::api::webhook(std::string id, std::string params, std::string body, std::string contenttype)
{
    checkInit();
    ScopeWipe wipe_id(id);
    ScopeWipe wipe_params(params);
    ScopeWipe wipe_body(body);
    ScopeWipe wipe_type(contenttype);

    CURL *curl = curl_easy_init();
    auto data =
        XorStr("type=webhook") +
        XorStr("&webid=") + id +
        XorStr("&params=") + curl_escape(curl, params) +
        XorStr("&body=") + curl_escape(curl, body) +
        XorStr("&conttype=") + contenttype +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    curl_easy_cleanup(curl);
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string KeyAuth::api::fetchonline() 
{
    checkInit();

    auto data =
        XorStr("type=fetchOnline") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            std::string onlineusers;

            int y = atoi(api::app_data.numOnlineUsers.c_str());
            for (int i = 0; i < y; i++)
            {
                onlineusers.append(json[XorStr("users")][i][XorStr("credential")]); onlineusers.append(XorStr("\n"));
            }

            return onlineusers;
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::fetchstats()
{
    checkInit();

    auto data =
        XorStr("type=fetchStats") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);

            if (json[(XorStr("success"))])
                load_app_data(json[(XorStr("appinfo"))]);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::forgot(std::string username, std::string email)
{
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_email(email);

    auto data =
        XorStr("type=forgot") +
        XorStr("&username=") + username +
        XorStr("&email=") + email +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    load_response_data(json);
}

void KeyAuth::api::logout() {
    checkInit();

    auto data =
        XorStr("type=logout") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    if (json[(XorStr("success"))]) {

        //clear all old user data from program
        user_data.createdate.clear();
        user_data.ip.clear();
        user_data.hwid.clear();
        user_data.lastlogin.clear();
        user_data.username.clear();
        user_data.subscriptions.clear();

        //clear sessionid
        sessionid.clear();

        //clear enckey
        enckey.clear();

    }

    load_response_data(json);
}

void KeyAuth::api::start_ban_monitor(int interval_seconds, bool check_session, std::function<void()> on_ban)
{
    if (ban_monitor_running_) {
        return;
    }

    if (interval_seconds < 1) {
        interval_seconds = 1;
    }

    ban_monitor_detected_ = false;
    ban_monitor_running_ = true;
    ban_monitor_thread_ = std::thread([this, interval_seconds, check_session, on_ban]() {
        while (ban_monitor_running_) {
            if (check_session) {
                this->check(false);
            }

            if (this->checkblack()) {
                ban_monitor_detected_ = true;
                ban_monitor_running_ = false;
                if (on_ban) {
                    on_ban();
                }
                return;
            }

            std::this_thread::sleep_for(std::chrono::seconds(interval_seconds));
        }
    });
}

void KeyAuth::api::stop_ban_monitor()
{
    ban_monitor_running_ = false;
    if (ban_monitor_thread_.joinable()) {
        ban_monitor_thread_.join();
    }
}

bool KeyAuth::api::ban_monitor_running() const
{
    return ban_monitor_running_.load();
}

bool KeyAuth::api::ban_monitor_detected() const
{
    return ban_monitor_detected_.load();
}

std::string KeyAuth::api::expiry_remaining(const std::string& expiry)
{
    if (expiry.empty())
        return "unknown";
    long long exp = 0;
    try {
        exp = std::stoll(expiry);
    }
    catch (...) {
        return "unknown";
    }
    const long long now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    long long diff = exp - now;
    if (diff <= 0)
        return "expired";

    const long long days = diff / 86400;
    const long long weeks = days / 7;
    const long long months = days / 30;
    const long long hours = (diff % 86400) / 3600;
    const long long minutes = (diff % 3600) / 60;

    std::time_t tt = static_cast<std::time_t>(exp);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    tm = *std::localtime(&tt);
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

    std::ostringstream out;
    out << days << "d " << hours << "h " << minutes << "m remaining"
        << " (expires " << buf << ", ~" << weeks << "w / " << months << "mo)";
    return out.str();
}

void KeyAuth::api::init_fail_delay()
{
    Sleep(kInitFailSleepMs);
}

void KeyAuth::api::bad_input_delay()
{
    Sleep(kBadInputSleepMs);
}

void KeyAuth::api::close_delay()
{
    Sleep(kCloseSleepMs);
}

bool KeyAuth::api::lockout_active(const lockout_state& state)
{
    return std::chrono::steady_clock::now() < state.locked_until;
}

int KeyAuth::api::lockout_remaining_ms(const lockout_state& state)
{
    if (!lockout_active(state))
        return 0;
    const auto now = std::chrono::steady_clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(state.locked_until - now).count();
    return remaining > 0 ? static_cast<int>(remaining) : 0;
}

void KeyAuth::api::record_login_fail(lockout_state& state, int max_attempts, int lock_seconds)
{
    if (max_attempts < 1)
        max_attempts = 1;
    if (lock_seconds < 1)
        lock_seconds = 1;
    state.fails += 1;
    if (state.fails >= max_attempts) {
        state.fails = 0;
        state.locked_until = std::chrono::steady_clock::now() + std::chrono::seconds(lock_seconds);
    }
}

void KeyAuth::api::reset_lockout(lockout_state& state)
{
    state.fails = 0;
    state.locked_until = std::chrono::steady_clock::time_point{};
}

int VerifyPayload(std::string signature, std::string timestamp, std::string body)
{
    if (!prologues_ok()) {
        error(XorStr("function prologue check failed, possible inline hook detected."));
    }
    integrity_check();
    if (timestamp.size() < 10 || timestamp.size() > 13) {
        MessageBoxA(0, "Signature verification failed (timestamp length)", "KeyAuth", MB_ICONERROR);
        exit(2);
    }
    for (char c : timestamp) {
        if (c < '0' || c > '9') {
            MessageBoxA(0, "Signature verification failed (timestamp format)", "KeyAuth", MB_ICONERROR);
            exit(2);
        }
    }
    long long unix_timestamp = 0;
    try {
        unix_timestamp = std::stoll(timestamp);
    }
    catch (...) {
        std::cerr << "[ERROR] Invalid timestamp format\n";
        MessageBoxA(0, "Signature verification failed (invalid timestamp)", "KeyAuth", MB_ICONERROR);
        exit(2);
    }

    auto current_time = std::chrono::system_clock::now();
    long long current_unix_time = std::chrono::duration_cast<std::chrono::seconds>(
        current_time.time_since_epoch()).count();

    const long long diff = std::llabs(current_unix_time - unix_timestamp);
    if (diff > 120) {
        std::cerr << "[ERROR] Timestamp too skewed (diff = "
            << diff << "s)\n";
        MessageBoxA(0, "Signature verification failed (timestamp skew)", "KeyAuth", MB_ICONERROR);
        exit(3);
    }

    if (sodium_init() < 0) {
        std::cerr << "[ERROR] Failed to initialize libsodium\n";
        MessageBoxA(0, "Signature verification failed (libsodium init)", "KeyAuth", MB_ICONERROR);
        exit(4);
    }

    std::string message = timestamp + body;

    unsigned char sig[64];
    unsigned char pk[32];

    if (signature.size() != 128) {
        MessageBoxA(0, "Signature verification failed (sig length)", "KeyAuth", MB_ICONERROR);
        exit(5);
    }
    if (sodium_hex2bin(sig, sizeof(sig), signature.c_str(), signature.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse signature hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid signature format)", "KeyAuth", MB_ICONERROR);
        exit(5);
    }

    const std::string pubkey_hex = get_public_key_hex();
    if (sodium_hex2bin(pk, sizeof(pk), pubkey_hex.c_str(), pubkey_hex.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse public key hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid public key)", "KeyAuth", MB_ICONERROR);
        exit(6);
    }

    /*std::cout << "[DEBUG] Timestamp: " << timestamp << std::endl;
    std::cout << "[DEBUG] Signature: " << signature << std::endl;
    std::cout << "[DEBUG] Body: " << body << std::endl;
    std::cout << "[DEBUG] Message (timestamp + body): " << message << std::endl;
    std::cout << "[DEBUG] Public Key: " << pubkey_hex << std::endl;*/

    if (crypto_sign_ed25519_verify_detached(sig,
        reinterpret_cast<const unsigned char*>(message.c_str()),
        message.length(),
        pk) != 0)
    {
        std::cerr << "[ERROR] Signature verification failed.\n";
        MessageBoxA(0, "Signature verification failed (invalid signature)", "KeyAuth", MB_ICONERROR);
        exit(7);
    }

    //std::cout << "[DEBUG] Payload verified successfully.\n";

    int value = 42 ^ 0xA5A5;
    return value & 0xFFFF;
}


// credits https://stackoverflow.com/a/3790661
static std::string hexDecode(const std::string& hex)
{
    int len = hex.length();
    std::string newString;
    for (int i = 0; i < len; i += 2)
    {
        std::string byte = hex.substr(i, 2);
        char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    return newString;
}
// credits https://stackoverflow.com/a/43002794
std::string get_str_between_two_str(const std::string& s,
    const std::string& start_delim,
    const std::string& stop_delim)
{
    const auto first_delim_pos = s.find(start_delim);
    if (first_delim_pos == std::string::npos)
        return {};
    const auto end_pos_of_first_delim = first_delim_pos + start_delim.length();
    const auto last_delim_pos = s.find(stop_delim, end_pos_of_first_delim);
    if (last_delim_pos == std::string::npos || last_delim_pos < end_pos_of_first_delim)
        return {};

    return s.substr(end_pos_of_first_delim,
        last_delim_pos - end_pos_of_first_delim);
}

std::string curl_escape(CURL* curl, const std::string& input)
{
    if (!curl)
        return input;
    char* escaped = curl_easy_escape(curl, input.c_str(), 0);
    if (!escaped)
        return {};
    std::string out(escaped);
    curl_free(escaped);
    return out;
}

std::string extract_host(const std::string& url)
{
    std::string host = url;
    const auto scheme_pos = host.find("://");
    if (scheme_pos != std::string::npos)
        host = host.substr(scheme_pos + 3);
    const auto slash_pos = host.find('/');
    if (slash_pos != std::string::npos)
        host = host.substr(0, slash_pos);
    const auto colon_pos = host.find(':');
    if (colon_pos != std::string::npos)
        host = host.substr(0, colon_pos);
    return host;
}

static bool is_ip_literal(const std::string& host)
{
    sockaddr_in sa4{};
    sockaddr_in6 sa6{};
    return inet_pton(AF_INET, host.c_str(), &sa4.sin_addr) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &sa6.sin6_addr) == 1;
}

static bool is_private_or_loopback_ipv4(uint32_t addr_net_order)
{
    const uint32_t a = ntohl(addr_net_order);
    const uint8_t b1 = static_cast<uint8_t>(a >> 24);
    const uint8_t b2 = static_cast<uint8_t>((a >> 16) & 0xFF);
    if (b1 == 10) return true;
    if (b1 == 127) return true;
    if (b1 == 0) return true;
    if (b1 == 169 && b2 == 254) return true;
    if (b1 == 100 && (b2 >= 64 && b2 <= 127)) return true; // 100.64.0.0/10
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 192 && b2 == 0) return true; // 192.0.0.0/24
    if (b1 == 198 && (b2 == 18 || b2 == 19)) return true; // 198.18.0.0/15
    if (b1 == 172) {
        const uint8_t b3 = static_cast<uint8_t>((a >> 8) & 0xFF);
        if (b3 >= 16 && b3 <= 31) return true;
    }
    if (b1 >= 224) return true; // multicast/reserved
    return false;
}

static bool is_loopback_ipv6(const in6_addr& addr)
{
    static const in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
    return std::memcmp(&addr, &loopback, sizeof(loopback)) == 0;
}

static bool is_private_or_loopback_ipv6(const in6_addr& addr)
{
    if (is_loopback_ipv6(addr))
        return true;
    const uint8_t b0 = addr.u.Byte[0];
    const uint8_t b1 = addr.u.Byte[1];
    if ((b0 & 0xFE) == 0xFC) // fc00::/7 unique-local
        return true;
    if (b0 == 0xFE && (b1 & 0xC0) == 0x80) // fe80::/10 link-local
        return true;
    if ((b0 & 0xFF) == 0xFF) // multicast ff00::/8
        return true;
    return false;
}

static bool ip_string_private_or_loopback(const std::string& ip)
{
    if (ip.empty())
        return false;
    sockaddr_in sa4{};
    if (inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1) {
        return is_private_or_loopback_ipv4(sa4.sin_addr.s_addr);
    }
    sockaddr_in6 sa6{};
    if (inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1) {
        return is_private_or_loopback_ipv6(sa6.sin6_addr);
    }
    return false;
}

static bool host_is_keyauth(const std::string& host_lower)
{
    if (host_lower == "keyauth.win" || host_lower == "keyauth.cc" || host_lower == "api-worker.keyauth.win")
        return true;
    const std::string suffix = ".keyauth.win";
    if (host_lower.size() > suffix.size() &&
        host_lower.compare(host_lower.size() - suffix.size(), suffix.size(), suffix) == 0)
        return true;
    return false;
}

static bool is_https_url(const std::string& url)
{
    const std::string prefix = "https://";
    if (url.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(url[i])));
        if (c != prefix[i])
            return false;
    }
    return true;
}

static bool winhttp_proxy_set()
{
    WINHTTP_PROXY_INFO info{};
    if (!WinHttpGetDefaultProxyConfiguration(&info))
        return false;
    bool set = false;
    if (info.lpszProxy && *info.lpszProxy)
        set = true;
    if (info.lpszProxyBypass && *info.lpszProxyBypass)
        set = true;
    if (info.lpszProxy) GlobalFree(info.lpszProxy);
    if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
    return set;
}

static bool winhttp_proxy_auto_set()
{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG cfg{};
    if (!WinHttpGetIEProxyConfigForCurrentUser(&cfg))
        return false;
    bool set = false;
    if (cfg.fAutoDetect)
        set = true;
    if (cfg.lpszAutoConfigUrl && *cfg.lpszAutoConfigUrl)
        set = true;
    if (cfg.lpszAutoConfigUrl) GlobalFree(cfg.lpszAutoConfigUrl);
    if (cfg.lpszProxy) GlobalFree(cfg.lpszProxy);
    if (cfg.lpszProxyBypass) GlobalFree(cfg.lpszProxyBypass);
    return set;
}

static bool host_resolves_private_only(const std::string& host, bool& has_public)
{
    has_public = false;
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return false;
    bool any = false;
    bool all_private = true;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (!p->ai_addr)
            continue;
        any = true;
        if (p->ai_family == AF_INET) {
            const auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if (!is_private_or_loopback_ipv4(sa->sin_addr.s_addr)) {
                all_private = false;
                has_public = true;
            }
        } else if (p->ai_family == AF_INET6) {
            const auto* sa = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (!is_loopback_ipv6(sa->sin6_addr)) {
                all_private = false;
                has_public = true;
            }
        }
    }
    freeaddrinfo(res);
    if (!any)
        return false;
    return all_private;
}

static void collect_ips_from_dns(PDNS_RECORD rec, std::vector<std::string>& out)
{
    for (auto p = rec; p; p = p->pNext) {
        if (p->wType == DNS_TYPE_A) {
            char buf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &p->Data.A.IpAddress, buf, sizeof(buf));
            out.emplace_back(buf);
        } else if (p->wType == DNS_TYPE_AAAA) {
            char buf[INET6_ADDRSTRLEN] = {};
            inet_ntop(AF_INET6, &p->Data.AAAA.Ip6Address, buf, sizeof(buf));
            out.emplace_back(buf);
        }
    }
}

static bool dns_cache_poisoned(const std::string& host)
{
    if (host.empty())
        return false;

    std::vector<std::string> cached;
    std::vector<std::string> fresh;

    PDNS_RECORD rec_cached = nullptr;
    PDNS_RECORD rec_fresh = nullptr;

    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &rec_cached, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_cached, cached);
        DnsRecordListFree(rec_cached, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_STANDARD, nullptr, &rec_cached, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_cached, cached);
        DnsRecordListFree(rec_cached, DnsFreeRecordList);
    }

    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }

    if (cached.empty() || fresh.empty())
        return false;

    std::sort(cached.begin(), cached.end());
    cached.erase(std::unique(cached.begin(), cached.end()), cached.end());
    std::sort(fresh.begin(), fresh.end());
    fresh.erase(std::unique(fresh.begin(), fresh.end()), fresh.end());

    return cached != fresh;
}

static bool dns_fresh_contains_ip(const std::string& host, const std::string& ip)
{
    if (host.empty() || ip.empty())
        return false;
    std::vector<std::string> fresh;
    PDNS_RECORD rec_fresh = nullptr;
    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (fresh.empty())
        return false;
    for (const auto& entry : fresh) {
        if (_stricmp(entry.c_str(), ip.c_str()) == 0)
            return true;
    }
    return false;
}

bool hosts_override_present(const std::string& host)
{
	if (host.empty())
		return false;

	std::string host_lower = host;
	std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

	const char* sysroot = std::getenv("SystemRoot");
	std::string hosts_path = sysroot ? std::string(sysroot) : "C:\\Windows";
	hosts_path += "\\System32\\drivers\\etc\\hosts";

	// this will block the symlink/reparse tricks and attrs
	const DWORD attr = GetFileAttributesA(hosts_path.c_str());
	if (attr == INVALID_FILE_ATTRIBUTES)
		return false;
	if (attr & FILE_ATTRIBUTE_REPARSE_POINT) // symlink/junction
		return true;

	std::ifstream file(hosts_path);
	if (!file.good())
		return false;

	std::string line;
	while (std::getline(file, line)) {
		auto hash_pos = line.find('#');
		if (hash_pos != std::string::npos)
			line = line.substr(0, hash_pos);

		std::transform(line.begin(), line.end(), line.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		// word check example, this can always be improved
		if (line.find(" " + host_lower) != std::string::npos || line.find("\t" + host_lower) != std::string::npos)
			return true;
	}
	return false;
}

static std::wstring to_lower_ws(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return value;
}

static bool path_has_any(const std::wstring& p, const std::initializer_list<std::wstring>& needles)
{
    for (const auto& n : needles) {
        if (p.find(n) != std::wstring::npos)
            return true;
    }
    return false;
}

bool module_has_rwx_section(HMODULE mod)
{
    if (!mod)
        return false;
    auto base = reinterpret_cast<std::uintptr_t>(mod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        const auto ch = section->Characteristics;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE))
            return true;
    }
    return false;
}

static bool verify_signature(const std::wstring& path)
{
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_IGNORE;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policy, &trust_data);
    return status == ERROR_SUCCESS;
}

bool core_modules_signed()
{
    // verify core dll signatures and reject rwx sections -nigel
    const wchar_t* kModules[] = { L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll" };
    for (const auto* name : kModules) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod)
            return false;
        wchar_t path[MAX_PATH] = {};
        if (!GetModuleFileNameW(mod, path, MAX_PATH))
            return false;
        if (!verify_signature(path))
            return false;
        if (module_has_rwx_section(mod))
            return false;
    }
    return true;
}

static bool reg_key_exists(HKEY root, const wchar_t* path)
{
    HKEY h = nullptr;
    const LONG res = RegOpenKeyExW(root, path, 0, KEY_READ, &h);
    if (res == ERROR_SUCCESS) {
        RegCloseKey(h);
        return true;
    }
    return false;
}

static bool file_exists(const std::wstring& path)
{
    const DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring get_system_dir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetSystemDirectoryW(buf, MAX_PATH) == 0)
        return L"";
    return std::wstring(buf);
}

static std::wstring get_syswow_dir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetSystemWow64DirectoryW(buf, MAX_PATH) == 0)
        return L"";
    return std::wstring(buf);
}

static std::wstring normalize_path(std::wstring p)
{
    std::transform(p.begin(), p.end(), p.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) {
        p.pop_back();
    }
    return p;
}

static bool get_module_path(HMODULE mod, std::wstring& out)
{
    wchar_t path[MAX_PATH] = {};
    if (!mod)
        return false;
    if (!GetModuleFileNameW(mod, path, MAX_PATH))
        return false;
    out.assign(path);
    return true;
}

static bool module_in_system32(HMODULE mod)
{
    std::wstring mod_path;
    if (!get_module_path(mod, mod_path))
        return false;
    mod_path = normalize_path(mod_path);

    std::wstring sys = normalize_path(get_system_dir());
    if (sys.empty())
        return false;

    return mod_path.rfind(sys + L"\\", 0) == 0;
}

static uint32_t file_crc32(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return 0;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (buf.empty()) return 0;

    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : buf) {
        crc ^= b;
        for (int k = 0; k < 8; ++k) {
            uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool critical_modules_safe()
{
    const wchar_t* system_mods[] = { L"wintrust.dll", L"crypt32.dll", L"bcrypt.dll" };
    for (const auto* name : system_mods) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod) return false;
        if (!module_in_system32(mod)) return false;
    }

    const wchar_t* app_mods[] = { L"libcurl.dll", L"libsodium.dll" };
    for (const auto* name : app_mods) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod) continue;
        std::wstring path;
        if (!get_module_path(mod, path)) return false;
        std::wstring p = normalize_path(path);

        if (p.find(L"\\appdata\\") != std::wstring::npos ||
            p.find(L"\\temp\\") != std::wstring::npos ||
            p.find(L"\\downloads\\") != std::wstring::npos) {
            return false;
        }
    }
    return true;
}

void snapshot_prologues()
{
    if (prologues_ready.load())
        return;
    const auto verify_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&VerifyPayload));
    const auto check_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&checkInit));
    const auto error_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&error));
    const auto integ_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&integrity_check));
    const auto section_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&check_section_integrity));
    std::memcpy(pro_verify.data(), verify_ptr, pro_verify.size());
    std::memcpy(pro_checkinit.data(), check_ptr, pro_checkinit.size());
    std::memcpy(pro_error.data(), error_ptr, pro_error.size());
    std::memcpy(pro_integrity.data(), integ_ptr, pro_integrity.size());
    std::memcpy(pro_section.data(), section_ptr, pro_section.size());
    prologues_ready.store(true);
    snapshot_text_hashes();
    snapshot_text_page_protections();
    snapshot_data_page_protections();
    {
        std::uintptr_t text_base = 0;
        size_t text_size = 0;
        if (get_text_section_info(text_base, text_size) && text_base && text_size) {
            const auto* text_ptr = reinterpret_cast<const uint8_t*>(text_base);
            text_crc_baseline.store(rolling_crc32(text_ptr, text_size));
        }
    }
}

static void snapshot_checkinit()
{
    if (checkinit_ready.load())
        return;
    const auto p = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&checkInit));
    std::memcpy(checkinit_prologue.data(), p, checkinit_prologue.size());
    checkinit_ready.store(true);
}

static bool checkinit_ok()
{
    if (!checkinit_ready.load())
        return true;
    const auto p = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&checkInit));
    return std::memcmp(checkinit_prologue.data(), p, checkinit_prologue.size()) == 0;
}

bool prologues_ok()
{
    if (!prologues_ready.load())
        return true;
    const auto verify_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&VerifyPayload));
    const auto check_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&checkInit));
    const auto error_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&error));
    const auto integ_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&integrity_check));
    const auto section_ptr = reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(&check_section_integrity));
    return std::memcmp(pro_verify.data(), verify_ptr, pro_verify.size()) == 0 &&
        std::memcmp(pro_checkinit.data(), check_ptr, pro_checkinit.size()) == 0 &&
        std::memcmp(pro_error.data(), error_ptr, pro_error.size()) == 0 &&
        std::memcmp(pro_integrity.data(), integ_ptr, pro_integrity.size()) == 0 &&
        std::memcmp(pro_section.data(), section_ptr, pro_section.size()) == 0;
}

bool func_region_ok(const void* addr)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0)
        return false;
    if (mbi.Type != MEM_IMAGE)
        return false;
    const DWORD prot = mbi.Protect;
    const bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
    const bool write = (prot & PAGE_READWRITE) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_WRITECOPY) || (prot & PAGE_EXECUTE_WRITECOPY);
    if (!exec || write)
        return false;
    return true;
}

bool timing_anomaly_detected()
{
    const auto wall_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    static auto wall_last = wall_now;
    static auto steady_last = steady_now;
    static ULONGLONG tick_last = GetTickCount64();
    static long long wall_last_sec = std::chrono::duration_cast<std::chrono::seconds>(
        wall_now.time_since_epoch()).count();
    const auto wall_delta = std::chrono::duration_cast<std::chrono::seconds>(wall_now - wall_last).count();
    const auto steady_delta = std::chrono::duration_cast<std::chrono::seconds>(steady_now - steady_last).count();
    wall_last = wall_now;
    steady_last = steady_now;
    const ULONGLONG tick_now = GetTickCount64();
    const long long tick_delta = static_cast<long long>((tick_now - tick_last) / 1000ULL);
    tick_last = tick_now;
    const long long wall_now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        wall_now.time_since_epoch()).count();
    const long long wall_tick_delta = wall_now_sec - wall_last_sec;
    wall_last_sec = wall_now_sec;
    if (wall_delta < -60 || wall_delta > 300)
        return true;
    if (std::llabs(wall_delta - steady_delta) > 120)
        return true;
    if (std::llabs(wall_tick_delta - tick_delta) > 120)
        return true;
    return false;
}

static bool get_text_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint32_t rolling_crc32(const uint8_t* data, size_t len, size_t window, size_t stride)
{
    if (!data || len < window)
        return 0;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i + window <= len; i += stride) {
        for (size_t j = 0; j < window; ++j) {
            uint8_t b = data[i + j];
            crc ^= b;
            for (int k = 0; k < 8; ++k) {
                uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
    }
    return ~crc;
}

static bool get_data_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".data", 5) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static bool get_rdata_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".rdata", 6) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint32_t fnv1a(const uint8_t* data, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

void snapshot_text_hashes()
{
    if (text_hashes_ready.load())
        return;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size) || size < 256)
        return;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, size - 64);
    text_hashes.clear();
    for (int i = 0; i < 8; ++i) {
        const size_t offset = dist(gen);
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(base + offset);
        text_hashes.push_back({ offset, 64, fnv1a(ptr, 64) });
    }
    text_hashes_ready.store(true);
}

bool text_hashes_ok()
{
    if (!text_hashes_ready.load())
        return true;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size))
        return true;
    for (const auto& h : text_hashes) {
        if (h.offset + h.len > size)
            return false;
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(base + h.offset);
        if (fnv1a(ptr, h.len) != h.hash)
            return false;
    }
    return true;
}

void snapshot_text_page_protections()
{
    if (text_prot_ready.load())
        return;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size))
        return;
    text_protections.clear();
    const size_t page = 0x1000;
    for (size_t off = 0; off < size; off += page) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
            continue;
        text_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
    }
    text_prot_ready.store(true);
}

void snapshot_data_page_protections()
{
    if (data_prot_ready.load())
        return;
    data_protections.clear();
    const size_t page = 0x1000;

    std::uintptr_t base = 0;
    size_t size = 0;
    if (get_data_section_info(base, size)) {
        for (size_t off = 0; off < size; off += page) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
                continue;
            data_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
        }
    }

    base = 0;
    size = 0;
    if (get_rdata_section_info(base, size)) {
        for (size_t off = 0; off < size; off += page) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
                continue;
            data_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
        }
    }

    data_prot_ready.store(true);
}

bool text_page_protections_ok()
{
    if (!text_prot_ready.load())
        return true;
    for (const auto& entry : text_protections) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(entry.first), &mbi, sizeof(mbi)) == 0)
            return false;
        const DWORD prot = mbi.Protect;
        if (prot != entry.second)
            return false;
        const bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
        const bool write = (prot & PAGE_READWRITE) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_WRITECOPY) || (prot & PAGE_EXECUTE_WRITECOPY);
        if (!exec || write)
            return false;
    }
    return true;
}

bool data_page_protections_ok()
{
    if (!data_prot_ready.load())
        return true;
    for (const auto& entry : data_protections) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(entry.first), &mbi, sizeof(mbi)) == 0)
            return false;
        const DWORD prot = mbi.Protect;
        if (prot != entry.second)
            return false;
        const bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
        if (exec)
            return false;
    }
    return true;
}


bool detour_suspect(const uint8_t* p)
{
    if (!p)
        return true;
    // jmp rel32 / call rel32 / jmp rel8
    if (p[0] == 0xE9 || p[0] == 0xE8 || p[0] == 0xEB)
        return true;
    // jmp/call [rip+imm32]
    if (p[0] == 0xFF && (p[1] == 0x25 || p[1] == 0x15))
        return true;
    // mov rax, imm64; jmp rax
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0)
        return true;
    return false;
}

static bool entry_is_jmp_or_call(const void* fn)
{
    if (!fn) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    if (p[0] == 0xE9) return true; // jmp rel32
    if (p[0] == 0xFF && p[1] == 0x25) return true; // jmp [rip+imm32]
    if (p[0] == 0xE8) return true; // call rel32
    if (p[0] == 0x68 && p[5] == 0xC3) return true; // push imm32; ret
    return false;
}

static bool entry_is_reg_jump(const void* fn)
{
    if (!fn) return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    if (p[0] == 0xFF && (p[1] & 0xF8) == 0xE0) return true; // jmp reg
    if (p[0] == 0xFF && (p[1] & 0xF8) == 0xD0) return true; // call reg
    return false;
}

static bool addr_in_module(const void* addr, const wchar_t* module_name)
{
    HMODULE mod = module_name ? GetModuleHandleW(module_name) : GetModuleHandle(nullptr);
    if (!mod)
        return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        return false;
    const auto base = reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll);
    const auto end = base + mi.SizeOfImage;
    return addr >= base && addr < end;
}

static bool addr_in_module_handle(const void* addr, HMODULE mod)
{
    if (!mod)
        return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
        return false;
    const auto base = reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll);
    const auto end = base + mi.SizeOfImage;
    return addr >= base && addr < end;
}

static bool export_mismatch(const char* dll, const char* func)
{
    HMODULE mod = GetModuleHandleA(dll);
    if (!mod)
        return false;

    void* by_export = nullptr;
    if (!get_export_address(mod, func, by_export))
        return false;

    void* by_proc = GetProcAddress(mod, func);
    if (!by_proc)
        return false;

    return by_export != by_proc;
}

static bool hotpatch_prologue_present(const void* fn)
{
    if (!fn)
        return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    if (p[0] == 0x8B && p[1] == 0xFF) return true; // mov edi, edi
    if (p[0] == 0x90 && p[1] == 0x90 && p[2] == 0x90 && p[3] == 0x90 && p[4] == 0x90) return true;
    return false;
}

static bool ntdll_syscall_stub_tampered(const char* name)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll || !name)
        return false;
    void* fn = GetProcAddress(ntdll, name);
    if (!fn)
        return false;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
#ifdef _WIN64
    if (!(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1)) return true;
    if (!(p[3] == 0xB8)) return true;
    if (!(p[8] == 0x0F && p[9] == 0x05)) return true;
    if (!(p[10] == 0xC3)) return true;
#endif
    return false;
}

static bool nearby_trampoline_present(const void* fn)
{
    if (!fn)
        return false;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
    for (int i = -32; i <= 32; ++i) {
        const uint8_t* q = p + i;
        if (q[0] == 0xE9) return true; // jmp rel32
        if (q[0] == 0xFF && q[1] == 0x25) return true; // jmp [rip+imm32]
    }
    return false;
}

static bool iat_hook_suspect(const char* dll_name, const char* func_name)
{
    HMODULE mod = GetModuleHandleA(dll_name);
    if (!mod || !func_name)
        return false;
    void* addr = GetProcAddress(mod, func_name);
    if (!addr)
        return false;
    return !addr_in_module_handle(addr, mod);
}

static bool get_export_address(HMODULE mod, const char* name, void*& out_addr)
{
    out_addr = nullptr;
    if (!mod || !name)
        return false;
    auto base = reinterpret_cast<uint8_t*>(mod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
        return false;

    auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
    auto funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
    auto ords = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base + names[i]);
        if (_stricmp(n, name) == 0) {
            WORD ord = ords[i];
            DWORD rva = funcs[ord];
            out_addr = base + rva;
            return true;
        }
    }
    return false;
}

bool import_addresses_ok()
{
    // wintrust functions should resolve inside wintrust.dll when loaded
    if (GetModuleHandleW(L"wintrust.dll")) {
        if (!addr_in_module(reinterpret_cast<const void*>(&WinVerifyTrust), L"wintrust.dll"))
            return false;
    }
    // VirtualQuery should be inside kernelbase/kernel32 when loaded
    if (GetModuleHandleW(L"kernelbase.dll") || GetModuleHandleW(L"kernel32.dll")) {
        if (!addr_in_module(reinterpret_cast<const void*>(&VirtualQuery), L"kernelbase.dll") &&
            !addr_in_module(reinterpret_cast<const void*>(&VirtualQuery), L"kernel32.dll"))
            return false;
    }
    // curl functions must live in main module (static)
    if (!addr_in_module(reinterpret_cast<const void*>(&curl_easy_perform), nullptr))
        return false;
    return true;
}

static bool iat_get_import_address(HMODULE module, const char* import_name, void*& out_addr, bool& found)
{
    if (!module)
        return true;
    auto base = reinterpret_cast<std::uintptr_t>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return true;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return true;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return true;
    auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    for (; desc->Name; ++desc) {
        const char* dll = reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(dll, "KERNEL32.DLL") != 0 && _stricmp(dll, "KERNELBASE.DLL") != 0)
            continue;
        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        auto orig = desc->OriginalFirstThunk
            ? reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk)
            : thunk;
        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                continue;
            auto import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + orig->u1.AddressOfData);
            if (strcmp(reinterpret_cast<char*>(import->Name), import_name) == 0) {
                found = true;
                out_addr = reinterpret_cast<void*>(thunk->u1.Function);
                return true;
            }
        }
    }
    return true;
}

static bool iat_points_outside_module(HMODULE module, const char* func_name)
{
    if (!module || !func_name)
        return false;

    void* addr = nullptr;
    bool found = false;
    if (!iat_get_import_address(module, func_name, addr, found) || !found)
        return false;

    HMODULE owner = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(addr), &owner)) {
        return true;
    }

    if (!addr_in_module_handle(addr, owner))
        return true;

    return false;
}

static bool iat_integrity_ok()
{
    HMODULE self = GetModuleHandle(nullptr);
    if (!self)
        return false;

    for (const char* name : kCriticalImports) {
        if (iat_points_outside_module(self, name)) {
            return false;
        }
    }
    return true;
}

void heartbeat_thread(KeyAuth::api* instance)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> sleep_seconds(45, 90);
    while (true) {
        Sleep(static_cast<DWORD>(sleep_seconds(gen) * 1000));
        if (!LoggedIn.load())
            continue;
        instance->check(false);
        if (!instance->response.success) {
            error(XorStr("session check failed."));
        }
    }
}

void start_heartbeat(KeyAuth::api* instance)
{
    if (heartbeat_started.exchange(true))
        return;
    std::thread(heartbeat_thread, instance).detach();
}

static void security_watchdog()
{
    while (true) {
        Sleep(15000);
        if (!checkinit_ok()) {
            error(XorStr("security watchdog detected tamper."));
        }
        checkInit();
    }
}

void KeyAuth::api::setDebug(bool value) {
    KeyAuth::api::debug = value;
}

std::string KeyAuth::api::req(std::string data, const std::string& url) {
    signature.clear();
    signatureTimestamp.clear();
    // gate requests on integrity checks to reduce bypasses -nigel
    integrity_check();
    // usage: keep this in req() so every api call is protected -nigel
    if (!prologues_ok()) {
        error(XorStr("function prologue check failed, possible inline hook detected."));
    }
    if (!func_region_ok(reinterpret_cast<const void*>(&VerifyPayload)) ||
        !func_region_ok(reinterpret_cast<const void*>(&checkInit)) ||
        !func_region_ok(reinterpret_cast<const void*>(&error)) ||
        !func_region_ok(reinterpret_cast<const void*>(&integrity_check)) ||
        !func_region_ok(reinterpret_cast<const void*>(&check_section_integrity))) {
        error(XorStr("function region check failed, possible hook detected."));
    }
    if (entry_is_jmp_or_call(reinterpret_cast<const void*>(&VerifyPayload)) ||
        entry_is_jmp_or_call(reinterpret_cast<const void*>(&checkInit)) ||
        entry_is_jmp_or_call(reinterpret_cast<const void*>(&integrity_check)) ||
        entry_is_jmp_or_call(reinterpret_cast<const void*>(&check_section_integrity)) ||
        entry_is_reg_jump(reinterpret_cast<const void*>(&VerifyPayload)) ||
        entry_is_reg_jump(reinterpret_cast<const void*>(&checkInit)) ||
        entry_is_reg_jump(reinterpret_cast<const void*>(&integrity_check)) ||
        entry_is_reg_jump(reinterpret_cast<const void*>(&check_section_integrity))) {
        error(XorStr("entry-point hook detected (jmp/call stub)."));
    }
    if (suspicious_processes_present() || suspicious_modules_present() || suspicious_windows_present()) {
        error(XorStr("debugger/emulator/proxy detected."));
    }
    if (proxy_env_set()) {
        error(XorStr("proxy environment detected."));
    }
    if (!is_https_url(url)) {
        error(XorStr("API URL must use HTTPS."));
    }
    std::string host = extract_host(url);
    ScopeWipe host_wipe(host);
    // block hosts-file redirects for api host -nigel
    if (hosts_override_present(host)) {
        error(XorStr("Hosts file override detected for API host."));
    }
    // block loopback/private redirects for keyauth domains -nigel
    {
        std::string host_lower = host;
        ScopeWipe host_lower_wipe(host_lower);
        std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!allowed_hosts.empty()) {
            bool allowed = false;
            for (const auto& entry : allowed_hosts) {
                std::string entry_lower = entry;
                std::transform(entry_lower.begin(), entry_lower.end(), entry_lower.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (entry_lower.rfind("*.", 0) == 0) {
                    auto suffix = entry_lower.substr(1);
                    if (host_lower.size() >= suffix.size() &&
                        host_lower.compare(host_lower.size() - suffix.size(), suffix.size(), suffix) == 0) {
                        allowed = true;
                        break;
                    }
                } else if (host_lower == entry_lower) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                error(XorStr("API host is not in allowed host list."));
        }
    }
    if (url_points_to_loopback(url)) {
        error(XorStr("loopback or local host detected for API URL."));
    }
    if (host_is_keyauth(host_lower)) {
        if (is_ip_literal(host_lower)) {
            error(XorStr("API host must not be an IP literal."));
        }
        if (proxy_env_set() || winhttp_proxy_set() || winhttp_proxy_auto_set()) {
            error(XorStr("Proxy settings detected for API host."));
        }
            bool has_public = false;
            if (host_resolves_private_only(host_lower, has_public) && !has_public) {
                error(XorStr("API host resolves to private or loopback."));
            }
            if (dns_cache_poisoned(host_lower)) {
                error(XorStr("DNS cache poisoning detected for API host."));
            }
        }
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        error(XorStr("CURL Initialization Failed!"));
    }

    std::string to_return;
    std::string headers;
    struct curl_slist* req_headers = nullptr;

    // Set CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
#ifdef CURL_SSLVERSION_TLSv1_2
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
#endif
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "KeyAuth");

    if (!pinned_public_keys.empty()) {
#ifdef CURLOPT_PINNEDPUBLICKEY
        if (pinned_public_keys.size() > 1) {
            error(XorStr("Multiple pinned public keys not supported."));
        }
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pinned_public_keys.at(0).c_str());
#else
        error(XorStr("Pinned public key not supported by this libcurl build."));
#endif
    }

    // Perform the request
    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        std::string errorMsg = "CURL Error: " + std::string(curl_easy_strerror(code));
        if (req_headers) curl_slist_free_all(req_headers);
        curl_easy_cleanup(curl);
        error(errorMsg);
    }

    long ssl_verify = 0;
    if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_verify) == CURLE_OK) {
        if (ssl_verify != 0) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("SSL verify result failed."));
        }
    }

    if (signature.empty() || signatureTimestamp.empty()) {
        if (req_headers) curl_slist_free_all(req_headers);
        curl_easy_cleanup(curl);
        error(XorStr("missing signature headers."));
    }

    char* effective_url = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url) == CURLE_OK && effective_url) {
        if (!is_https_url(effective_url)) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("effective url not https."));
        }
        std::string eff_host = extract_host(effective_url);
        std::string host_lower = host;
        std::string eff_lower = eff_host;
        std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(eff_lower.begin(), eff_lower.end(), eff_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!eff_lower.empty() && eff_lower != host_lower) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("effective url host mismatch."));
        }
    }

    long primary_port = 0;
    if (curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &primary_port) == CURLE_OK) {
        if (primary_port != 443) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("api port mismatch."));
        }
    }

    char* primary_ip = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK && primary_ip) {
        std::string ip = primary_ip;
        std::string host_lower = host;
        std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (host_is_keyauth(host_lower) && ip_string_private_or_loopback(ip)) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("api host resolved to private or loopback ip."));
        }
        if (host_is_keyauth(host_lower) && !dns_fresh_contains_ip(host_lower, ip)) {
            if (req_headers) curl_slist_free_all(req_headers);
            curl_easy_cleanup(curl);
            error(XorStr("api host ip mismatch vs fresh dns."));
        }
    }

    if (KeyAuth::api::debug) {
        debugInfo("n/a", "n/a", to_return, "n/a");
    }
    if (to_return.size() > (2 * 1024 * 1024)) {
        if (req_headers) curl_slist_free_all(req_headers);
        curl_easy_cleanup(curl);
        error(XorStr("response too large."));
    }
    if (to_return.size() < 32) {
        if (req_headers) curl_slist_free_all(req_headers);
        curl_easy_cleanup(curl);
        error(XorStr("response too small."));
    }
    if (req_headers) curl_slist_free_all(req_headers);
    curl_easy_cleanup(curl);
    secure_zero(data);
    return to_return;
}

void error(std::string message) {
    for (char& c : message) {
        if (c == '&' || c == '|' || c == '\"') c = ' '; // minimize cmd injection surface. -nigel
    }
    system((XorStr("start cmd /C \"color b && title Error && echo ").c_str() + message + XorStr(" && timeout /t 5\"")).c_str());
    LI_FN(__fastfail)(0);
}
// code submitted in pull request from https://github.com/Roblox932
auto check_section_integrity( const char *section_name, bool fix = false ) -> bool
{
    const auto map_file = []( HMODULE hmodule ) -> std::tuple<std::uintptr_t, HANDLE>
    {
        wchar_t filename[ MAX_PATH ];
        DWORD size = MAX_PATH;
        QueryFullProcessImageName(GetCurrentProcess(), 0, filename, &size);


        const auto file_handle = CreateFile( filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
        if ( !file_handle || file_handle == INVALID_HANDLE_VALUE )
        {
            return { 0ull, nullptr };
        }

        const auto file_mapping = CreateFileMapping( file_handle, 0, PAGE_READONLY, 0, 0, 0 );
        if ( !file_mapping )
        {
            CloseHandle( file_handle );
            return { 0ull, nullptr };
        }

        return { reinterpret_cast< std::uintptr_t >( MapViewOfFile( file_mapping, FILE_MAP_READ, 0, 0, 0 ) ), file_handle };
    };

    const auto hmodule = GetModuleHandle( 0 );
    if ( !hmodule ) return true;

    const auto base_0 = reinterpret_cast< std::uintptr_t >( hmodule );
    if ( !base_0 ) return true;

    const auto dos_0 = reinterpret_cast< IMAGE_DOS_HEADER * >( base_0 );
    if ( dos_0->e_magic != IMAGE_DOS_SIGNATURE ) return true;

    const auto nt_0 = reinterpret_cast< IMAGE_NT_HEADERS * >( base_0 + dos_0->e_lfanew );
    if ( nt_0->Signature != IMAGE_NT_SIGNATURE ) return true;

    auto section_0 = IMAGE_FIRST_SECTION( nt_0 );

    const auto [base_1, file_handle] = map_file( hmodule );
    if ( !base_1 || !file_handle || file_handle == INVALID_HANDLE_VALUE ) return true;

    const auto dos_1 = reinterpret_cast< IMAGE_DOS_HEADER * >( base_1 );
    if ( dos_1->e_magic != IMAGE_DOS_SIGNATURE )
    {
        UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
        CloseHandle( file_handle );
        return true;
    }

    const auto nt_1 = reinterpret_cast< IMAGE_NT_HEADERS * >( base_1 + dos_1->e_lfanew );
    if ( nt_1->Signature != IMAGE_NT_SIGNATURE ||
        nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
        nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections )
    {
        UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
        CloseHandle( file_handle );
        return true;
    }

    auto section_1 = IMAGE_FIRST_SECTION( nt_1 );

    bool patched = false;
    for ( auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1 )
    {
        if ( strcmp( reinterpret_cast< char * >( section_0->Name ), section_name ) ||
            !( section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) continue;

        for ( auto i = 0u; i < section_0->SizeOfRawData; ++i )
        {
            const auto old_value = *reinterpret_cast< BYTE * >( base_1 + section_1->PointerToRawData + i );

            if ( *reinterpret_cast< BYTE * >( base_0 + section_0->VirtualAddress + i ) == old_value )
            {
                continue;
            }

            if ( fix )
            {
                DWORD new_protect { PAGE_EXECUTE_READWRITE }, old_protect;
                VirtualProtect( ( void * )( base_0 + section_0->VirtualAddress + i ), sizeof( BYTE ), new_protect, &old_protect );
                *reinterpret_cast< BYTE * >( base_0 + section_0->VirtualAddress + i ) = old_value;
                VirtualProtect( ( void * )( base_0 + section_0->VirtualAddress + i ), sizeof( BYTE ), old_protect, &new_protect );
            }

            patched = true;
        }

        break;
    }

    UnmapViewOfFile( reinterpret_cast< void * >( base_1 ) );
    CloseHandle( file_handle );

    return patched;
}

void runChecks() {
   // Wait before starting checks
   int waitTime = 45000; 
   while (waitTime > 0) {

        if (LoggedIn.load()) {
	    // If the user is logged in, proceed with the checks immediately
            break;
         }
         std::this_thread::sleep_for(std::chrono::seconds(1));
         waitTime -= 1000;
    }

    // Create separate threads for each check
    std::thread(checkAtoms).detach(); 
    std::thread(checkFiles).detach(); 
    std::thread(checkRegistry).detach();
}

void checkAtoms() {

    while (true) {
        if (LI_FN(GlobalFindAtomA)(seed.c_str()) == 0) {
            LI_FN(exit)(13);
            LI_FN(__fastfail)(0);
        }
        Sleep(1000); // thread interval
    }
}

void checkFiles() {

    while (true) {
        std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
        DWORD file_attr = LI_FN(GetFileAttributesA)(file_path.c_str());
        if (file_attr == INVALID_FILE_ATTRIBUTES || (file_attr & FILE_ATTRIBUTE_DIRECTORY)) {
            LI_FN(exit)(14);
            LI_FN(__fastfail)(0);
        }
        Sleep(2000); // thread interval, files are more intensive than Atom tables which use memory
    }
}

void checkRegistry() {
	
    while (true) {
        std::string regPath = XorStr("Software\\").c_str() + seed;
        HKEY hKey;
        LONG result = LI_FN(RegOpenKeyExA)(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            LI_FN(exit)(15);
            LI_FN(__fastfail)(0);
        }
        LI_FN(RegCloseKey)(hKey);
	Sleep(1500); // thread interval
    }
}

std::string checksum()
{
    auto exec = [&](const char* cmd) -> std::string 
    {
        uint16_t line = -1;
        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
        if (!pipe) {
            throw std::runtime_error(XorStr("popen() failed!"));
        }

        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result = buffer.data();
        }
        return result;
    };

    char rawPathName[MAX_PATH];
    GetModuleFileNameA(NULL, rawPathName, MAX_PATH);

    return exec(("certutil -hashfile \"" + std::string(rawPathName) + XorStr( "\" MD5 | find /i /v \"md5\" | find /i /v \"certutil\"") ).c_str());
}

std::string getPath() {
    const char* programDataPath = std::getenv("ALLUSERSPROFILE");

    if (programDataPath != nullptr) {
        return std::string(programDataPath);
    }
    else {

        return std::filesystem::current_path().string();
    }
}

void RedactField(nlohmann::json& jsonObject, const std::string& fieldName)
{

    if (jsonObject.contains(fieldName)) {
        jsonObject[fieldName] = "REDACTED";
    }
}

void KeyAuth::api::debugInfo(std::string data, std::string url, std::string response, std::string headers) {
    // output debug logs to C:\ProgramData\KeyAuth\Debug\

    if (!KeyAuth::api::debug) {
        return;
    }

    std::string redacted_response = "n/a";
    // for logging the headers, since response is not avaliable there
    if (response != "n/a") {
        //turn response into json
        nlohmann::json responses = nlohmann::json::parse(response);
        RedactField(responses, "sessionid");
        RedactField(responses, "ownerid");
        RedactField(responses, "app");
        RedactField(responses, "name");
        RedactField(responses, "contents");
        RedactField(responses, "key");
        RedactField(responses, "username");
        RedactField(responses, "password");
        RedactField(responses, "version");
        RedactField(responses, "fileid");
        RedactField(responses, "webhooks");
        redacted_response = responses.dump();
    }

    std::string redacted_data = "n/a";
    // for logging the headers, since request JSON is not avaliable there
    if (data != "n/a") {
        //turn data into json
        std::replace(data.begin(), data.end(), '&', ' ');

        nlohmann::json datas;

        std::istringstream iss(data);
        std::vector<std::string> results((std::istream_iterator<std::string>(iss)),
            std::istream_iterator<std::string>());

        for (auto const& value : results) {
            const auto pos = value.find('=');
            if (pos == std::string::npos)
                continue;
            datas[value.substr(0, pos)] = value.substr(pos + 1);
        }

        RedactField(datas, "sessionid");
        RedactField(datas, "ownerid");
        RedactField(datas, "app");
        RedactField(datas, "name");
        RedactField(datas, "key");
        RedactField(datas, "username");
        RedactField(datas, "password");
        RedactField(datas, "contents");
        RedactField(datas, "version");
        RedactField(datas, "fileid");
        RedactField(datas, "webhooks");

        redacted_data = datas.dump();
    }

    //gets the path
    std::string path = getPath();

    //fetch filename

    TCHAR filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);

    TCHAR* filename_only = PathFindFileName(filename);

    std::wstring filenameOnlyString(filename_only);

    std::string filenameOnly(filenameOnlyString.begin(), filenameOnlyString.end());

    ///////////////////////

    //creates variables for the paths needed :smile:
    std::string KeyAuthPath = path + "\\KeyAuth";
    std::string logPath = KeyAuthPath + "\\Debug\\" + filenameOnly.substr(0, filenameOnly.size() - 4);

    //basically loops until we have all the paths
    if (!std::filesystem::exists(KeyAuthPath) || !std::filesystem::exists(KeyAuthPath + "\\Debug") || !std::filesystem::exists(logPath)) {

        if (!std::filesystem::exists(KeyAuthPath)) { std::filesystem::create_directory(KeyAuthPath); }

        if (!std::filesystem::exists(KeyAuthPath + "\\Debug")) { std::filesystem::create_directory(KeyAuthPath + "\\Debug"); }

        if (!std::filesystem::exists(logPath)) { std::filesystem::create_directory(logPath); }

    }

    if (response.length() >= 500) { return; }

    //fetch todays time
    std::time_t t = std::time(nullptr);
    char time[80];

    std::tm* localTime = std::localtime(&t);

    std::strftime(time, sizeof(time), "%m-%d-%Y", localTime);

    std::ofstream logfile(logPath + "\\" + time + ".txt", std::ios::app);

    //get time
    int hours = localTime->tm_hour;
    int minutes = localTime->tm_min;

    std::string period;
    if (hours < 12) {
        period = "AM";
    }
    else {
        period = "PM";
        hours -= 12;
    }

    std::string formattedMinutes = (minutes < 10) ? "0" + std::to_string(minutes) : std::to_string(minutes);

    std::string currentTimeString = std::to_string(hours) + ":" + formattedMinutes + " " + period;

    std::string contents = "\n\n@ " + currentTimeString + "\nURL: " + url + "\nData sent : " + redacted_data + "\nResponse : " + redacted_response + "\n" + headers;

    logfile << contents;

    logfile.close();
}

static bool compare_text_to_disk()
{
    wchar_t filename[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageName(GetCurrentProcess(), 0, filename, &size))
        return false;

    HANDLE file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    HANDLE map = CreateFileMappingW(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!map) {
        CloseHandle(file);
        return false;
    }

    void* mapped = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) {
        CloseHandle(map);
        CloseHandle(file);
        return false;
    }

    auto base_mem = reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr));
    auto base_disk = reinterpret_cast<std::uintptr_t>(mapped);

    auto dos_mem = reinterpret_cast<IMAGE_DOS_HEADER*>(base_mem);
    auto dos_disk = reinterpret_cast<IMAGE_DOS_HEADER*>(base_disk);

    if (dos_mem->e_magic != IMAGE_DOS_SIGNATURE || dos_disk->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(mapped);
        CloseHandle(map);
        CloseHandle(file);
        return false;
    }

    auto nt_mem = reinterpret_cast<IMAGE_NT_HEADERS*>(base_mem + dos_mem->e_lfanew);
    auto nt_disk = reinterpret_cast<IMAGE_NT_HEADERS*>(base_disk + dos_disk->e_lfanew);

    auto sec_mem = IMAGE_FIRST_SECTION(nt_mem);
    auto sec_disk = IMAGE_FIRST_SECTION(nt_disk);

    for (unsigned i = 0; i < nt_mem->FileHeader.NumberOfSections; ++i, ++sec_mem, ++sec_disk) {
        if (std::memcmp(sec_mem->Name, ".text", 5) == 0) {
            const size_t size_text = sec_mem->Misc.VirtualSize;
            const uint8_t* mem_ptr = reinterpret_cast<const uint8_t*>(base_mem + sec_mem->VirtualAddress);
            const uint8_t* disk_ptr = reinterpret_cast<const uint8_t*>(base_disk + sec_disk->PointerToRawData);
            bool same = (std::memcmp(mem_ptr, disk_ptr, size_text) == 0);

            UnmapViewOfFile(mapped);
            CloseHandle(map);
            CloseHandle(file);
            return same;
        }
    }

    UnmapViewOfFile(mapped);
    CloseHandle(map);
    CloseHandle(file);
    return false;
}

void checkInit() {
    if (!initialized) {
        error(XorStr("You need to run the KeyAuthApp.init(); function before any other KeyAuth functions"));
    }

    if (!checkinit_ok()) {
        error(XorStr("checkInit prologue modified."));
    }

    // usage: call init() once at startup; checks run automatically after that -nigel
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto last_mod = last_module_check.load();
    if (now - last_mod > 60) {
        last_module_check.store(now);
        // core module trust check to detect tampered system dlls -nigel
        if (!core_modules_signed()) {
            error(XorStr("module path check failed, possible side-load detected."));
        }
    }
    const auto last_periodic = last_periodic_check.load();
    if (now - last_periodic > 30) {
        last_periodic_check.store(now);
        // detect basic clock tampering to block expired key reuse -nigel
        if (timing_anomaly_detected()) {
            error(XorStr("timing anomaly detected, possible time tamper."));
        }
        // periodic integrity sweep across code regions -nigel
        const bool heavy_ok =
            text_hashes_ok() &&
            text_page_protections_ok() &&
            data_page_protections_ok() &&
            import_addresses_ok() &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&VerifyPayload)) &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&checkInit)) &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&error)) &&
            !entry_is_jmp_or_call(reinterpret_cast<const void*>(&VerifyPayload)) &&
            !entry_is_jmp_or_call(reinterpret_cast<const void*>(&checkInit)) &&
            !entry_is_jmp_or_call(reinterpret_cast<const void*>(&error)) &&
            !entry_is_jmp_or_call(reinterpret_cast<const void*>(&integrity_check)) &&
            !entry_is_jmp_or_call(reinterpret_cast<const void*>(&check_section_integrity)) &&
            !entry_is_reg_jump(reinterpret_cast<const void*>(&VerifyPayload)) &&
            !entry_is_reg_jump(reinterpret_cast<const void*>(&checkInit)) &&
            !entry_is_reg_jump(reinterpret_cast<const void*>(&error)) &&
            !entry_is_reg_jump(reinterpret_cast<const void*>(&integrity_check)) &&
            !entry_is_reg_jump(reinterpret_cast<const void*>(&check_section_integrity)) &&
            prologues_ok() &&
            func_region_ok(reinterpret_cast<const void*>(&VerifyPayload)) &&
            func_region_ok(reinterpret_cast<const void*>(&checkInit)) &&
            func_region_ok(reinterpret_cast<const void*>(&error)) &&
            func_region_ok(reinterpret_cast<const void*>(&integrity_check)) &&
            func_region_ok(reinterpret_cast<const void*>(&check_section_integrity));

        if (!heavy_ok) {
            const int streak = heavy_fail_streak.fetch_add(1) + 1;
            if (streak >= 2) {
                error(XorStr("security checks failed, possible tamper detected."));
            }
        } else {
            heavy_fail_streak.store(0);
        }
        {
            std::uintptr_t text_base = 0;
            size_t text_size = 0;
            if (get_text_section_info(text_base, text_size) && text_base && text_size) {
                const auto* text_ptr = reinterpret_cast<const uint8_t*>(text_base);
                const uint32_t crc_now = rolling_crc32(text_ptr, text_size);
                const uint32_t crc_base = text_crc_baseline.load();
                if (crc_base != 0 && crc_now != crc_base) {
                    error(XorStr(".text rolling crc mismatch."));
                }
            }
        }

        if (!compare_text_to_disk()) {
            error(XorStr("memory .text mismatch vs disk image."));
        }

        if (export_mismatch("KERNEL32.dll", "LoadLibraryA") ||
            export_mismatch("KERNEL32.dll", "GetProcAddress") ||
            export_mismatch("WINHTTP.dll", "WinHttpGetDefaultProxyConfiguration") ||
            export_mismatch("WINTRUST.dll", "WinVerifyTrust")) {
            error(XorStr("export mismatch detected."));
        }

        if (hotpatch_prologue_present(&WinVerifyTrust) ||
            hotpatch_prologue_present(&WinHttpGetDefaultProxyConfiguration)) {
            error(XorStr("hotpatch prologue detected."));
        }

        if (ntdll_syscall_stub_tampered("NtQueryInformationProcess") ||
            ntdll_syscall_stub_tampered("NtProtectVirtualMemory")) {
            error(XorStr("ntdll syscall stub tampered."));
        }

        if (nearby_trampoline_present(&curl_easy_perform) ||
            nearby_trampoline_present(&curl_easy_setopt)) {
            error(XorStr("trampoline near api detected."));
        }

        if (iat_hook_suspect("KERNEL32.dll", "LoadLibraryA") ||
            iat_hook_suspect("KERNEL32.dll", "GetProcAddress") ||
            iat_hook_suspect("WINHTTP.dll", "WinHttpGetDefaultProxyConfiguration") ||
            iat_hook_suspect("WINTRUST.dll", "WinVerifyTrust")) {
            error(XorStr("iat hook detected."));
        }

        if (!iat_integrity_ok()) {
            error(XorStr("iat integrity check failed."));
        }

        if (!critical_modules_safe()) {
            error(XorStr("critical module path violation."));
        }

        HMODULE curl = GetModuleHandleW(L"libcurl.dll");
        if (curl) {
            std::wstring p;
            if (get_module_path(curl, p)) {
                uint32_t now_crc = file_crc32(p);
                uint32_t base_crc = curl_crc_baseline.load();
                if (base_crc != 0 && now_crc != base_crc) {
                    error(XorStr("libcurl checksum mismatch."));
                }
            }
        }

        HMODULE sodium = GetModuleHandleW(L"libsodium.dll");
        if (sodium) {
            std::wstring p;
            if (get_module_path(sodium, p)) {
                uint32_t now_crc = file_crc32(p);
                uint32_t base_crc = sodium_crc_baseline.load();
                if (base_crc != 0 && now_crc != base_crc) {
                    error(XorStr("libsodium checksum mismatch."));
                }
            }
        }

periodic_done:
        if (check_section_integrity(XorStr(".text").c_str(), false)) {
            const int streak = integrity_fail_streak.fetch_add(1) + 1;
            if (streak >= 2) {
                error(XorStr("check_section_integrity() failed, don't tamper with the program."));
            }
        } else {
            integrity_fail_streak.store(0);
        }
    }
    if (!prologues_ok()) {
        error(XorStr("function prologue check failed, possible inline hook detected."));
    }
    if (!func_region_ok(reinterpret_cast<const void*>(&VerifyPayload)) ||
        !func_region_ok(reinterpret_cast<const void*>(&checkInit)) ||
        !func_region_ok(reinterpret_cast<const void*>(&error)) ||
        !func_region_ok(reinterpret_cast<const void*>(&integrity_check)) ||
        !func_region_ok(reinterpret_cast<const void*>(&check_section_integrity))) {
        error(XorStr("function region check failed, possible hook detected."));
    }
    integrity_check();
}

void integrity_check() {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto last = last_integrity_check.load();
    if (now - last > 30) {
        last_integrity_check.store(now);
        if (suspicious_processes_present() || suspicious_modules_present() || suspicious_windows_present()) {
            error(XorStr("debugger/emulator/proxy detected."));
        }
        if (check_section_integrity(XorStr(".text").c_str(), false)) {
            error(XorStr("check_section_integrity() failed, don't tamper with the program."));
        }
    }
}

// code submitted in pull request from https://github.com/BINM7MD
BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    }
    return (*szMask) == NULL;
}
DWORD64 FindPattern(BYTE* bMask, const char* szMask)
{
    MODULEINFO mi{ };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

    DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
    const auto dwModuleSize = mi.SizeOfImage;

    for (auto i = 0ul; i < dwModuleSize; i++)
    {
        if (bDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
            return DWORD64(dwBaseAddress + i);
    }
    return NULL;
}

DWORD64 Function_Address;
void modify()
{
    check_section_integrity( XorStr( ".text" ).c_str( ), true );

    while (true)
    {
        #if KEYAUTH_HAVE_KILLEMU
        protection::init();
        #endif
        // ^ check for jumps, break points (maybe useless), return address.

        if ( check_section_integrity( XorStr( ".text" ).c_str( ), false ) )
        {
            error(XorStr("check_section_integrity() failed, don't tamper with the program."));
        }
        // code submitted in pull request from https://github.com/sbtoonz, authored by KeePassXC https://github.com/keepassxreboot/keepassxc/blob/dab7047113c4ad4ffead944d5c4ebfb648c1d0b0/src/core/Bootstrap.cpp#L121
        if(!LockMemAccess())
        {
            error(XorStr("LockMemAccess() failed, don't tamper with the program."));
        }
        // code submitted in pull request from https://github.com/BINM7MD
        if (Function_Address == NULL) {
            Function_Address = FindPattern(PBYTE("\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x49\x8b\xf0"), XorStr("xxxx?xxxx????xxx").c_str()) - 0x5;
        }
        BYTE Instruction = *(BYTE*)Function_Address;

        if ((DWORD64)Instruction == 0xE9) {
            error(XorStr("Pattern checksum failed, don't tamper with the program."));
        }
        Sleep(50);
    }
}

// Clean up seed data (file and registry key)
void cleanUpSeedData(const std::string& seed) {

    // Clean up the seed file
    std::string file_path = "C:\\ProgramData\\" + seed;
    if (std::filesystem::exists(file_path)) {
        std::filesystem::remove(file_path);
    }

    // Clean up the seed registry entry
    std::string regPath = "Software\\" + seed;
    RegDeleteKeyA(HKEY_CURRENT_USER, regPath.c_str()); 
}
