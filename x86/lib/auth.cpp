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

#include <ctime>
#include <filesystem>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")

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

#include "Security.hpp"
#include "killEmulator.hpp"
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
bool prologues_ok();
bool func_region_ok(const void* addr);
bool timing_anomaly_detected();
void start_heartbeat(KeyAuth::api* instance);
void heartbeat_thread(KeyAuth::api* instance);
void snapshot_text_hashes();
bool text_hashes_ok();
bool detour_suspect(const uint8_t* p);
bool import_addresses_ok();
void snapshot_text_page_protections();
bool text_page_protections_ok();
 
inline void secure_zero(std::string& value) noexcept;
inline void securewipe(std::string& value) noexcept;
std::string seed;
void cleanUpSeedData(const std::string& seed);
std::string signature;
std::string signatureTimestamp;
bool initialized;
std::string API_PUBLIC_KEY = "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b";
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
std::atomic<int> heavy_fail_streak{ 0 };

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
    seed = generate_random_number();
    std::atexit([]() { cleanUpSeedData(seed); });
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

    if (sodium_hex2bin(sig, sizeof(sig), signature.c_str(), signature.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse signature hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid signature format)", "KeyAuth", MB_ICONERROR);
        exit(5);
    }

    if (sodium_hex2bin(pk, sizeof(pk), API_PUBLIC_KEY.c_str(), API_PUBLIC_KEY.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse public key hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid public key)", "KeyAuth", MB_ICONERROR);
        exit(6);
    }

    /*std::cout << "[DEBUG] Timestamp: " << timestamp << std::endl;
    std::cout << "[DEBUG] Signature: " << signature << std::endl;
    std::cout << "[DEBUG] Body: " << body << std::endl;
    std::cout << "[DEBUG] Message (timestamp + body): " << message << std::endl;
    std::cout << "[DEBUG] Public Key: " << API_PUBLIC_KEY << std::endl;*/

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
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 172) {
        const uint8_t b3 = static_cast<uint8_t>((a >> 8) & 0xFF);
        if (b3 >= 16 && b3 <= 31) return true;
    }
    return false;
}

static bool is_loopback_ipv6(const in6_addr& addr)
{
    static const in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
    return std::memcmp(&addr, &loopback, sizeof(loopback)) == 0;
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

static bool proxy_env_set()
{
    const char* keys[] = { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" };
    for (const char* k : keys) {
        const char* v = std::getenv(k);
        if (v && *v)
            return true;
    }
    return false;
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
        if (line.find(host_lower) == std::string::npos)
            continue;
        // basic whole-word check
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
        if (host_is_keyauth(host_lower)) {
            if (is_ip_literal(host_lower)) {
                error(XorStr("API host must not be an IP literal."));
            }
            if (proxy_env_set() || winhttp_proxy_set()) {
                error(XorStr("Proxy settings detected for API host."));
            }
            bool has_public = false;
            if (host_resolves_private_only(host_lower, has_public) && !has_public) {
                error(XorStr("API host resolves to private or loopback."));
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
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr("keyauth.win").c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req_headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "KeyAuth");

    // Perform the request
    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        std::string errorMsg = "CURL Error: " + std::string(curl_easy_strerror(code));
        if (req_headers) curl_slist_free_all(req_headers);
        curl_easy_cleanup(curl);
        error(errorMsg);
    }

    if (KeyAuth::api::debug) {
        debugInfo("n/a", "n/a", to_return, "n/a");
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

void checkInit() {
    if (!initialized) {
        error(XorStr("You need to run the KeyAuthApp.init(); function before any other KeyAuth functions"));
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
            import_addresses_ok() &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&VerifyPayload)) &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&checkInit)) &&
            !detour_suspect(reinterpret_cast<const uint8_t*>(&error)) &&
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
    // code submitted in pull request from https://github.com/Roblox932
    check_section_integrity( XorStr( ".text" ).c_str( ), true );

    while (true)
    {
        // new code by https://github.com/LiamG53
        protection::init();
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
