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

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include <functional>
#include <vector>
#include <bitset>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )
#include <thread>
#include "hmac_sha256.h"

#include <cctype>
#include <algorithm>

#include "Security.hpp"
#include "integrity.h"

#define SHA256_HASH_SIZE 32

static std::string hexDecode(const std::string& hex);
std::string get_str_between_two_str(const std::string& s, const std::string& start_delim, const std::string& stop_delim);
bool constantTimeStringCompare(const char* str1, const char* str2, size_t length);
void checkInit();
std::string checksum();
void debugInfo(std::string data, std::string url, std::string response);
void modify();
void error(std::string message);
std::string signature;
bool initalized;

void KeyAuth::api::init()
{
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)modify, 0, 0, 0);

    if (ownerid.length() != 10 || secret.length() != 64)
    {
        MessageBoxA(0, XorStr("Application Not Setup Correctly. Please Watch Video Linked in main.cpp").c_str(), NULL, MB_ICONERROR);
        exit(0);
    }

    UUID uuid = { 0 };
    std::string guid;
    ::UuidCreate(&uuid);
    RPC_CSTR szUuid = NULL;
    if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
    {
        guid = (char*)szUuid;
        ::RpcStringFreeA(&szUuid);
    }
    std::string sentKey;
    sentKey = guid.substr(0, 16);
    enckey = sentKey + XorStr("-") + secret;

    std::string hash = checksum();
    CURL* curl = curl_easy_init();
    auto data =
        XorStr("type=init") +
        XorStr("&ver=") + version +
        XorStr("&hash=") + hash +
        XorStr("&enckey=") + sentKey +
        XorStr("&name=") + curl_easy_escape(curl, name.c_str(), 0) +
        XorStr("&ownerid=") + ownerid;

    if (path != "" || !path.empty()) {

        if (!std::filesystem::exists(path)) {
			MessageBoxA(0, XorStr("File not found. Please make sure the file exists.").c_str(), NULL, MB_ICONERROR);
			exit(0);
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

        thash =  exec(("certutil -hashfile \"" + path + XorStr("\" MD5 | find /i /v \"md5\" | find /i /v \"certutil\"")).c_str());

        data += XorStr("&token=").c_str() + token;
        data += XorStr("&thash=").c_str() + path;
    }
    curl_easy_cleanup(curl);

    auto response = req(data, url);

    if (response == XorStr("KeyAuth_Invalid")) {
        MessageBoxA(0, XorStr("Application not found. Please copy strings directly from dashboard.").c_str(), NULL, MB_ICONERROR);
        exit(0);
    }

    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(secret.data(), secret.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }
    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);

    if (json[(XorStr("success"))])
    {
        if (json[(XorStr("newSession"))]) {
            Sleep(100);
        }
        sessionid = json[(XorStr("sessionid"))];
        initalized = true;
        load_app_data(json[(XorStr("appinfo"))]);
    }
    else if (json[(XorStr("message"))] == XorStr("invalidver"))
    {
        std::string dl = json[(XorStr("download"))];
        if (dl == "")
        {
            MessageBoxA(0, XorStr("Version in the loader does match the one on the dashboard, and the download link on dashboard is blank.\n\nTo fix this, either fix the loader so it matches the version on the dashboard. Or if you intended for it to have different versions, update the download link on dashboard so it will auto-update correctly.").c_str(), NULL, MB_ICONERROR);
        }
        else
        {
            ShellExecuteA(0, XorStr("open").c_str(), dl.c_str(), 0, 0, SW_SHOWNORMAL);
        }
        exit(0);
    }
}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    // thanks to https://stackoverflow.com/q/28537837 and https://stackoverflow.com/a/66660987
    std::string temp = std::string(buffer);
    if (temp.substr(0, 9) == "signature") {
        std::string parsed = temp.erase(0, 11);; // remove "signature: "  from string 
        signature = parsed.substr(0, 64); // if I don't this, there's an extra line. so yeah.
    }
    std::string* headers = (std::string*)userdata;
    headers->append(buffer, nitems * size);
    return nitems * size;
}

void KeyAuth::api::login(std::string username, std::string password)
{
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=login") +
        XorStr("&username=") + username +
        XorStr("&pass=") + password +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    if (json[(XorStr("success"))])
        load_user_data(json[(XorStr("info"))]);
}

void KeyAuth::api::chatget(std::string channel)
{
    checkInit();

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
    return json[("success")];
}

void KeyAuth::api::changeUsername(std::string newusername)
{
    checkInit();

    auto data =
        XorStr("type=changeUsername") +
        XorStr("&newUsername=") + newusername +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);

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
        exit(0);
    }
    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for Initialize", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    // Create server session.
    HTTP_SERVER_SESSION_ID serverSessionId;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Version for session invalid", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "pServerSessionId parameter is null", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateServerSession", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    // Create URL group.
    HTTP_URL_GROUP_ID groupId;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Url group create parameter error", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateUrlGroup", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    // Create request queue.
    HANDLE requestQueueHandle;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Wrong version", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Byte length exceeded", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "pName already used", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, "queue access denied", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_DLL_INIT_FAILED) {
        MessageBoxA(NULL, "Initialize not called", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateRequestQueue", "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info;
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("Invalid parameter").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpSetUrlGroupProperty").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    // Add URLs to URL group.
    PCWSTR url = L"http://localhost:1337/handshake";
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, XorStr("No permissions to run web server").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, XorStr("You are running this program already").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("ERROR_INVALID_PARAMETER for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result == ERROR_SHARING_VIOLATION) {
        MessageBoxA(NULL, XorStr("Another program is using the webserver. Close Razer Chroma mouse software if you use that. Try to restart computer.").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        exit(0);
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
        BYTE* buffer = new BYTE[requestSize];
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
        RtlZeroMemory(buffer, requestSize);
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

            delete[]buffer;
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
        auto json = response_decoder.parse(resp);
        std::string message = json[(XorStr("message"))];

        // from https://github.com/h5p9sl/hmac_sha256
        std::stringstream ss_result;

        // Allocate memory for the HMAC
        std::vector<uint8_t> out(SHA256_HASH_SIZE);

        // Call hmac-sha256 function
        hmac_sha256(enckey.data(), enckey.size(), resp.data(), resp.size(),
            out.data(), out.size());

        // Convert `out` to string with std::hex
        for (uint8_t x : out) {
            ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
        }

        if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
            error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
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

        delete []buffer;

        if (!success)
            exit(0);
    }
}

void KeyAuth::api::button(std::string button)
{
    checkInit();

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
        BYTE* buffer = new BYTE[requestSize];
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
        RtlZeroMemory(buffer, requestSize);
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

        delete[]buffer;
    }
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key, std::string email) {
    checkInit();

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
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    if (json[(XorStr("success"))])
        load_user_data(json[(XorStr("info"))]);
}

void KeyAuth::api::upgrade(std::string username, std::string key) {
    checkInit();

    auto data =
        XorStr("type=upgrade") +
        XorStr("&username=") + username +
        XorStr("&key=") + key +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    json[(XorStr("success"))] = false;
    load_response_data(json);
}

void KeyAuth::api::license(std::string key) {
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=license") +
        XorStr("&key=") + key +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    if (json[(XorStr("success"))])
        load_user_data(json[(XorStr("info"))]);
}

void KeyAuth::api::setvar(std::string var, std::string vardata) {
    checkInit();

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

    auto data =
        XorStr("type=getvar") +
        XorStr("&var=") + var +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
}

void KeyAuth::api::ban(std::string reason) {
    checkInit();

    auto data =
        XorStr("type=ban") +
        XorStr("&reason=") + reason +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
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
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }
    return json[("success")];
}

void KeyAuth::api::check() {
    checkInit();

    auto data =
        XorStr("type=check") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
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
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    return json[(XorStr("message"))];
}

void KeyAuth::api::log(std::string message) {
    checkInit();

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

    auto to_uc_vector = [](std::string value) {
        return std::vector<unsigned char>(value.data(), value.data() + value.length() );
    };


    auto data =
        XorStr("type=file") +
        XorStr("&fileid=") + fileid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=").c_str() + ownerid;

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

    CURL *curl = curl_easy_init();
    auto data =
        XorStr("type=webhook") +
        XorStr("&webid=") + id +
        XorStr("&params=") + curl_easy_escape(curl, params.c_str(), 0) +
        XorStr("&body=") + curl_easy_escape(curl, body.c_str(), 0) +
        XorStr("&conttype=") + contenttype +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    curl_easy_cleanup(curl);
    auto response = req(data, url);
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    // from https://github.com/h5p9sl/hmac_sha256
    std::stringstream ss_result;

    // Allocate memory for the HMAC
    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    // Call hmac-sha256 function
    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    // Convert `out` to string with std::hex
    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);
    return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
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
    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    std::stringstream ss_result;

    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    std::string onlineusers;

    int y = atoi(api::app_data.numOnlineUsers.c_str());
    for (int i = 0; i < y; i++)
    {
        onlineusers.append(json[XorStr("users")][i][XorStr("credential")]); onlineusers.append(XorStr("\n"));
    }

    return onlineusers;
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

    auto json = response_decoder.parse(response);
    std::string message = json[(XorStr("message"))];

    std::stringstream ss_result;

    std::vector<uint8_t> out(SHA256_HASH_SIZE);

    hmac_sha256(enckey.data(), enckey.size(), response.data(), response.size(),
        out.data(), out.size());

    for (uint8_t x : out) {
        ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
    }

    if (!constantTimeStringCompare(ss_result.str().c_str(), signature.c_str(), sizeof(signature).c_str())) { // check response authenticity, if not authentic program crashes
        error("Signature checksum failed. Request was tampered with or session ended most likely. & echo: & echo Message: " + message);
    }

    load_response_data(json);

    if (json[(XorStr("success"))])
        load_app_data(json[(XorStr("appinfo"))]);
}

void KeyAuth::api::forgot(std::string username, std::string email)
{
    checkInit();

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
    unsigned first_delim_pos = s.find(start_delim);
    unsigned end_pos_of_first_delim = first_delim_pos + start_delim.length();
    unsigned last_delim_pos = s.find(stop_delim);

    return s.substr(end_pos_of_first_delim,
        last_delim_pos - end_pos_of_first_delim);
}

std::string KeyAuth::api::req(std::string data, std::string url) {
    CURL* curl = curl_easy_init();
    if (!curl)
        return XorStr("null");

    std::string to_return;
    std::string headers;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1);

    curl_easy_setopt(curl, CURLOPT_NOPROXY, ( "keyauth.win" ) );

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &to_return);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);

    auto code = curl_easy_perform(curl);

    if (code != CURLE_OK)
        error(curl_easy_strerror(code));

    debugInfo(data, url, to_return);

    struct curl_certinfo* ci;
    code = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);

    if (!code) {
        bool issuer_found = false;

        for (int i = 0; i < ci->num_of_certs; i++) {
            struct curl_slist* slist;

            for (slist = ci->certinfo[i]; slist; slist = slist->next) {
                if (std::strstr(slist->data, XorStr("Google Trust Services").c_str()) != NULL || std::strstr(slist->data, XorStr("Let's Encrypt").c_str()) != NULL) {
                    issuer_found = true;
                }
            }
        }

        if (!issuer_found)
            error(XorStr("SSL certificate couldn't be verified"));
    }

    return to_return;
}
void error(std::string message) {
    system(("start cmd /C \"color b && title Error && echo " + message + " && timeout /t 5\"").c_str());
    __fastfail(0);
}
// code submitted in pull request from https://github.com/Roblox932
#if defined(__x86_64__) || defined(_M_X64)
    auto check_section_integrity(const char* section_name, bool fix = false) -> bool
    {
        const auto map_file = [](HMODULE hmodule) -> std::tuple<std::uintptr_t, HANDLE>
            {
                wchar_t filename[MAX_PATH];
                DWORD size = MAX_PATH;
                QueryFullProcessImageName(GetCurrentProcess(), 0, filename, &size);


                const auto file_handle = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                if (!file_handle || file_handle == INVALID_HANDLE_VALUE)
                {
                    return { 0ull, nullptr };
                }

                const auto file_mapping = CreateFileMapping(file_handle, 0, PAGE_READONLY, 0, 0, 0);
                if (!file_mapping)
                {
                    CloseHandle(file_handle);
                    return { 0ull, nullptr };
                }

                return { reinterpret_cast<std::uintptr_t>(MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0)), file_handle };
            };

        const auto hmodule = GetModuleHandle(0);
        if (!hmodule) return true;

        const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
        if (!base_0) return true;

        const auto dos_0 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
        if (dos_0->e_magic != IMAGE_DOS_SIGNATURE) return true;

        const auto nt_0 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos_0->e_lfanew);
        if (nt_0->Signature != IMAGE_NT_SIGNATURE) return true;

        auto section_0 = IMAGE_FIRST_SECTION(nt_0);

        const auto [base_1, file_handle] = map_file(hmodule);
        if (!base_1 || !file_handle || file_handle == INVALID_HANDLE_VALUE) return true;

        const auto dos_1 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_1);
        if (dos_1->e_magic != IMAGE_DOS_SIGNATURE)
        {
            UnmapViewOfFile(reinterpret_cast<void*>(base_1));
            CloseHandle(file_handle);
            return true;
        }

        const auto nt_1 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_1 + dos_1->e_lfanew);
        if (nt_1->Signature != IMAGE_NT_SIGNATURE ||
            nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
            nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections)
        {
            UnmapViewOfFile(reinterpret_cast<void*>(base_1));
            CloseHandle(file_handle);
            return true;
        }

        auto section_1 = IMAGE_FIRST_SECTION(nt_1);

        bool patched = false;
        for (auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1)
        {
            if (strcmp(reinterpret_cast<char*>(section_0->Name), section_name) ||
                !(section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            for (auto i = 0u; i < section_0->SizeOfRawData; ++i)
            {
                const auto old_value = *reinterpret_cast<BYTE*>(base_1 + section_1->PointerToRawData + i);

                if (*reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + i) == old_value)
                {
                    continue;
                }

                if (fix)
                {
                    DWORD new_protect{ PAGE_EXECUTE_READWRITE }, old_protect;
                    VirtualProtect((void*)(base_0 + section_0->VirtualAddress + i), sizeof(BYTE), new_protect, &old_protect);
                    *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + i) = old_value;
                    VirtualProtect((void*)(base_0 + section_0->VirtualAddress + i), sizeof(BYTE), old_protect, &new_protect);
                }

                patched = true;
            }

            break;
        }

        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_handle);

        return patched;
    }
#elif defined(__i386) || defined(_M_IX86)
    // code submitted in pull request from https://github.com/autumnlikescode authored by https://github.com/Vasie1337/integrity-check
    auto check_section_integrity() {
        _integrity_check check;
        return check.check_integrity();
    }
#endif

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

bool constantTimeStringCompare(const char* str1, const char* str2, size_t length) {
    int result = 0;

    for (size_t i = 0; i < length; ++i) {
        result |= str1[i] ^ str2[i];
    }

    return result == 0;
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

void debugInfo(std::string data, std::string url, std::string response) {

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
    RedactField(responses, "secret");
    RedactField(responses, "version");
    RedactField(responses, "fileid");
    RedactField(responses, "webhooks");
    std::string redacted_response = responses.dump();

    //turn data into json
    std::replace(data.begin(), data.end(), '&', ' ');

    nlohmann::json datas;

    std::istringstream iss(data);
    std::vector<std::string> results((std::istream_iterator<std::string>(iss)),
        std::istream_iterator<std::string>());

    for (auto const& value : results) {
        datas[value.substr(0, value.find('='))] = value.substr(value.find('=') + 1);
    }

    RedactField(datas, "sessionid");
    RedactField(datas, "ownerid");
    RedactField(datas, "app");
    RedactField(datas, "name");
    RedactField(datas, "key");
    RedactField(datas, "username");
    RedactField(datas, "password");
    RedactField(datas, "contents");
    RedactField(datas, "secret");
    RedactField(datas, "version");
    RedactField(datas, "fileid");
    RedactField(datas, "webhooks");

    std::string redacted_data = datas.dump();


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

    if (response.length() >= 200) { return; }

    //now time for my life to end yay :skull:

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

    std::string contents = "\n\n@ " + currentTimeString + "\nData sent : " + redacted_data + "\nResponse : " + redacted_response + "Sent to: " + url;

    logfile << contents;

    logfile.close();
}

void checkInit() {
    if (!initalized) {
        error("You need to run the KeyAuthApp.init(); function before any other KeyAuth functions");
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

#if defined(__x86_64__) || defined(_M_X64)
    DWORD64 Function_Address;
    void modify()
    {
        // code submitted in pull request from https://github.com/Roblox932
        check_section_integrity(XorStr(".text").c_str(), true);

        while (true)
        {
            if (check_section_integrity(XorStr(".text").c_str(), false))
            {
                error("check_section_integrity() failed, don't tamper with the program.");
            }
            // code submitted in pull request from https://github.com/sbtoonz, authored by KeePassXC https://github.com/keepassxreboot/keepassxc/blob/dab7047113c4ad4ffead944d5c4ebfb648c1d0b0/src/core/Bootstrap.cpp#L121
            if (!LockMemAccess())
            {
                error("LockMemAccess() failed, don't tamper with the program.");
            }
            // code submitted in pull request from https://github.com/BINM7MD
            if (Function_Address == NULL) {
                Function_Address = FindPattern(PBYTE("\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x49\x8b\xf0"), XorStr("xxxx?xxxx????xxx").c_str()) - 0x5;
            }
            BYTE Instruction = *(BYTE*)Function_Address;

            if ((DWORD64)Instruction == 0xE9) {
                error("Pattern checksum failed, don't tamper with the program.");
            }
            Sleep(50);
        }
    }
#elif defined(__i386) || defined(_M_IX86)
// code submitted in pull request from https://github.com/autumnlikescode authored by https://github.com/Vasie1337/integrity-check
    void modify() {
        while (true) {
            if (check_section_integrity()) {
                error(XorStr("check_section_integrity() failed, don't tamper with the program."));
            }
        }
    }
#endif
