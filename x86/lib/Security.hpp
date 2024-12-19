#pragma once
#include <Windows.h>
#include <string>
#include <accctrl.h>
#include <aclapi.h>
#include <bcrypt.h>

// code submitted in pull request from https://github.com/sbtoonz, authored by KeePassXC https://github.com/keepassxreboot/keepassxc/blob/dab7047113c4ad4ffead944d5c4ebfb648c1d0b0/src/core/Bootstrap.cpp#L121
inline bool LockMemAccess()
{
    bool bSuccess = false;
    // Process token and user
    HANDLE hToken = nullptr;
    PTOKEN_USER pTokenUser = nullptr;
    DWORD cbBufferSize = 0;
 
    // Access control list
    PACL pACL = nullptr;
    DWORD cbACL = 0;
 
    // Open the access token associated with the calling process
    if (!OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY,
        &hToken
    )) {
        goto Cleanup;
    }
 
    // Retrieve the token information in a TOKEN_USER structure
    GetTokenInformation(
        hToken,
        TokenUser,  // request for a TOKEN_USER structure
        nullptr,
        0,
        &cbBufferSize
    );
 
    pTokenUser = static_cast<PTOKEN_USER>(malloc(cbBufferSize));
    if (pTokenUser == nullptr) {
        goto Cleanup;
    }
 
    if (!GetTokenInformation(
        hToken,
        TokenUser,
        pTokenUser,
        cbBufferSize,
        &cbBufferSize
    )) {
        goto Cleanup;
    }
 
    if (!IsValidSid(pTokenUser->User.Sid)) {
        goto Cleanup;
    }
 
    // Calculate the amount of memory that must be allocated for the DACL
    cbACL = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pTokenUser->User.Sid);
 
    // Create and initialize an ACL
    pACL = static_cast<PACL>(malloc(cbACL));
    if (pACL == nullptr) {
        goto Cleanup;
    }
 
    if (!InitializeAcl(pACL, cbACL, ACL_REVISION)) {
        goto Cleanup;
    }
 
    // Add allowed access control entries, everything else is denied
    if (!AddAccessAllowedAce(
        pACL,
        ACL_REVISION,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,    // same as protected process
        pTokenUser->User.Sid                                                    // pointer to the trustee's SID
    )) {
        goto Cleanup;
    }
 
    // Set discretionary access control list
    bSuccess = ERROR_SUCCESS == SetSecurityInfo(
        GetCurrentProcess(),        // object handle
        SE_KERNEL_OBJECT,           // type of object
        DACL_SECURITY_INFORMATION,  // change only the objects DACL
        nullptr, nullptr,           // do not change owner or group
        pACL,                       // DACL specified
        nullptr                     // do not change SACL
    );
 
Cleanup:
 
    if (pACL != nullptr) {
        free(pACL);
 
    }
    if (pTokenUser != nullptr) {
        free(pTokenUser);
 
    }
    if (hToken != nullptr) {
        CloseHandle(hToken);
 
    }
    return bSuccess;
}