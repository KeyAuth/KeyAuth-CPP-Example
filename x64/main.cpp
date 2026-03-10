#include <Windows.h>
#include "auth.hpp"
#include "auth_guard.hpp"
#include "skStr.h"
#include "storage.hpp"
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#undef max

using namespace KeyAuth;

std::string tm_to_readable_time(std::tm ctx);
std::string remaining_until(const std::string& timestamp);

namespace {

std::tm timestamp_to_tm(const std::string& timestamp) {
    const std::time_t raw = static_cast<std::time_t>(std::strtoll(timestamp.c_str(), nullptr, 10));
    std::tm result{};
    localtime_s(&result, &raw);
    return result;
}

void init_fail_delay() {
    Sleep(api::kInitFailSleepMs);
}

void bad_input_delay() {
    Sleep(api::kBadInputSleepMs);
}

void close_delay() {
    Sleep(api::kCloseSleepMs);
}

bool lockout_active(const api::lockout_state& state) {
    return std::chrono::steady_clock::now() < state.locked_until;
}

int lockout_remaining_ms(const api::lockout_state& state) {
    if (!lockout_active(state))
        return 0;

    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            state.locked_until - std::chrono::steady_clock::now()).count());
}

void record_login_fail(api::lockout_state& state, int max_attempts = 3, int lock_seconds = 30) {
    if (lockout_active(state))
        return;

    ++state.fails;
    if (state.fails >= max_attempts) {
        state.fails = 0;
        state.locked_until = std::chrono::steady_clock::now() + std::chrono::seconds(lock_seconds);
    }
}

void reset_lockout(api::lockout_state& state) {
    state.fails = 0;
    state.locked_until = std::chrono::steady_clock::time_point{};
}

std::string expiry_remaining(const std::string& expiry) {
    const std::time_t expiry_time = static_cast<std::time_t>(std::strtoll(expiry.c_str(), nullptr, 10));
    const std::time_t now = std::time(nullptr);

    if (expiry_time <= 0 || expiry_time <= now)
        return "expired";

    long long remaining = static_cast<long long>(expiry_time - now);
    const long long days = remaining / 86400;
    remaining %= 86400;
    const long long hours = remaining / 3600;
    remaining %= 3600;
    const long long minutes = remaining / 60;
    const long long seconds = remaining % 60;

    std::string result;
    if (days > 0)
        result += std::to_string(days) + "d ";
    if (days > 0 || hours > 0)
        result += std::to_string(hours) + "h ";
    if (days > 0 || hours > 0 || minutes > 0)
        result += std::to_string(minutes) + "m ";
    result += std::to_string(seconds) + "s";
    return result;
}

bool read_int(int& out) {
    std::cin >> out;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return false; // bad input read. -nigel
    }
    return true;
}

char read_choice(char fallback) {
    char choice = fallback;
    std::cin >> choice;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        choice = fallback; // default on bad input. -nigel
    }
    return choice;
}

bool try_auto_login(api& app, std::string& username, std::string& password, std::string& key) {
    if (!std::filesystem::exists(api::kSavePath))
        return false;

    const auto saved_license = ReadFromJson(api::kSavePath, "license");
    const auto saved_username = ReadFromJson(api::kSavePath, "username");
    const auto saved_password = ReadFromJson(api::kSavePath, "password");

    if (!saved_license.empty()) {
        key = saved_license;
        app.license(key);
        return true;
    }

    if (!saved_username.empty() && !saved_password.empty()) {
        username = saved_username;
        password = saved_password;
        app.login(username, password);
        return true;
    }

    return false;
}

void save_or_clear_creds(bool save, const std::string& username, const std::string& password, const std::string& key) {
    if (!save) {
        std::remove(api::kSavePath); // remove stale creds when opting out. -nigel
        return;
    }

    if (username.empty() || password.empty()) {
        WriteToJson(api::kSavePath, "license", key, false, "", "");
        return;
    }

    WriteToJson(api::kSavePath, "username", username, true, "password", password);
}

void print_user_data(const api& app) {
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << app.user_data.username;
    std::cout << skCrypt("\n IP address: ") << app.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << app.user_data.hwid;
    std::cout << skCrypt("\n Create date: ")
              << tm_to_readable_time(timestamp_to_tm(app.user_data.createdate));
    std::cout << skCrypt("\n Last login: ")
              << tm_to_readable_time(timestamp_to_tm(app.user_data.lastlogin));
    std::cout << skCrypt("\n Subscription(s): ");

    for (size_t i = 0; i < app.user_data.subscriptions.size(); i++) {
        const auto& sub = app.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ")
                  << tm_to_readable_time(timestamp_to_tm(sub.expiry));
        std::cout << skCrypt(" (") << remaining_until(sub.expiry) << skCrypt(")");
    }
}
} // namespace

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

// copy and paste from https://keyauth.cc/app/ and replace these string variables
// Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
std::string name = skCrypt("name").decrypt(); // App name
std::string ownerid = skCrypt("ownerid").decrypt(); // Account ID
std::string version = skCrypt("1.0").decrypt(); // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt(); // change if using KeyAuth custom domains feature
std::string path = skCrypt("").decrypt(); // (OPTIONAL) see tutorial here https://www.youtube.com/watch?v=I9rxt821gMk&t=1s

api KeyAuthApp(name, ownerid, version, url, path);
api::lockout_state login_guard{};

int main()
{
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        init_fail_delay();
        exit(1);
    }

    const std::string ownerid_copy = ownerid; // preserve for auth check thread. -nigel
    name.clear(); ownerid.clear(); version.clear(); url.clear(); path.clear();

    if (lockout_active(login_guard)) {
        std::cout << skCrypt("\n Status: Too many attempts. Try again in ")
                  << lockout_remaining_ms(login_guard) << skCrypt(" ms.");
        close_delay();
        return 0;
    }

    std::string username;
    std::string password;
    std::string key;
    std::string TfaCode;

    const bool used_saved_creds = try_auto_login(KeyAuthApp, username, password, key);

    if (!used_saved_creds)
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option = 0;
        if (!read_int(option))
        {
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            bad_input_delay();
            exit(1);
        }

        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password, "");
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.license(key, "");
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            bad_input_delay();
            exit(1);
        }
    }

    if (KeyAuthApp.response.message.empty())
        exit(11);

    if (!KeyAuthApp.response.success)
    {
        if (KeyAuthApp.response.message == "2FA code required.") {
            if (username.empty() || password.empty()) {
                std::cout << skCrypt("\n Your account has 2FA enabled, please enter 6-digit code:");
                std::cin >> TfaCode;
                KeyAuthApp.license(key, TfaCode);
            }
            else {
                std::cout << skCrypt("\n Your account has 2FA enabled, please enter 6-digit code:");
                std::cin >> TfaCode;
                KeyAuthApp.login(username, password, TfaCode);
            }

            if (KeyAuthApp.response.message.empty())
                exit(11);
            if (!KeyAuthApp.response.success) {
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                std::remove(api::kSavePath);
                record_login_fail(login_guard);
                init_fail_delay();
                exit(1);
            }
        }
        else {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            std::remove(api::kSavePath);
            record_login_fail(login_guard);
            init_fail_delay();
            exit(1);
        }
    }
    reset_lockout(login_guard);

    std::cout << skCrypt("\n\n Save credentials to disk for auto-login? [y/N]: ");
    const char save_choice = read_choice('n'); // read once to avoid double input. -nigel
    const bool save_creds = (save_choice == 'y' || save_choice == 'Y');
    save_or_clear_creds(save_creds, username, password, key);
    if (save_creds)
        std::cout << skCrypt("Successfully Created File For Auto Login");

    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid_copy);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.
    run.detach(); // detach immediately to avoid terminate on early exits. -nigel
    check.detach(); // detach immediately to avoid terminate on early exits. -nigel

    //enable 2FA 
    // KeyAuthApp.enable2fa(); you will need to ask for the code
    //enable 2fa without the need of asking for the code
    //KeyAuthApp.enable2fa().handleInput(KeyAuthApp);

    //disbale 2FA
    // KeyAuthApp.disable2fa();

    if (KeyAuthApp.user_data.username.empty())
        exit(10);

    print_user_data(KeyAuthApp);

    std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.response.message;
    std::cout << skCrypt("\n\n Closing in five seconds...");
    close_delay();

    return 0;
}

void sessionStatus() {
    KeyAuthApp.check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!KeyAuthApp.response.success) {
        return; // allow clean exit from thread. -nigel
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                return; // allow clean exit from thread. -nigel
            }
        }
    }
}

std::string tm_to_readable_time(std::tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

std::string remaining_until(const std::string& timestamp) {
    return expiry_remaining(timestamp);
}
