#include <Windows.h>
#include "auth.hpp"
#include <string>
#include <thread>
#include "utils.hpp"
#include "skStr.h"
#include <iostream>
#include <filesystem> // file checks for saved creds. -nigel
#include <limits> // input validation helpers. -nigel
#include <chrono> // date math for expiry display. -nigel
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
static std::string remaining_until(std::string timestamp); // human readable expiry countdown. -nigel
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace KeyAuth;

// copy and paste from https://keyauth.cc/app/ and replace these string variables
// Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
std::string name = skCrypt("name").decrypt(); // App name
std::string ownerid = skCrypt("ownerid").decrypt(); // Account ID
std::string version = skCrypt("1.0").decrypt(); // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt(); // change if using KeyAuth custom domains feature
std::string path = skCrypt("").decrypt(); // (OPTIONAL) see tutorial here https://www.youtube.com/watch?v=I9rxt821gMk&t=1s


api KeyAuthApp(name, ownerid, version, url, path);

int main()
{
    // clear plaintext config copies after api init below. -nigel
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }
    name.clear(); ownerid.clear(); version.clear(); url.clear(); path.clear(); // reduce exposure of config strings. -nigel

    std::string username, password, key, TfaCode; // keep this before the auto-login with saved file.
    // because if you don't and the user has 2FA on, then they won't be asked for 2FA code and can't login.

    const std::string save_path = "test.json"; // keep consistent with existing example file. -nigel
    bool used_saved_creds = false; // track whether we auto-logged in. -nigel
    if (std::filesystem::exists(save_path))
    {
        // only trust saved data if it parses cleanly and is non-empty. -nigel
        const auto saved_license = ReadFromJson(save_path, "license");
        const auto saved_username = ReadFromJson(save_path, "username");
        const auto saved_password = ReadFromJson(save_path, "password");

        if (!saved_license.empty())
        {
            key = saved_license;
            KeyAuthApp.license(key);
            used_saved_creds = true;
        }
        else if (!saved_username.empty() && !saved_password.empty())
        {
            username = saved_username;
            password = saved_password;
            KeyAuthApp.login(username, password);
            used_saved_creds = true;
        }
    }

    if (!used_saved_creds)
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option;

        std::cin >> option;
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection"); // bad input path. -nigel
            Sleep(3000);
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
            Sleep(3000);
            exit(1);
        }
    }

    if (KeyAuthApp.response.message.empty()) exit(11);
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

            if (KeyAuthApp.response.message.empty()) exit(11);
            if (!KeyAuthApp.response.success) {
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                std::remove("test.json");
                Sleep(1500);
                exit(1);
            }
        }
        else {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            std::remove("test.json");
            Sleep(1500);
            exit(1);
        }
    }

    bool save_creds = false; // opt-in to disk storage to reduce exposure. -nigel
    std::cout << skCrypt("\n\n Save credentials to disk for auto-login? [y/N]: ");
    char save_choice = 'n';
    std::cin >> save_choice;
    if (std::cin.fail())
    {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        save_choice = 'n'; // default to no on bad input. -nigel
    }
    save_creds = (save_choice == 'y' || save_choice == 'Y');

    if (save_creds)
    {
        if (username.empty() || password.empty())
        {
            WriteToJson(save_path, "license", key, false, "", "");
        }
        else
        {
            WriteToJson(save_path, "username", username, true, "password", password);
        }
        std::cout << skCrypt("Successfully Created File For Auto Login");
    }
    else
    {
        std::remove(save_path.c_str()); // remove stale creds if user opts out. -nigel
    }

    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.

    //enable 2FA 
    // KeyAuthApp.enable2fa(); you will need to ask for the code
    //enable 2fa without the need of asking for the code
    //KeyAuthApp.enable2fa().handleInput(KeyAuthApp);

    //disbale 2FA
    // KeyAuthApp.disable2fa();

    if (KeyAuthApp.user_data.username.empty()) exit(10);
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << KeyAuthApp.user_data.username;
    std::cout << skCrypt("\n IP address: ") << KeyAuthApp.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.user_data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
        std::cout << skCrypt(" (") << remaining_until(sub.expiry) << skCrypt(")"); // show time remaining. -nigel
    }


    std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.response.message;


    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);

    return 0;
}

void sessionStatus() {
    KeyAuthApp.check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    char* end = nullptr;
    auto cv = strtol(timestamp.c_str(), &end, 10);
    if (end == timestamp.c_str())
        return 0; // invalid timestamp returns epoch. -nigel
    return static_cast<time_t>(cv);
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}

static std::string remaining_until(std::string timestamp) {
    const auto expiry = string_to_timet(timestamp);
    const auto now = std::time(nullptr);
    if (expiry <= now)
        return "expired"; // already expired. -nigel
    auto diff = std::chrono::seconds(expiry - now);
    auto days = std::chrono::duration_cast<std::chrono::hours>(diff).count() / 24;
    auto weeks = days / 7;
    auto months = days / 30;
    auto years = days / 365;
    std::string out;
    if (years > 0) out += std::to_string(years) + "y ";
    if (months > 0) out += std::to_string(months % 12) + "mo ";
    if (weeks > 0) out += std::to_string(weeks % 4) + "w ";
    out += std::to_string(days % 7) + "d";
    return out;
}
