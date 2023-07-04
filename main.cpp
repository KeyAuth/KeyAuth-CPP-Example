#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

std::string name = skCrypt("").decrypt(); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = skCrypt("").decrypt(); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = skCrypt("").decrypt(); // app secret, the blurred text on licenses tab and other tabs
std::string version = skCrypt("1.0").decrypt(); // leave alone unless you've changed version on website
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting

/*
    KeyAuth.cc C++ example

    Setup tutorial https://www.youtube.com/watch?v=uJ0Umy_C6Fg go to https://keyauth.cc/app/, select C++, and copy into here

    Video on how to add KeyAuth to your own application https://www.youtube.com/watch?v=GB4XW_TsHqA

    Video to use Web Loader (control loader from customer panel) https://www.youtube.com/watch?v=9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url);

int main()
{
    std::string consoleTitle = (std::string)skCrypt("Loader - Built at:  ") + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");
    KeyAuthApp.init();
    if (!KeyAuthApp.data.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
        Sleep(1500);
        exit(0);
    }

    if (std::filesystem::exists("test.json")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            std::string key = ReadFromJson("test.json", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.data.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
                Sleep(1500);
                exit(0);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("test.json", "username");
            std::string password = ReadFromJson("test.json", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.data.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
                Sleep(1500);
                exit(0);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
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
            KeyAuthApp.license(key);
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(0);
        }

        if (!KeyAuthApp.data.success)
        {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.data.message;
            Sleep(1500);
            exit(0);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson("test.json", "license", key, false, "", "");
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("test.json", "username", username, true, "password", password);
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }


    }
    
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << KeyAuthApp.data.username;
    std::cout << skCrypt("\n IP address: ") << KeyAuthApp.data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < KeyAuthApp.data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
    }

    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);
    exit(0);
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}
