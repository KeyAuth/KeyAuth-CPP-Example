#include <Windows.h>
#include "auth.hpp"
#include "skStr.h"
#include "utils.hpp"
#include <chrono>
#include <ctime>
#include <iostream>
#include <limits>
#include <string>

using namespace KeyAuth;

namespace {
constexpr int kInitFailSleepMs = 1500;
constexpr int kBadInputSleepMs = 3000;
constexpr int kCloseSleepMs = 5000;

std::string tm_to_readable_time(std::tm ctx);
std::time_t string_to_timet(const std::string& timestamp);
std::tm timet_to_tm(time_t timestamp);
std::string remaining_until(const std::string& timestamp);

bool read_int(int& out) {
    std::cin >> out;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return false; // bad input read. -nigel
    }
    return true;
}

void print_user_data(const api& app) {
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << app.user_data.username;
    std::cout << skCrypt("\n IP address: ") << app.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << app.user_data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(app.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(app.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < app.user_data.subscriptions.size(); i++) {
        const auto& sub = app.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
        std::cout << skCrypt(" (") << remaining_until(sub.expiry) << skCrypt(")");
    }
}
} // namespace

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

std::string name = skCrypt("name").decrypt();
std::string ownerid = skCrypt("ownerid").decrypt();
std::string secret = skCrypt("secret").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt(); // optional, set a path if you're using the token validation setting

api KeyAuthApp(name, ownerid, secret, version, url, path);

int main()
{
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(kInitFailSleepMs);
        exit(1);
    }

    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear(); // reduce exposure in memory. -nigel

    std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

    int option = 0;
    std::string username;
    std::string password;
    std::string key;

    if (!read_int(option))
    {
        std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
        Sleep(kBadInputSleepMs);
        exit(1);
    }

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
        Sleep(kBadInputSleepMs);
        exit(1);
    }

    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(kInitFailSleepMs);
        exit(1);
    }

    print_user_data(KeyAuthApp);

    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(kCloseSleepMs);

    return 0;
}

std::string tm_to_readable_time(std::tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

std::time_t string_to_timet(const std::string& timestamp) {
    char* end = nullptr;
    auto cv = strtol(timestamp.c_str(), &end, 10);
    if (end == timestamp.c_str())
        return 0; // invalid timestamp returns epoch. -nigel
    return static_cast<time_t>(cv);
}

std::tm timet_to_tm(time_t timestamp) {
    std::tm context;
    localtime_s(&context, &timestamp);
    return context;
}

std::string remaining_until(const std::string& timestamp) {
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
