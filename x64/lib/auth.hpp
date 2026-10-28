#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <includes.hpp>
#include <xorstr.hpp>
#include <random>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>
#include <stdexcept>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <sstream>
#include <cstring>
#include <climits>
#include <ws2tcpip.h>

#define CURL_STATICLIB 

#include <string>
#include <algorithm>
#include <cctype>

namespace keyauth_detail {
struct SignatureHeaders {
    std::string signature;
    std::string timestamp;
    bool conflicting = false;
};

// libcurl may deliver CONNECT, informational, final and trailer header blocks.
// Only the current response's values may authenticate its body.
inline bool consume_header(SignatureHeaders& out, std::string line) {
    if (line.rfind("HTTP/", 0) == 0) {
        out = {};
        return true;
    }
    const auto colon = line.find(':');
    if (colon == std::string::npos) return true;
    std::string key = line.substr(0, colon);
    std::transform(key.begin(), key.end(), key.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string* target = nullptr;
    if (key == "x-signature-ed25519") target = &out.signature;
    if (key == "x-signature-timestamp") target = &out.timestamp;
    if (!target) return true;
    std::string value = line.substr(colon + 1);
    const auto first = value.find_first_not_of(" \t\r\n");
    const auto last = value.find_last_not_of(" \t\r\n");
    value = first == std::string::npos ? "" : value.substr(first, last - first + 1);
    if (!target->empty() && *target != value) out.conflicting = true;
    *target = value;
    return true;
}
}

#include <sodium.h>
#include <string>
#include <algorithm>
#include <cstdlib>

namespace keyauth_detail {
inline bool auth_window_fresh(long long sealed, long long current) {
    return sealed > 0 && current >= sealed && current - sealed <= 2;
}
enum class PayloadResult { valid, timestamp_format, timestamp_skew, sodium_init,
                           signature_format, public_key_format, invalid_signature };
inline PayloadResult verify_payload(const std::string& signature,
    const std::string& timestamp, const std::string& body,
    const std::string& public_key, long long now_seconds) {
    if ((timestamp.size() != 10 && timestamp.size() != 13) ||
        !std::all_of(timestamp.begin(), timestamp.end(),
                     [](unsigned char c) { return c >= '0' && c <= '9'; }))
        return PayloadResult::timestamp_format;
    long long seconds = std::stoll(timestamp);
    if (timestamp.size() == 13) seconds /= 1000;
    if (std::llabs(now_seconds - seconds) > 120) return PayloadResult::timestamp_skew;
    if (sodium_init() < 0) return PayloadResult::sodium_init;
    unsigned char sig[crypto_sign_BYTES] = {};
    unsigned char pk[crypto_sign_PUBLICKEYBYTES] = {};
    size_t size = 0;
    if (signature.size() != sizeof(sig) * 2 ||
        sodium_hex2bin(sig, sizeof(sig), signature.data(), signature.size(),
                       nullptr, &size, nullptr) != 0 || size != sizeof(sig))
        return PayloadResult::signature_format;
    if (public_key.size() != sizeof(pk) * 2 ||
        sodium_hex2bin(pk, sizeof(pk), public_key.data(), public_key.size(),
                       nullptr, &size, nullptr) != 0 || size != sizeof(pk))
        return PayloadResult::public_key_format;
    const std::string message = timestamp + body;
    return crypto_sign_verify_detached(sig,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(), pk) == 0
        ? PayloadResult::valid : PayloadResult::invalid_signature;
}
}

#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <array>
#include <stdexcept>
#include <string>
#pragma comment(lib, "bcrypt.lib")

namespace keyauth_detail {
// MD5 is retained solely for the API's existing executable/token hash fields.
// Authentication is provided by TLS and Ed25519, not this compatibility digest.
inline std::string file_md5(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open file for API checksum.");
    struct Provider {
        BCRYPT_ALG_HANDLE handle = nullptr;
        ~Provider() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    } provider;
    struct Hash {
        BCRYPT_HASH_HANDLE handle = nullptr;
        ~Hash() { if (handle) BCryptDestroyHash(handle); }
    } hash;
    if (BCryptOpenAlgorithmProvider(&provider.handle, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(provider.handle, &hash.handle, nullptr, 0, nullptr, 0, 0) < 0)
        throw std::runtime_error("Cannot initialize API checksum.");
    std::array<unsigned char, 16384> buffer{};
    while (input.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || input.gcount()) {
        if (BCryptHashData(hash.handle, buffer.data(), static_cast<ULONG>(input.gcount()), 0) < 0)
            throw std::runtime_error("Cannot hash API checksum input.");
    }
    if (!input.eof()) throw std::runtime_error("Cannot read API checksum input.");
    std::array<unsigned char, 16> digest{};
    if (BCryptFinishHash(hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
        throw std::runtime_error("Cannot finish API checksum.");
    const char* hex = "0123456789abcdef";
    std::string out;
    for (const auto value : digest) {
        out += hex[value >> 4]; out += hex[value & 15];
    }
    return out;
}
}


namespace keyauth_detail {
inline std::string canonical_host(std::string host) {
    std::transform(host.begin(), host.end(), host.begin(),
        [](unsigned char c) { return static_cast<char>(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c); });
    if (!host.empty() && host.back() == '.') host.pop_back();
    return host;
}

struct ApiEndpoint {
    std::string url;
    std::string host;
    int port = 443;
};

inline ApiEndpoint parse_api_endpoint(const std::string& input) {
    if (input.empty() || input.find_first_of("\r\n\t\\") != std::string::npos ||
        input.find('\0') != std::string::npos)
        throw std::invalid_argument("Invalid API URL.");
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> handle(curl_url(), curl_url_cleanup);
    if (!handle || curl_url_set(handle.get(), CURLUPART_URL, input.c_str(), CURLU_DISALLOW_USER) != CURLUE_OK)
        throw std::invalid_argument("Invalid API URL or URL credentials.");
    auto part = [&](CURLUPart field, unsigned flags = 0) {
        char* raw = nullptr;
        const auto code = curl_url_get(handle.get(), field, &raw, flags);
        std::unique_ptr<char, decltype(&curl_free)> value(raw, curl_free);
        return code == CURLUE_OK && raw ? std::string(raw) : std::string();
    };
    if (canonical_host(part(CURLUPART_SCHEME)) != "https" || !part(CURLUPART_FRAGMENT).empty())
        throw std::invalid_argument("API URL must use HTTPS without a fragment.");
    ApiEndpoint endpoint;
    endpoint.host = canonical_host(part(CURLUPART_HOST));
    const auto port = part(CURLUPART_PORT, CURLU_DEFAULT_PORT);
    if (endpoint.host.empty() || endpoint.host.size() > 253 || port != "443")
        throw std::invalid_argument("API URL requires a hostname and HTTPS port 443.");
    size_t label_length = 0;
    char previous = 0;
    for (unsigned char c : endpoint.host) {
        if (c == '.') {
            if (!label_length || label_length > 63 || previous == '-')
                throw std::invalid_argument("Invalid API hostname.");
            label_length = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') ||
                (!label_length && c == '-'))
                throw std::invalid_argument("Invalid API hostname.");
            ++label_length;
        }
        previous = static_cast<char>(c);
    }
    if (!label_length || label_length > 63 || previous == '-')
        throw std::invalid_argument("Invalid API hostname.");
    in_addr ipv4{};
    if (inet_pton(AF_INET, endpoint.host.c_str(), &ipv4) == 1)
        throw std::invalid_argument("API URL must use a DNS hostname.");
    if (curl_url_set(handle.get(), CURLUPART_HOST, endpoint.host.c_str(), 0) != CURLUE_OK)
        throw std::invalid_argument("Invalid API hostname.");
    endpoint.url = part(CURLUPART_URL);
    if (endpoint.url.empty()) throw std::invalid_argument("Invalid API URL.");
    return endpoint;
}

inline bool hosts_line_overrides(std::string line, const std::string& host) {
    const auto comment = line.find('#');
    if (comment != std::string::npos) line.resize(comment);
    std::istringstream tokens(line);
    std::string address;
    if (!(tokens >> address)) return false;
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, address.c_str(), &v4) != 1 &&
        inet_pton(AF_INET6, address.c_str(), &v6) != 1) return false;
    const auto expected = canonical_host(host);
    std::string alias;
    while (tokens >> alias) {
        if (canonical_host(alias) == expected) return true;
    }
    return false;
}

inline bool private_ipv4(uint32_t address) {
    const uint32_t value = ntohl(address);
    const unsigned a = value >> 24;
    const unsigned b = (value >> 16) & 255;
    return a == 0 || a == 10 || a == 127 || a >= 224 ||
        (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127) ||
        (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
        (a == 198 && (b == 18 || b == 19));
}

inline bool private_ipv6(const in6_addr& address) {
    if (IN6_IS_ADDR_UNSPECIFIED(&address) || IN6_IS_ADDR_LOOPBACK(&address) ||
        IN6_IS_ADDR_MULTICAST(&address) || IN6_IS_ADDR_LINKLOCAL(&address) ||
        IN6_IS_ADDR_SITELOCAL(&address) ||
        (address.u.Byte[0] & 0xfe) == 0xfc) return true;
    if (IN6_IS_ADDR_V4MAPPED(&address)) {
        uint32_t mapped = 0;
        std::memcpy(&mapped, address.u.Byte + 12, sizeof(mapped));
        return private_ipv4(mapped);
    }
    return false;
}

inline bool private_address(const std::string& input) {
    in_addr v4{};
    if (inet_pton(AF_INET, input.c_str(), &v4) == 1) return private_ipv4(v4.s_addr);
    in6_addr v6{};
    if (inet_pton(AF_INET6, input.c_str(), &v6) == 1) return private_ipv6(v6);
    return true;
}

inline bool loopback_address(const std::string& input) {
    in_addr v4{};
    if (inet_pton(AF_INET, input.c_str(), &v4) == 1) {
        const auto first = ntohl(v4.s_addr) >> 24;
        return first == 0 || first == 127;
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, input.c_str(), &v6) != 1) return true;
    if (IN6_IS_ADDR_UNSPECIFIED(&v6) || IN6_IS_ADDR_LOOPBACK(&v6)) return true;
    if (IN6_IS_ADDR_V4MAPPED(&v6)) {
        uint32_t mapped = 0;
        std::memcpy(&mapped, v6.u.Byte + 12, sizeof(mapped));
        const auto first = ntohl(mapped) >> 24;
        return first == 0 || first == 127;
    }
    return false;
}

inline bool connection_address_allowed(const std::string& ip, int port,
    bool using_proxy, bool restrict_private, bool allow_proxy = true) {
    if (using_proxy) return allow_proxy;
    return (port == 443 && !loopback_address(ip) &&
        (!restrict_private || !private_address(ip)));
}

inline bool hostname_matches(const std::string& host, const std::string& entry) {
    const auto expected = canonical_host(entry);
    if (expected.rfind("*.", 0) != 0) return canonical_host(host) == expected;
    const auto actual = canonical_host(host);
    const auto suffix = expected.substr(1);
    return actual.size() > suffix.size() &&
        actual.compare(actual.size() - suffix.size(), suffix.size(), suffix) == 0;
}
}


namespace keyauth_detail {
inline std::string json_text(const nlohmann::json& object, const std::string& key,
    const std::string& fallback = "") {
    if (!object.contains(key) || object[key].is_null()) return fallback;
    const auto& value = object[key];
    if (value.is_string()) return value.get<std::string>();
    if (value.is_number_integer() || value.is_number_unsigned()) return value.dump();
    throw std::invalid_argument("Invalid API field type: " + key);
}

inline void validate_api_reply(const nlohmann::json& data, const std::string& owner) {
    if (!data.is_object() || !data.contains("success") || !data["success"].is_boolean() ||
        !data.contains("message") || !data["message"].is_string())
        throw std::invalid_argument("Invalid API response structure.");
    if (data.contains("ownerid") && (!data["ownerid"].is_string() || data["ownerid"] != owner))
        throw std::invalid_argument("API response owner does not match the application.");
    if (data["success"].get<bool>() && data.contains("code") &&
        (!data["code"].is_number_integer() || data["code"] != 68))
        throw std::invalid_argument("Invalid API success code.");
}

inline bool magic_link_approved(const nlohmann::json& data) {
    if (!data.is_object() || !data.contains("success") || !data["success"].is_boolean() ||
        !data["success"].get<bool>()) return false;
    if (data.contains("authenticated") && data["authenticated"].is_boolean())
        return data["authenticated"].get<bool>();
    if (data.contains("status") && data["status"].is_string()) {
        const auto status = data["status"].get<std::string>();
        if (status == "approved" || status == "authenticated") return true;
        if (status == "pending" || status == "sent" || status == "expired" ||
            status == "denied" || status == "cancelled") return false;
    }
    if (data.contains("info") && data["info"].is_object() &&
        data["info"].contains("username") && data["info"]["username"].is_string() &&
        !data["info"]["username"].get<std::string>().empty()) return true;
    return data.value("message", std::string()) == "Logged in!";
}

inline bool email_request_uses_get(const std::string& type) {
    return type == "loginEmail" || type == "emailOTPSend" || type == "emailOTPVerify" ||
        type == "magicLinkSend" || type == "magicLinkCheck";
}

inline std::string email_request(const std::string& type, const std::string& email,
    const std::string& password, const std::string& code, const std::string& session,
    const std::string& name, const std::string& owner, const std::string& hwid) {
    if (!email_request_uses_get(type)) throw std::invalid_argument("Invalid email authentication operation.");
    if (email.empty()) throw std::invalid_argument("Email is required.");
    if (type == "emailOTPVerify" && (code.size() != 6 || !std::all_of(code.begin(), code.end(),
        [](unsigned char c) { return c >= '0' && c <= '9'; })))
        throw std::invalid_argument("Email verification code must contain six digits.");
    auto encode = [](const std::string& value) {
        if (value.empty()) return std::string();
        if (value.size() > INT_MAX) throw std::invalid_argument("API input is too large.");
        std::unique_ptr<char, decltype(&curl_free)> raw(
            curl_easy_escape(nullptr, value.data(), static_cast<int>(value.size())), curl_free);
        if (!raw) throw std::runtime_error("Could not encode API input.");
        return std::string(raw.get());
    };
    std::string request = "type=" + type + "&email=" + encode(email) + "&sessionid=" + encode(session) +
        "&name=" + encode(name) + "&ownerid=" + encode(owner);
    if (type != "emailOTPSend") request += "&hwid=" + encode(hwid);
    if (type == "loginEmail") request += "&pass=" + encode(password) + "&code=" + encode(code);
    if (type == "emailOTPVerify") request += "&code=" + encode(code);
    return request;
}

struct ResponseBuffer {
    std::string body;
    size_t limit;
    bool exceeded = false;
};

inline bool append_response(ResponseBuffer& output, const char* bytes, size_t count) {
    if (count > output.limit || output.body.size() > output.limit - count) {
        output.exceeded = true;
        return false;
    }
    output.body.append(bytes, count);
    return true;
}
}

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

namespace KeyAuth {
    // Network/server/signature errors reject the operation and can be retried by
    // the application after correcting the cause. Do not retry mutations blindly.
    class request_error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

	class api {
	public:

		std::string name, ownerid, version, url, path; 
		static bool debug;

		api(std::string name, std::string ownerid, std::string version, std::string url, std::string path, bool debugParameter = false) 
		: name(name), ownerid(ownerid), version(version), url(url), path(path)
		{
		    setDebug(debugParameter);
		}

		~api();
		void ban(std::string reason = "");
		void init();
		void check(bool check_paid = false);
        bool authenticated(bool require_paid = false) const;
		void log(std::string msg);
		void license(std::string key, std::string code = "");
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body = "", std::string contenttype = "");
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password, std::string code = "");
        void login_email(std::string email, std::string password, std::string code = "");
        void email_otp_send(std::string email);
        void email_otp_verify(std::string email, std::string code);
        void magic_link_send(std::string email);
        bool magic_link_check();
        bool magic_link_pending() const;
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key, std::string email = "");
		void chatget(std::string channel);
		bool chatsend(std::string message, std::string channel);
		void changeUsername(std::string newusername);
		std::string fetchonline();
		void fetchstats();
		void forgot(std::string username, std::string email);
		void logout();
		void start_ban_monitor(int interval_seconds = 45, bool check_session = false, std::function<void()> on_ban = {});
		void stop_ban_monitor();
		bool ban_monitor_running() const;
		bool ban_monitor_detected() const;
		bool require_pinning = false;
		bool block_custom_ca = false;
		bool block_private_dns = false;
        bool block_proxy = false;
        bool require_signed_downloads = true;
        size_t max_api_response_bytes = 8ULL * 1024 * 1024;
        size_t max_download_response_bytes = 512ULL * 1024 * 1024;
		static std::string expiry_remaining(const std::string& expiry);
		static constexpr const char* kSavePath = "test.json";
		static constexpr int kInitFailSleepMs = 1500;
		static constexpr int kBadInputSleepMs = 3000;
		static constexpr int kCloseSleepMs = 5000;
		struct lockout_state {
			int fails = 0;
			std::chrono::steady_clock::time_point locked_until{};
		};
		static void init_fail_delay();
		static void bad_input_delay();
		static void close_delay();
		static bool lockout_active(const lockout_state& state);
		static int lockout_remaining_ms(const lockout_state& state);
		static void record_login_fail(lockout_state& state, int max_attempts = 3, int lock_seconds = 30);
		static void reset_lockout(lockout_state& state);

		class subscriptions_class {
		public:
			std::string name;
			std::string expiry;
		};

		class userdata {
		public:

			// user data
			std::string username;
			std::string ip;
			std::string hwid;
			std::string createdate;
			std::string lastlogin;

			std::vector<subscriptions_class> subscriptions;
		};

		class appdata {
		public:
			// app data
			std::string numUsers;
			std::string numOnlineUsers;
			std::string numKeys;
			std::string version;
			std::string customerPanelLink;
			std::string downloadLink;
		};

		class responsedata {
		public:
			// response data
			std::vector<channel_struct> channeldata;
			bool success{};
			std::string message;
			bool isPaid{};
		};

		bool activate = false;
		class Tfa {
		public:
			std::string secret;
			std::string link;
			Tfa& handleInput(KeyAuth::api& apiInstance);
		private:
			void QrCode();
		};

		Tfa& enable2fa(std::string code = "");
		Tfa& disable2fa(std::string code = "");

		userdata user_data;
		appdata app_data;
		responsedata response;
		Tfa tfa;

		// Optional network hardening controls (do not require backend changes).
		void set_allowed_hosts(const std::vector<std::string>& hosts) { allowed_hosts = hosts; }
		void add_allowed_host(const std::string& host) { allowed_hosts.push_back(host); }
		void clear_allowed_hosts() { allowed_hosts.clear(); }

		void set_pinned_public_keys(const std::vector<std::string>& pins) { pinned_public_keys = pins; }
		void add_pinned_public_key(const std::string& pin) { pinned_public_keys.push_back(pin); }
		void clear_pinned_public_keys() { pinned_public_keys.clear(); }

		// Optional in-memory string protection. When enabled, public fields like
		// name/ownerid/version/url/path are wiped and only decrypted on demand.
		void enable_secure_strings(bool enable = true);
	private:

        void checkInit();
        void start_heartbeat();
        bool initialized = false;
        std::atomic<bool> LoggedIn{false};
        mutable std::recursive_mutex api_mutex_;
        std::mutex heartbeat_mutex_;
        std::condition_variable heartbeat_cv_;
        bool heartbeat_stop_ = false;
        std::thread heartbeat_thread_;
		std::string sessionid, enckey;
        std::string authenticated_host_;
        std::string magic_link_email_;
        std::chrono::steady_clock::time_point magic_link_started_{};
        std::chrono::steady_clock::time_point magic_link_last_check_{};
        nlohmann::json email_reply(std::string data);
        bool finish_email_login(const nlohmann::json& data, const std::string& email);
		std::vector<std::string> allowed_hosts;
		std::vector<std::string> pinned_public_keys;
		bool secure_strings_enabled_ = false;
		std::string name_enc_;
		std::string ownerid_enc_;
		std::string version_enc_;
		std::string url_enc_;
		std::string path_enc_;

		std::string get_name() const;
		std::string get_ownerid() const;
		std::string get_version() const;
		std::string get_url() const;
		std::string get_path() const;
		std::string protect_field(const std::string& in, bool encrypt) const;
		void reset_auth_runtime();
		void mark_authenticated();
		void refresh_auth_runtime();
		bool local_auth_valid(bool require_paid = false, bool require_fresh = true) const;
		bool has_active_subscription() const;
		uint64_t compute_auth_seal(uint64_t nonce, long long window) const;

		std::string req(std::string data, const std::string& url);
		static void debugInfo(std::string data, std::string url, std::string response, std::string headers);
		static void setDebug(bool value);
		std::atomic<uint64_t> auth_nonce_{ 0 };
        std::array<unsigned char, crypto_shorthash_KEYBYTES> auth_seal_key_{};
		std::atomic<long long> auth_window_{ 0 };
		std::atomic<uint64_t> auth_seal_{ 0 };
		

		void load_user_data(nlohmann::json data) {
			const std::string key_username = XorStr("username");
			const std::string key_ip = XorStr("ip");
			const std::string key_hwid = XorStr("hwid");
			const std::string key_created = XorStr("createdate");
			const std::string key_lastlogin = XorStr("lastlogin");
			const std::string key_subs = XorStr("subscriptions");
			const std::string key_sub_name = XorStr("subscription");
			const std::string key_sub_expiry = XorStr("expiry");
			api::user_data.username = keyauth_detail::json_text(data, key_username);
			api::user_data.ip = keyauth_detail::json_text(data, key_ip);
			if (!data.contains(key_hwid) || data[key_hwid].is_null()) {
				api::user_data.hwid = XorStr("none");
			}
			else {
				api::user_data.hwid = data[key_hwid];
			}
			api::user_data.createdate = keyauth_detail::json_text(data, key_created);
			api::user_data.lastlogin = keyauth_detail::json_text(data, key_lastlogin);

			api::user_data.subscriptions.clear();
			if (data.contains(key_subs) && data[key_subs].is_array()) {
				for (const auto& sub : data[key_subs]) {
					subscriptions_class subscriptions;
					if (sub.contains(key_sub_name))
						subscriptions.name = sub.value(key_sub_name, "");
					if (sub.contains(key_sub_expiry))
						subscriptions.expiry = keyauth_detail::json_text(sub, key_sub_expiry);
					api::user_data.subscriptions.emplace_back(subscriptions);
				}
			}
		}

		void load_app_data(nlohmann::json data) {
			api::app_data.numUsers = data[XorStr("numUsers")];
			api::app_data.numOnlineUsers = data[XorStr("numOnlineUsers")];
			api::app_data.numKeys = data[XorStr("numKeys")];
			api::app_data.version = data[XorStr("version")];
			api::app_data.customerPanelLink = data[XorStr("customerPanelLink")];
		}

		void load_response_data(nlohmann::json data) {
			api::response.success = data[XorStr("success")];
			api::response.message = data["message"];
			api::response.isPaid = false;

			if (data.contains(XorStr("role").c_str()) && data[XorStr("role")] != XorStr("tester").c_str() && data[XorStr("role")] != XorStr("not_checked").c_str()) {
				api::response.isPaid = true;
			}
		}

		void load_channel_data(nlohmann::json data) {
			api::response.success = data[XorStr("success")]; // intentional. Possibly trick a reverse engineer into thinking this string is for login function
			api::response.message = data["message"];
			api::response.channeldata.clear(); //If you do not delete the data before pushing it, the data will be repeated. github.com/TTakaTit
			if (!data.contains("messages") || !data["messages"].is_array()) {
				return; // avoid invalid server payload crash. -nigel
			}
			const std::string key_author = XorStr("author");
			const std::string key_timestamp = XorStr("timestamp");
			for (const auto& sub : data["messages"]) {
				if (!sub.is_object())
					continue;
				std::string authoroutput = sub.value(key_author, "");
				std::string messageoutput = sub.value("message", "");
				const int timestamp = sub.value(key_timestamp, 0);
				std::string timestampoutput = std::to_string(timestamp);
				authoroutput.erase(remove(authoroutput.begin(), authoroutput.end(), '"'), authoroutput.end());
				messageoutput.erase(remove(messageoutput.begin(), messageoutput.end(), '"'), messageoutput.end());
				timestampoutput.erase(remove(timestampoutput.begin(), timestampoutput.end(), '"'), timestampoutput.end());
				channel_struct output = { authoroutput , messageoutput, timestampoutput };
				api::response.channeldata.push_back(output);
			}
		}

		std::atomic<bool> ban_monitor_running_{ false };
		std::atomic<bool> ban_monitor_detected_{ false };
		std::thread ban_monitor_thread_;

		nlohmann::json response_decoder;

	};
}
