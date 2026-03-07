#include <includes.hpp>
#include <xorstr.hpp>
#include <random>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>

#define CURL_STATICLIB 

struct channel_struct
{
	std::string author;
	std::string message;
	std::string timestamp;
};

namespace KeyAuth {
	class api {
	public:

		std::string name, ownerid, version, url, path; 
		static bool debug;

		api(std::string name, std::string ownerid, std::string version, std::string url, std::string path, bool debugParameter = false) 
		: name(name), ownerid(ownerid), version(version), url(url), path(path)
		{
		    setDebug(debugParameter);
		}

		void ban(std::string reason = "");
		void init();
		void check(bool check_paid = false);
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
		bool block_proxy = false;
		bool block_custom_ca = false;
		bool block_private_dns = false;
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
	private:

		std::string sessionid, enckey;
		std::vector<std::string> allowed_hosts;
		std::vector<std::string> pinned_public_keys;
		std::string req(std::string data, const std::string& url);
		static void debugInfo(std::string data, std::string url, std::string response, std::string headers);
		static void setDebug(bool value);
		

		void load_user_data(nlohmann::json data) {
			const std::string key_username = XorStr("username");
			const std::string key_ip = XorStr("ip");
			const std::string key_hwid = XorStr("hwid");
			const std::string key_created = XorStr("createdate");
			const std::string key_lastlogin = XorStr("lastlogin");
			const std::string key_subs = XorStr("subscriptions");
			const std::string key_sub_name = XorStr("subscription");
			const std::string key_sub_expiry = XorStr("expiry");
			api::user_data.username = data.value(key_username, "");
			api::user_data.ip = data.value(key_ip, "");
			if (!data.contains(key_hwid) || data[key_hwid].is_null()) {
				api::user_data.hwid = XorStr("none");
			}
			else {
				api::user_data.hwid = data[key_hwid];
			}
			api::user_data.createdate = data.value(key_created, "");
			api::user_data.lastlogin = data.value(key_lastlogin, "");

			api::user_data.subscriptions.clear();
			if (data.contains(key_subs) && data[key_subs].is_array()) {
				for (const auto& sub : data[key_subs]) {
					subscriptions_class subscriptions;
					if (sub.contains(key_sub_name))
						subscriptions.name = sub.value(key_sub_name, "");
					if (sub.contains(key_sub_expiry))
						subscriptions.expiry = sub.value(key_sub_expiry, "");
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
