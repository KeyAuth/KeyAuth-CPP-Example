#include <includes.hpp>

#pragma comment(lib, "libcurl.lib")

#if defined(__x86_64__) || defined(_M_X64)
	#pragma comment(lib, "libcurl.lib")
#elif defined(__i386) || defined(_M_IX86)
	#pragma comment(lib, "libcurl86.lib")
#endif

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

		std::string name, ownerid, secret, version, url, path;

		api(std::string name, std::string ownerid, std::string secret, std::string version, std::string url, std::string path = "") : name(name), ownerid(ownerid), secret(secret), version(version), url(url), path(path) {}

		void ban(std::string reason = "");
		void init();
		void check();
		void log(std::string msg);
		void license(std::string key);
		std::string var(std::string varid);
		std::string webhook(std::string id, std::string params, std::string body = "", std::string contenttype = "");
		void setvar(std::string var, std::string vardata);
		std::string getvar(std::string var);
		bool checkblack();
		void web_login();
		void button(std::string value);
		void upgrade(std::string username, std::string key);
		void login(std::string username, std::string password);
		std::vector<unsigned char> download(std::string fileid);
		void regstr(std::string username, std::string password, std::string key, std::string email = "");
		void chatget(std::string channel);
		bool chatsend(std::string message, std::string channel);
		void changeUsername(std::string newusername);
		std::string fetchonline();
		void fetchstats();
		void forgot(std::string username, std::string email);
		void logout();

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
		};

		class responsedata {
		public:
			// response data
			std::vector<channel_struct> channeldata{};
			bool success;
			std::string message;
		};

		userdata user_data;
		appdata app_data;
		responsedata response;
	private:
		std::string sessionid, enckey;

		static std::string req(std::string data, std::string url);
		

		void load_user_data(nlohmann::json data) {
			api::user_data.username = data["username"];
			api::user_data.ip = data["ip"];
			if (data["hwid"].is_null()) {
				api::user_data.hwid = "none";
			}
			else {
				api::user_data.hwid = data["hwid"];
			}
			api::user_data.createdate = data["createdate"];
			api::user_data.lastlogin = data["lastlogin"];

			for (int i = 0; i < data["subscriptions"].size(); i++) { // Prompto#7895 & stars#2297 was here
				subscriptions_class subscriptions;
				subscriptions.name = data["subscriptions"][i]["subscription"];
				subscriptions.expiry = data["subscriptions"][i]["expiry"];
				api::user_data.subscriptions.emplace_back(subscriptions);
			}
		}

		void load_app_data(nlohmann::json data) {
			api::app_data.numUsers = data["numUsers"];
			api::app_data.numOnlineUsers = data["numOnlineUsers"];
			api::app_data.numKeys = data["numKeys"];
			api::app_data.version = data["version"];
			api::app_data.customerPanelLink = data["customerPanelLink"];
		}

		void load_response_data(nlohmann::json data) {
			api::response.success = data["success"];
			api::response.message = data["message"];
		}

		void load_channel_data(nlohmann::json data) {
			api::response.success = data["success"];
			api::response.message = data["message"];
			for (const auto sub : data["messages"]) {

				std::string authoroutput = sub["author"];
				std::string messageoutput = sub["message"];
				int timestamp = sub["timestamp"]; std::string timestampoutput = std::to_string(timestamp);
				authoroutput.erase(remove(authoroutput.begin(), authoroutput.end(), '"'), authoroutput.end());
				messageoutput.erase(remove(messageoutput.begin(), messageoutput.end(), '"'), messageoutput.end());
				timestampoutput.erase(remove(timestampoutput.begin(), timestampoutput.end(), '"'), timestampoutput.end());
				channel_struct output = { authoroutput , messageoutput, timestampoutput };
				api::response.channeldata.push_back(output);
			}
		}

		nlohmann::json response_decoder;

	};
}
