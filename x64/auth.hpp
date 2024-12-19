#include <includes.hpp>
#include <xorstr.hpp>
#include <random>

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

		api(std::string name, std::string ownerid, std::string version, std::string url, std::string path) : name(name), ownerid(ownerid), version(version), url(url), path(path) {}

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
		void enable2fa(std::string code = "");
		void disable2fa(std::string code);

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
			std::vector<channel_struct> channeldata;
			bool success{};
			std::string message;
			bool isPaid{};
		};

		userdata user_data;
		appdata app_data;
		responsedata response;
	private:
		std::string sessionid, enckey;

		static std::string req(std::string data, std::string url);
		

		void load_user_data(nlohmann::json data) {
			api::user_data.username = data[XorStr("username")];
			api::user_data.ip = data[XorStr("ip")];
			if (data[XorStr("hwid")].is_null()) {
				api::user_data.hwid = XorStr("none");
			}
			else {
				api::user_data.hwid = data[XorStr("hwid")];
			}
			api::user_data.createdate = data[XorStr("createdate")];
			api::user_data.lastlogin = data[XorStr("lastlogin")];

			for (int i = 0; i < data[XorStr("subscriptions")].size(); i++) { // Prompto#7895 & stars#2297 was here
				subscriptions_class subscriptions;
				subscriptions.name = data[XorStr("subscriptions")][i][XorStr("subscription")];
				subscriptions.expiry = data[XorStr("subscriptions")][i][XorStr("expiry")];
				api::user_data.subscriptions.emplace_back(subscriptions);
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
			api::response.success = data["success"]; // intentional. Possibly trick a reverse engineer into thinking this string is for login function
			api::response.message = data["message"];
			api::response.channeldata.clear(); //If you do not delete the data before pushing it, the data will be repeated. github.com/TTakaTit
			for (const auto sub : data["messages"]) {

				std::string authoroutput = sub[XorStr("author")];
				std::string messageoutput = sub["message"];
				int timestamp = sub[XorStr("timestamp")]; std::string timestampoutput = std::to_string(timestamp);
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
