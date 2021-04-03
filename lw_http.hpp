#pragma once

#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment( lib, "winhttp.lib" )

#define LWHTTP_USER_AGENT L"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
#define LWHTTP_CONT_TYPE L"Content-Type: application/x-www-form-urlencoded"

namespace lw_http_tools
{
	bool			is_base64(BYTE u_ch);
	std::string		encode_base64(const char* psz_input);
	std::string		decode_base64(std::string const& s_input);

	std::string		url_encode(std::string const& s_input);
	std::string		url_decode(std::string const& s_input);
}

class c_lw_httpd
{
private:
	std::string m_s_data_;

	void		fmt_out(const PCHAR pszFieldName, const PCHAR pszFmt, ...);

public:
	void		clear(void);

	void		add_field(const PCHAR pszName, const char* pszValue);

	DWORD		get_size(void) const;
	const char* get_data(void) const;
};

class c_lw_http
{
private:
	HINTERNET	m_h_session_;
	PWCHAR		m_psz_referer_;
	PWCHAR		m_psz_user_agent_;
	DWORD		m_dw_last_reply_size_;

private:
	static void	parse_url_a(std::wstring& s_url, std::wstring& s_srv, std::wstring& s_obj, INTERNET_PORT& w_port);
	bool	send_request(std::wstring s_url, std::vector<BYTE>& bt_reply, PWCHAR psz_type, LPVOID p_data, DWORD dw_data_len);
	static DWORD	read_req_reply(HINTERNET hRequest, std::vector<BYTE>& btReply);

public:
	c_lw_http(void);
	~c_lw_http(void);

	bool	open_session(void);
	void	close_session(void) const;

	bool	set_referer(PWCHAR pszReferer);
	PWCHAR	get_referer(void) const;

	bool	set_user_agent(PWCHAR pszUserAgent);
	PWCHAR	get_user_agent(void) const;

	DWORD	get_last_re_size(void) { return m_dw_last_reply_size_; }

	bool	get(std::wstring sURL, std::string& s_reply);
	bool	get(std::wstring s_url, std::vector<BYTE>& btReply);

	bool	post(std::wstring sURL, std::string& sReply, c_lw_httpd& PostData);
	bool	post(std::wstring sURL, std::vector<BYTE>& btReply, c_lw_httpd& PostData);
};