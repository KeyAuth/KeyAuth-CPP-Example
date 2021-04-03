#include "lw_http.hpp"

static const std::string g_s_base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

bool lw_http_tools::is_base64(const BYTE u_ch)
{
	return (isalnum(u_ch) || (u_ch == '+') || (u_ch == '/'));
}

std::string lw_http_tools::encode_base64(const char* psz_input)
{
	size_t uInputSize = strlen(psz_input);
	int I = 0;
	int J = 0;

	BYTE ucArray3[3];
	BYTE ucArray4[4];

	std::string sResult;

	while (uInputSize--)
	{
		ucArray3[I++] = *(psz_input++);

		if (I == 3)
		{
			ucArray4[0] = (ucArray3[0] & 0xfc) >> 2;
			ucArray4[1] = ((ucArray3[0] & 0x03) << 4) + ((ucArray3[1] & 0xf0) >> 4);
			ucArray4[2] = ((ucArray3[1] & 0x0f) << 2) + ((ucArray3[2] & 0xc0) >> 6);
			ucArray4[3] = ucArray3[2] & 0x3f;

			for (I = 0; (I < 4); I++)
				sResult += g_s_base64_chars[ucArray4[I]];
			I = 0;
		}
	}

	if (I)
	{
		for (J = I; J < 3; J++)
			ucArray3[J] = '\0';

		ucArray4[0] = (ucArray3[0] & 0xfc) >> 2;
		ucArray4[1] = ((ucArray3[0] & 0x03) << 4) + ((ucArray3[1] & 0xf0) >> 4);
		ucArray4[2] = ((ucArray3[1] & 0x0f) << 2) + ((ucArray3[2] & 0xc0) >> 6);
		ucArray4[3] = ucArray3[2] & 0x3f;

		for (J = 0; (J < I + 1); J++)
			sResult += g_s_base64_chars[ucArray4[J]];

		while ((I++ < 3))
			sResult += '=';
	}

	return sResult;
}

std::string lw_http_tools::decode_base64(std::string const& s_input)
{
	size_t uInputSize = s_input.size();
	int i = 0;
	int j = 0;
	int n_in = 0;

	BYTE uc_array3[3];
	BYTE uc_array4[4];

	std::string s_result;

	while (uInputSize-- && (s_input[n_in] != '=') && is_base64(s_input[n_in]))
	{
		uc_array4[i++] = s_input[n_in]; n_in++;

		if (i == 4)
		{
			for (i = 0; i < 4; i++)
				uc_array4[i] = g_s_base64_chars.find(uc_array4[i]);

			uc_array3[0] = (uc_array4[0] << 2) + ((uc_array4[1] & 0x30) >> 4);
			uc_array3[1] = ((uc_array4[1] & 0xf) << 4) + ((uc_array4[2] & 0x3c) >> 2);
			uc_array3[2] = ((uc_array4[2] & 0x3) << 6) + uc_array4[3];

			for (i = 0; i < 3; i++)
				s_result += uc_array3[i];

			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 4; j++)
			uc_array4[j] = 0;

		for (j = 0; j < 4; j++)
			uc_array4[j] = g_s_base64_chars.find(uc_array4[j]);

		uc_array3[0] = (uc_array4[0] << 2) + ((uc_array4[1] & 0x30) >> 4);
		uc_array3[1] = ((uc_array4[1] & 0xf) << 4) + ((uc_array4[2] & 0x3c) >> 2);
		uc_array3[2] = ((uc_array4[2] & 0x3) << 6) + uc_array4[3];

		for (j = 0; (j < i - 1); j++)
			s_result += uc_array3[j];
	}

	return s_result;
}

std::string lw_http_tools::url_encode(std::string const& s_input)
{
	std::string s_result;
	s_result.reserve(s_input.length());

	for (size_t I = 0; I < s_input.length(); ++I)
	{
		char ch = s_input[I];

		if ((ch < 33) || (ch > 126) || strchr("!\"#%&'*,:;<=>?[]^`{|} ", ch))
		{
			char sz_buffer[4];
			sprintf_s(sz_buffer, ("%%%02x"), ch & 0xFF);
			s_result += sz_buffer;
		}
		else
			s_result += ch;
	}

	return s_result;
}

std::string lw_http_tools::url_decode(std::string const& s_input)
{
	std::string s_result;
	s_result.reserve(s_input.length());

	char szBuffer[4];
	szBuffer[2] = '\0';

	const char* psz_input = s_input.c_str();

	while (*psz_input)
	{
		if (*psz_input == '%' && psz_input[1] && psz_input[2])
		{
			szBuffer[0] = psz_input[1];
			szBuffer[1] = psz_input[2];
			s_result += (char)(strtoul(szBuffer, NULL, 16));
			psz_input += 3;
		}
		else
		{
			s_result += *psz_input;
			++psz_input;
		}
	}

	return s_result;
}

///////////////////////////////////////////////////////////////////////////////

void c_lw_httpd::fmt_out(const PCHAR pszFieldName, const PCHAR pszFmt, ...)
{
	static char sz_value[2048];
	ZeroMemory(sz_value, sizeof(sz_value));

	va_list VAList;
	va_start(VAList, pszFmt);
	_vsnprintf_s(sz_value, sizeof(sz_value), pszFmt, VAList);
	va_end(VAList);

	std::string sValueEncoded = lw_http_tools::url_encode(sz_value);

	static char szOut[2048];
	ZeroMemory(szOut, sizeof(szOut));
	//sprintf_s( szOut, "&%s=%s", pszFieldName, szValue );
	sprintf_s(szOut, ("&%s=%s"), pszFieldName, sValueEncoded.c_str());

	m_s_data_ += szOut;
}

void c_lw_httpd::add_field(const PCHAR pszName, const char* pszValue)
{
	fmt_out(pszName, (PCHAR)("%s"), pszValue);
}

const char* c_lw_httpd::get_data(void) const
{
	return &(m_s_data_.data()[1]);
}

DWORD c_lw_httpd::get_size(void) const
{
	return m_s_data_.length() - 1;
}

void c_lw_httpd::clear(void)
{
	m_s_data_.clear();
}

///////////////////////////////////////////////////////////////////////////////

c_lw_http::c_lw_http(void) : m_dw_last_reply_size_(0)
{
	m_h_session_ = nullptr;
	m_psz_referer_ = (PWCHAR)L"";
	m_psz_user_agent_ = (PWCHAR)LWHTTP_USER_AGENT;
}

c_lw_http::~c_lw_http(void)
{
}

void c_lw_http::parse_url_a(std::wstring& s_url, std::wstring& s_srv, std::wstring& s_obj, INTERNET_PORT& w_port)
{
	s_srv = s_url;

	size_t uSrv = s_srv.find(L"://");
	if (uSrv != -1)
		s_srv.erase(0, uSrv + 3);

	s_obj = s_srv;

	uSrv = s_srv.find(L"/");
	if (uSrv != -1)
		s_srv.erase(uSrv);

	size_t uObj = s_obj.find(L"/");
	if (uObj != -1)
		s_obj.erase(0, uObj);
	else
		s_obj = L"/";

	if (s_url.find(L"https://") == -1)
		w_port = INTERNET_DEFAULT_PORT;
	else
		w_port = INTERNET_DEFAULT_HTTPS_PORT;
}

bool c_lw_http::send_request(std::wstring s_url, std::vector<BYTE>& bt_reply, const PWCHAR psz_type, const LPVOID p_data, const DWORD dw_data_len)
{
	bool b_result = false;

	if (!m_h_session_) return b_result;

	INTERNET_PORT w_srv_port = 0;
	std::wstring s_server, s_object;
	parse_url_a(s_url, s_server, s_object, w_srv_port);

	const HINTERNET h_connect = ::WinHttpConnect(m_h_session_, s_server.c_str(), w_srv_port, 0);
	if (!h_connect) return b_result;

	LPCWSTR psz_accept_types[2];
	psz_accept_types[0] = L"*/*";
	psz_accept_types[1] = NULL;


	const HINTERNET h_request = ::WinHttpOpenRequest(h_connect, psz_type,
		s_object.c_str(), L"HTTP/1.1", m_psz_referer_, psz_accept_types,
		w_srv_port == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0);
	if (!h_request) return b_result;

	DWORD dwOptionValue = WINHTTP_DISABLE_REDIRECTS;
	BOOL value = WinHttpSetOption(h_request, WINHTTP_OPTION_DISABLE_FEATURE, &dwOptionValue, sizeof(dwOptionValue));

	// Custom Header: Content-Type
	BOOL b_http_result = ::WinHttpAddRequestHeaders(h_request,
		LWHTTP_CONT_TYPE, -1, WINHTTP_ADDREQ_FLAG_ADD);
	if (!b_http_result) goto CleanUp;

	b_http_result = ::WinHttpSendRequest(h_request,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0, p_data, dw_data_len, dw_data_len, NULL);
	if (!b_http_result) goto CleanUp;

	b_http_result = ::WinHttpReceiveResponse(h_request, NULL);
	if (!b_http_result) goto CleanUp;

	if ((m_dw_last_reply_size_ = read_req_reply(h_request, bt_reply)))
		b_result = true;

CleanUp:
	if (h_request)
		::WinHttpCloseHandle(h_request);

	if (h_connect)
		::WinHttpCloseHandle(h_connect);

	return b_result;
}

DWORD c_lw_http::read_req_reply(HINTERNET hRequest, std::vector<BYTE>& btReply)
{
	if (!hRequest) return -1;

	DWORD dw_bytes_read = 0,
		dw_bytes_total = 0,
		dw_bytes_available = 0;

	char* psz_tmp_buffer = NULL;

	do
	{
		dw_bytes_available = dw_bytes_read = 0;

		if (!WinHttpQueryDataAvailable(hRequest, &dw_bytes_available) ||
			(dw_bytes_available <= 0))
			goto CleanUp;

		psz_tmp_buffer = (char*)(malloc(dw_bytes_available + 1));
		ZeroMemory(psz_tmp_buffer, dw_bytes_available + 1);

		if (!WinHttpReadData(hRequest, psz_tmp_buffer, dw_bytes_available, &dw_bytes_read))
			goto CleanUp;

		btReply.insert(btReply.end(), (PBYTE)(psz_tmp_buffer),
			(PBYTE)((uintptr_t)(psz_tmp_buffer)+dw_bytes_available));
		dw_bytes_total += dw_bytes_read;
		free(psz_tmp_buffer);
		psz_tmp_buffer = NULL;
	} while (dw_bytes_available > 0);

CleanUp:

	if (psz_tmp_buffer)
		free(psz_tmp_buffer);

	return dw_bytes_total;
}

bool c_lw_http::open_session(void)
{
	if (m_h_session_) return false;

	m_h_session_ = ::WinHttpOpen(m_psz_user_agent_, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	return (m_h_session_ ? true : false);
}

void c_lw_http::close_session(void) const
{
	if (m_h_session_)
		::WinHttpCloseHandle(m_h_session_);
}

bool c_lw_http::set_referer(PWCHAR pszReferer)
{
	if (!pszReferer) return false;

	m_psz_referer_ = pszReferer;

	return true;
}

PWCHAR c_lw_http::get_referer(void) const
{
	return m_psz_referer_;
}

bool c_lw_http::set_user_agent(PWCHAR pszUserAgent)
{
	if (!pszUserAgent || m_h_session_) return false;

	m_psz_user_agent_ = pszUserAgent;

	return true;
}

PWCHAR c_lw_http::get_user_agent(void) const
{
	return m_psz_user_agent_;
}

bool c_lw_http::get(const std::wstring sURL, std::string& s_reply)
{
	std::vector< BYTE > bt_reply;

	const bool b_result = send_request(sURL, bt_reply, (PWCHAR)L"GET", NULL, 0);

	s_reply.clear();
	s_reply = std::string(bt_reply.begin(), bt_reply.end());

	return b_result;
}

bool c_lw_http::get(std::wstring s_url, std::vector<BYTE>& btReply)
{
	return send_request(s_url, btReply, (PWCHAR)L"GET", nullptr, 0);
}

bool c_lw_http::post(std::wstring sURL, std::string& sReply, c_lw_httpd& PostData)
{
	std::vector< BYTE > btReply;

	bool bResult = send_request(sURL, btReply, (PWCHAR)L"POST",
		(LPVOID)(PostData.get_data()), PostData.get_size());

	sReply.clear();
	sReply = std::string(btReply.begin(), btReply.end());
	//std::string( ( char *)( &btReply[0] ), btReply.size() );

	return bResult;
}

bool c_lw_http::post(std::wstring sURL, std::vector<BYTE>& btReply, c_lw_httpd& PostData)
{
	return send_request(sURL, btReply, (PWCHAR)L"POST",
		LPVOID(PostData.get_data()), PostData.get_size());
}

///////////////////////////////////////////////////////////////////////////////