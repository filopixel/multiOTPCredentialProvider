/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** DasCredentialProvider Utilities
**
** Copyright 2026 Adamantic
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include "Utilities.h"
#include "helpers.h"
#include "SecureString.h"
#include "scenario.h"
#include "guid.h"
#include <Shlwapi.h>

using namespace std;

Utilities::Utilities(std::shared_ptr<Configuration> c) noexcept
{
	_config = c;
}

HRESULT Utilities::KerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr;

	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}
	if (bGetCompName)
	{
		domain = wstring(wsz, cch);
	}

	DebugPrint("Packing Credential:");
	DebugPrint(username);
	DebugPrint(domain);

	if (!domain.empty() || bGetCompName)
	{
		PWSTR pwzProtectedPassword;

		hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

		if (SUCCEEDED(hr))
		{
			KERB_INTERACTIVE_UNLOCK_LOGON kiul;
			LPWSTR lpwszDomain = new wchar_t[domain.size() + 1];
			wcscpy_s(lpwszDomain, (domain.size() + 1), domain.c_str());

			LPWSTR lpwszUsername = new wchar_t[username.size() + 1];
			wcscpy_s(lpwszUsername, (username.size() + 1), username.c_str());

			hr = KerbInteractiveUnlockLogonInit(lpwszDomain, lpwszUsername, pwzProtectedPassword, cpus, &kiul);

			if (SUCCEEDED(hr))
			{
				hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

				if (SUCCEEDED(hr))
				{
					ULONG ulAuthPackage;
					hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

					if (SUCCEEDED(hr))
					{
						pcpcs->ulAuthenticationPackage = ulAuthPackage;
						pcpcs->clsidCredentialProvider = CLSID_CSample;
						*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
					}
				}
			}

			delete[] lpwszDomain;
			delete[] lpwszUsername;

			CoTaskMemFree(pwzProtectedPassword);
		}
	}
	else
	{
		hr = HRESULT_FROM_WIN32(GetLastError());
	}

	return hr;
}

HRESULT Utilities::CredPackAuthentication(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in std::wstring username,
	__in SecureWString password,
	__in std::wstring domain)
{
	DebugPrint(__FUNCTION__);
	DebugPrint(username);
	DebugPrint(domain);

	const DWORD credPackFlags = _config->provider.credPackFlags;
	PWSTR pwzProtectedPassword;
	HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus, &pwzProtectedPassword);

	WCHAR wsz[MAX_SIZE_DOMAIN];
	DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = false;

	if (domain.empty())
	{
		bGetCompName = GetComputerNameW(wsz, &cch);
	}
	if (bGetCompName)
	{
		domain = wsz;
	}

	if (SUCCEEDED(hr))
	{
		PWSTR domainUsername = NULL;
		hr = DomainUsernameStringAlloc(domain.c_str(), username.c_str(), &domainUsername);
		DebugPrint(domainUsername);
		if (SUCCEEDED(hr))
		{
			DWORD size = 0;
			BYTE* rawbits = NULL;

			LPWSTR lpwszPassword = new wchar_t[(password.size() + 1)];
			wcscpy_s(lpwszPassword, (password.size() + 1), password.c_str());

			if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
				domainUsername, lpwszPassword, rawbits, &size))
			{
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					rawbits = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & credPackFlags) ? CRED_PACK_WOW_BUFFER : 0,
						domainUsername, lpwszPassword, rawbits, &size))
					{
						HeapFree(GetProcessHeap(), 0, rawbits);
						HeapFree(GetProcessHeap(), 0, domainUsername);

						hr = HRESULT_FROM_WIN32(GetLastError());
					}
					else
					{
						pcpcs->rgbSerialization = rawbits;
						pcpcs->cbSerialization = size;
					}
				}
				else
				{
					HeapFree(GetProcessHeap(), 0, domainUsername);
					hr = HRESULT_FROM_WIN32(GetLastError());
				}
			}

			if (SUCCEEDED(hr))
			{
				ULONG ulAuthPackage;
				hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

				if (SUCCEEDED(hr))
				{
					pcpcs->ulAuthenticationPackage = ulAuthPackage;
					pcpcs->clsidCredentialProvider = CLSID_CSample;
					*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
				}
			}

			SecureZeroMemory(lpwszPassword, sizeof(lpwszPassword));
		}

		CoTaskMemFree(pwzProtectedPassword);
	}

	return hr;
}

HRESULT Utilities::SetScenario(
	__in ICredentialProviderCredential* pCredential,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in SCENARIO scenario)
{
	DebugPrint(__FUNCTION__);
	HRESULT hr = S_OK;

	switch (scenario)
	{
	case SCENARIO::LOGON:
		DebugPrint("SetScenario: LOGON");
		hr = SetFieldStatePairBatch(pCredential, pCPCE, s_rgScenarioLogon);
		break;
	case SCENARIO::NO_CHANGE:
	default:
		break;
	}

	// Set display text
	const int hideFullName = _config->hideFullName;
	const int hideDomain = _config->hideDomainName;

	wstring text = _config->credential.username + L"@" + _config->credential.domain;
	if (hideDomain || (_config->credential.username.find(L"@") != std::string::npos))
	{
		text = _config->credential.username;
	}
	if (hideFullName)
	{
		text = L"";
	}

	if (text.empty() || _config->credential.username.empty())
	{
		pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, _config->loginText.c_str());
	}
	else
	{
		pCPCE->SetFieldString(pCredential, FID_LARGE_TEXT, text.c_str());
	}

	return hr;
}

HRESULT Utilities::Clear(
	wchar_t* (&field_strings)[FID_NUM_FIELDS],
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
	ICredentialProviderCredential* pcpc,
	ICredentialProviderCredentialEvents* pcpce,
	char clear)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		char do_something = 0;

		if ((pcpfd[i].cpft == CPFT_PASSWORD_TEXT && clear >= CLEAR_FIELDS_CRYPT) ||
			(pcpfd[i].cpft == CPFT_EDIT_TEXT && clear >= CLEAR_FIELDS_EDIT_AND_CRYPT))
		{
			if (field_strings[i])
			{
				const size_t len = lstrlen(field_strings[i]);
				SecureZeroMemory(field_strings[i], len * sizeof(*field_strings[i]));
				do_something = 1;
			}
		}

		if (do_something || clear >= CLEAR_FIELDS_ALL)
		{
			CoTaskMemFree(field_strings[i]);
			hr = SHStrDupW(L"", &field_strings[i]);

			if (pcpce)
			{
				pcpce->SetFieldString(pcpc, i, field_strings[i]);
			}
			if (clear == CLEAR_FIELDS_ALL_DESTROY)
			{
				CoTaskMemFree(pcpfd[i].pszLabel);
			}
		}
	}

	return hr;
}

HRESULT Utilities::SetFieldStatePairBatch(
	__in ICredentialProviderCredential* self,
	__in ICredentialProviderCredentialEvents* pCPCE,
	__in const FIELD_STATE_PAIR* pFSP)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = S_OK;

	if (!pCPCE || !self)
	{
		return E_INVALIDARG;
	}

	for (unsigned int i = 0; i < FID_NUM_FIELDS && SUCCEEDED(hr); i++)
	{
		hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);
		if (SUCCEEDED(hr))
		{
			hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
		}
	}

	return hr;
}

HRESULT Utilities::InitializeField(
	LPWSTR* rgFieldStrings,
	DWORD field_index)
{
	HRESULT hr = E_INVALIDARG;
	const int hide_fullname = _config->hideFullName;
	const int hide_domainname = _config->hideDomainName;

	wstring loginText = _config->loginText;
	wstring user_name = _config->credential.username;
	wstring domain_name = _config->credential.domain;

	switch (field_index)
	{
	case FID_LDAP_PASS:
	case FID_OTP:
	case FID_SUBMIT_BUTTON:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	case FID_USERNAME:
		hr = SHStrDupW((user_name.empty() ? L"" : user_name.c_str()), &rgFieldStrings[field_index]);
		break;
	case FID_LARGE_TEXT:
		if (!loginText.empty())
		{
			hr = SHStrDupW(loginText.c_str(), &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"Daemon Stub Login", &rgFieldStrings[field_index]);
		}
		break;
	case FID_SMALL_TEXT:
		// In CPUS_UNLOCK_WORKSTATION the username is displayed here
		if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION && !user_name.empty()
			&& !hide_fullname && !hide_domainname)
		{
			if (!domain_name.empty())
			{
				wstring fullName = user_name + L"@" + domain_name;
				hr = SHStrDupW(fullName.c_str(), &rgFieldStrings[field_index]);
			}
			else if (!user_name.empty())
			{
				hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
			}
			else
			{
				hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
			}
		}
		else if (!user_name.empty() && hide_domainname && !hide_fullname)
		{
			hr = SHStrDupW(user_name.c_str(), &rgFieldStrings[field_index]);
		}
		else
		{
			hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		}
		break;
	case FID_LOGO:
		hr = S_OK;
		break;
	default:
		hr = SHStrDupW(L"", &rgFieldStrings[field_index]);
		break;
	}
	return hr;
}

HRESULT Utilities::ReadFieldValues()
{
	DebugPrint(__FUNCTION__);

	switch (_config->provider.cpu)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		ReadUserField();
		ReadPasswordField();
		ReadOTPField();
		break;
	}

	return S_OK;
}

HRESULT Utilities::ReadUserField()
{
	wstring input(_config->provider.field_strings[FID_USERNAME]);
	DebugPrint(L"Loading user/domain from GUI: '" + input + L"'");
	wstring user_name, domain_name;

	auto const pos = input.find_first_of(L"\\", 0);
	if (pos == std::string::npos)
	{
		user_name = wstring(input);
	}
	else
	{
		user_name = wstring(input.substr(pos + 1, input.size()));
		domain_name = wstring(input.substr(0, pos));
	}

	if (!user_name.empty())
	{
		_config->credential.username = user_name;
	}

	if (!domain_name.empty())
	{
		_config->credential.domain = domain_name;
	}

	return S_OK;
}

HRESULT Utilities::ReadPasswordField()
{
	SecureWString newPassword(_config->provider.field_strings[FID_LDAP_PASS]);

	if (!newPassword.empty())
	{
		_config->credential.password = newPassword;
		DebugPrint("Password loaded from GUI");
	}

	return S_OK;
}

HRESULT Utilities::ReadOTPField()
{
	wstring newOTP(_config->provider.field_strings[FID_OTP]);
	DebugPrint(L"Loading OTP from GUI: '" + newOTP + L"'");
	_config->credential.otp = newOTP;

	return S_OK;
}

HRESULT Utilities::ResetScenario(
	ICredentialProviderCredential* pSelf,
	ICredentialProviderCredentialEvents* pCredProvCredentialEvents)
{
	DebugPrint(__FUNCTION__);

	// All scenarios (logon, unlock, credui) use the same LOGON layout
	SetScenario(pSelf, pCredProvCredentialEvents, SCENARIO::LOGON);

	return S_OK;
}
