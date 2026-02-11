/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** DasCredentialProvider - CCredential
**
** OTP Validation: Even last digit = SUCCESS, Odd last digit = FAILURE
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

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"
#include "Logger.h"
#include <resource.h>
#include <string>

using namespace std;

CCredential::CCredential(std::shared_ptr<Configuration> c) :
	_config(c), _util(_config)
{
	_cRef = 1;
	_pCredProvCredentialEvents = nullptr;

	DllAddRef();

	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);
}

CCredential::~CCredential()
{
	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);
	DllRelease();
}

// Initializes one credential with the field information passed in.
HRESULT CCredential::Initialize(
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
)
{
	wstring wstrUsername, wstrDomainname;
	SecureWString wstrPassword;

	if (NOT_EMPTY(user_name))
	{
		wstrUsername = wstring(user_name);
	}
	if (NOT_EMPTY(domain_name))
	{
		wstrDomainname = wstring(domain_name);
	}
	if (NOT_EMPTY(password))
	{
		wstrPassword = SecureWString(password);
	}

	DebugPrint(__FUNCTION__);
	DebugPrint(L"Username from provider: " + (wstrUsername.empty() ? L"empty" : wstrUsername));
	DebugPrint(L"Domain from provider: " + (wstrDomainname.empty() ? L"empty" : wstrDomainname));

	HRESULT hr = S_OK;

	if (!wstrUsername.empty())
	{
		_config->credential.username = wstrUsername;
	}

	if (!wstrDomainname.empty())
	{
		_config->credential.domain = wstrDomainname;
	}

	if (!wstrPassword.empty())
	{
		_config->credential.password = wstrPassword;
		SecureZeroMemory(password, sizeof(password));
	}

	for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
	{
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
		{
			break;
		}

		_util.InitializeField(_rgFieldStrings, i);
	}

	// If serialized credentials are available (NLA/RDP), show username in disabled field
	// Password stays in config for GetSerialization() but field is HIDDEN in serialized scenario
	if (SUCCEEDED(hr) && !_config->credential.username.empty())
	{
		CoTaskMemFree(_rgFieldStrings[FID_USERNAME]);
		hr = SHStrDupW(_config->credential.username.c_str(), &_rgFieldStrings[FID_USERNAME]);
		DebugPrint(L"Using NLA credentials for: " + _config->credential.username);
	}
	else if (SUCCEEDED(hr))
	{
		DebugPrint("No serialized credentials, fields are editable");
	}

	DebugPrint(SUCCEEDED(hr) ? "Init: OK" : "Init: FAIL");
	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(__in ICredentialProviderCredentialEvents* pcpce)
{
	if (_pCredProvCredentialEvents != nullptr)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CCredential::UnAdvise()
{
	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = nullptr;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
	DebugPrint(__FUNCTION__);
	*pbAutoLogon = false;

	if (_config->doAutoLogon)
	{
		*pbAutoLogon = TRUE;
		_config->doAutoLogon = false;
	}

	return S_OK;
}

// Called when tile is deselected - clear password fields
HRESULT CCredential::SetDeselected()
{
	DebugPrint(__FUNCTION__);

	_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);
	_util.ResetScenario(this, _pCredProvCredentialEvents);

	return S_OK;
}

// Gets info for a particular field of a tile.
HRESULT CCredential::GetFieldState(
	__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
)
{
	HRESULT hr = S_OK;

	if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
)
{
	HRESULT hr = S_OK;

	if (dwFieldID < FID_NUM_FIELDS && ppwsz)
	{
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_INVALIDARG;
	if ((FID_LOGO == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));

		if (hbmp != nullptr)
		{
			hr = S_OK;
			*phbmp = hbmp;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be adjacent to.
HRESULT CCredential::GetSubmitButtonValue(
	__in DWORD dwFieldID,
	__out DWORD* pdwAdjacentTo
)
{
	DebugPrint(__FUNCTION__);
	if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		*pdwAdjacentTo = FID_OTP;
		return S_OK;
	}
	return E_INVALIDARG;
}

// Sets the value of a field which can accept a string as a value.
HRESULT CCredential::SetStringValue(
	__in DWORD dwFieldID,
	__in PCWSTR pwz
)
{
	HRESULT hr;

	if (dwFieldID < FID_NUM_FIELDS &&
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
			CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Returns the number of items to be included in the combobox
HRESULT CCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	*pcItems = 0;
	*pdwSelectedItem = 0;
	return E_NOTIMPL;
}

HRESULT CCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID,
	__in DWORD dwItem,
	__deref_out PWSTR* ppwszItem)
{
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszItem);
	return E_NOTIMPL;
}

HRESULT CCredential::SetComboBoxSelectedValue(
	__in DWORD dwFieldID,
	__in DWORD dwSelectedItem
)
{
	UNREFERENCED_PARAMETER(dwSelectedItem);
	UNREFERENCED_PARAMETER(dwFieldID);
	return E_NOTIMPL;
}

HRESULT CCredential::GetCheckboxValue(
	__in DWORD dwFieldID,
	__out BOOL* pbChecked,
	__deref_out PWSTR* ppwszLabel
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(ppwszLabel);
	*pbChecked = FALSE;
	return E_NOTIMPL;
}

HRESULT CCredential::SetCheckboxValue(
	__in DWORD dwFieldID,
	__in BOOL bChecked
)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);
	return E_NOTIMPL;
}

HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	return E_NOTIMPL;
}

// Collect the username and password into a serialized credential for logon
HRESULT CCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);
	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL;

	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.pCredProvCredential = this;
	_config->provider.pcpcs = pcpcs;
	_config->provider.pcpgsr = pcpgsr;
	_config->provider.status_icon = pcpsiOptionalStatusIcon;
	_config->provider.status_text = ppwszOptionalStatusText;
	_config->provider.field_strings = _rgFieldStrings;

	if (_config->userCanceled)
	{
		*_config->provider.status_icon = CPSI_ERROR;
		*_config->provider.pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		SHStrDupW(L"Logon cancelled", _config->provider.status_text);
		return S_FALSE;
	}

	// For CREDUI, Connect() is never called (Windows uses ICredentialProviderCredential,
	// not IConnectableCredentialProviderCredential), so validate OTP here
	if (_config->provider.cpu == CPUS_CREDUI && _authStatus != S_OK)
	{
		_util.ReadFieldValues();
		std::wstring otp = _config->credential.otp;
		if (!otp.empty())
		{
			wchar_t lastChar = otp.back();
			int lastDigit = lastChar - L'0';
			if (lastDigit >= 0 && lastDigit <= 9 && lastDigit % 2 == 0)
			{
				DebugPrint("=== DAEMON STUB === CREDUI OTP validation: SUCCESS (even)");
				_authStatus = S_OK;
			}
			else
			{
				DebugPrint("=== DAEMON STUB === CREDUI OTP validation: FAILURE (odd or non-digit)");
			}
		}
		else
		{
			DebugPrint("=== DAEMON STUB === CREDUI OTP validation: FAILURE (empty)");
		}
	}

	// Check authentication result
	if (_authStatus == S_OK)
	{
		// Authentication successful - pack credentials for logon
		_authStatus = E_FAIL; // Reset for next attempt

		if (_config->provider.cpu == CPUS_CREDUI)
		{
			hr = _util.CredPackAuthentication(pcpgsr, pcpcs, _config->provider.cpu,
				_config->credential.username, _config->credential.password, _config->credential.domain);
		}
		else
		{
			hr = _util.KerberosLogon(pcpgsr, pcpcs, _config->provider.cpu,
				_config->credential.username, _config->credential.password, _config->credential.domain);
		}
	}
	else
	{
		// Authentication failed
		ShowErrorMessage(L"Wrong One-Time Password!", 0);
		_util.ResetScenario(this, _pCredProvCredentialEvents);
		*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
	}

	if (_config->clearFields)
	{
		_util.Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	}
	else
	{
		_config->clearFields = true;
	}

	DebugPrint("CCredential::GetSerialization - END");
	return hr;
}

void CCredential::ShowErrorMessage(const std::wstring& message, const HRESULT& code)
{
	*_config->provider.status_icon = CPSI_ERROR;
	wstring errorMessage = message;
	if (code != 0) errorMessage += L" (" + to_wstring(code) + L")";
	SHStrDupW(errorMessage.c_str(), _config->provider.status_text);
}

// Connect is called first after the submit button is pressed.
// DAEMON STUB: Validates OTP - even last digit = success, odd = failure
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(pqcws);

	_config->provider.pCredProvCredential = this;
	_config->provider.pCredProvCredentialEvents = _pCredProvCredentialEvents;
	_config->provider.field_strings = _rgFieldStrings;
	_util.ReadFieldValues();

	// Debug: Print username and password to debug output
	std::wstring debugMsg = L"=== DAEMON STUB === User: " +
		_config->credential.username + L" Pass: " +
		std::wstring(_config->credential.password.c_str());
	OutputDebugStringW(debugMsg.c_str());
	DebugPrint(L"=== DAEMON STUB === User: " + _config->credential.username);
	DebugPrint(L"=== DAEMON STUB === OTP: " + _config->credential.otp);

	// Validate OTP: even last digit = success, odd last digit = failure
	std::wstring otp = _config->credential.otp;
	if (!otp.empty())
	{
		wchar_t lastChar = otp.back();
		int lastDigit = lastChar - L'0';
		if (lastDigit >= 0 && lastDigit <= 9 && lastDigit % 2 == 0)
		{
			DebugPrint("=== DAEMON STUB === OTP validation: SUCCESS (even)");
			_authStatus = S_OK;  // Even = success
		}
		else
		{
			DebugPrint("=== DAEMON STUB === OTP validation: FAILURE (odd or non-digit)");
			_authStatus = E_FAIL;  // Odd or non-digit = failure
		}
	}
	else
	{
		DebugPrint("=== DAEMON STUB === OTP validation: FAILURE (empty)");
		_authStatus = E_FAIL;  // Empty OTP = failure
	}

	return S_OK; // Always return S_OK, actual result is in _authStatus
}

HRESULT CCredential::Disconnect()
{
	return E_NOTIMPL;
}

// ReportResult allows a credential to customize the string and icon displayed
// in the case of a logon failure.
HRESULT CCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
	DebugPrint(__FUNCTION__);
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);
	UNREFERENCED_PARAMETER(ntsStatus);
	UNREFERENCED_PARAMETER(ntsSubstatus);

	_util.ResetScenario(this, _pCredProvCredentialEvents);
	return S_OK;
}
