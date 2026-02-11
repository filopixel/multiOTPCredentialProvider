/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** DasCredentialProvider - CProvider
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

#include "CProvider.h"
#include "Logger.h"
#include "Configuration.h"
#include "scenario.h"
#include <credentialprovider.h>

using namespace std;

CProvider::CProvider() :
	_cRef(1),
	_pkiulSetSerialization(nullptr),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
	_pCredProviderUserArray(nullptr)
{
	DllAddRef();
	_config = std::make_shared<Configuration>();
}

CProvider::~CProvider()
{
	if (_credential != NULL)
	{
		_credential->Release();
	}

	if (_pCredProviderUserArray != nullptr)
	{
		_pCredProviderUserArray->Release();
		_pCredProviderUserArray = nullptr;
	}

	DllRelease();
}

void CProvider::_CleanupSetSerialization()
{
	DebugPrint(__FUNCTION__);

	if (_pkiulSetSerialization)
	{
		KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
		SecureZeroMemory(_pkiulSetSerialization,
			sizeof(*_pkiulSetSerialization) +
			pkil->LogonDomainName.MaximumLength +
			pkil->UserName.MaximumLength +
			pkil->Password.MaximumLength);
		HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
	}
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
HRESULT CProvider::SetUsageScenario(
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in DWORD dwFlags
)
{
	DebugPrint(__FUNCTION__);
	DebugPrint("Daemon Stub Credential Provider - SetUsageScenario");

#ifdef _DEBUG
	_config->printConfiguration();
#endif

	HRESULT hr = E_INVALIDARG;

	_config->provider.credPackFlags = dwFlags;
	_config->provider.cpu = cpus;

	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		hr = S_OK;
		break;
	case CPUS_CHANGE_PASSWORD:
	case CPUS_PLAP:
	case CPUS_INVALID:
		hr = E_NOTIMPL;
		break;
	default:
		return E_INVALIDARG;
	}

	DebugPrint("SetScenario result:");
	DebugPrint(hr);

	return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI
HRESULT CProvider::SetSerialization(
	__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
)
{
	DebugPrint(__FUNCTION__);
	HRESULT result = E_NOTIMPL;
	ULONG authPackage = NULL;
	result = RetrieveNegotiateAuthPackage(&authPackage);

	if (!SUCCEEDED(result))
	{
		DebugPrint("Failed to retrieve authPackage");
		return result;
	}

	if (_config->provider.cpu == CPUS_CREDUI)
	{
		if (((_config->provider.credPackFlags & CREDUIWIN_IN_CRED_ONLY) || (_config->provider.credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY))
			&& authPackage != pcpcs->ulAuthenticationPackage)
		{
			return E_INVALIDARG;
		}

		if (_config->provider.credPackFlags & CREDUIWIN_AUTHPACKAGE_ONLY)
		{
			result = S_FALSE;
		}
	}

	if (authPackage == pcpcs->ulAuthenticationPackage && pcpcs->cbSerialization > 0 && pcpcs->rgbSerialization)
	{
		KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
		if (pkil->Logon.MessageType == KerbInteractiveLogon)
		{
			if (pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
			{
				BYTE* nativeSerialization = nullptr;
				DWORD nativeSerializationSize = 0;
				DebugPrint("Serialization found from remote");

				if (_config->provider.credPackFlags == CPUS_CREDUI && (_config->provider.credPackFlags & CREDUIWIN_PACK_32_WOW))
				{
					if (!SUCCEEDED(KerbInteractiveUnlockLogonRepackNative(pcpcs->rgbSerialization, pcpcs->cbSerialization,
						&nativeSerialization, &nativeSerializationSize)))
					{
						return result;
					}
				}
				else
				{
					nativeSerialization = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pcpcs->cbSerialization);
					nativeSerializationSize = pcpcs->cbSerialization;

					if (!nativeSerialization)
					{
						return E_OUTOFMEMORY;
					}

					CopyMemory(nativeSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
				}

				KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)nativeSerialization, nativeSerializationSize);

				if (_pkiulSetSerialization)
				{
					LocalFree(_pkiulSetSerialization);
				}

				_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)nativeSerialization;

				result = S_OK;
			}
		}
	}

	return result;
}

// Called by LogonUI to give you a callback
HRESULT CProvider::Advise(
	__in ICredentialProviderEvents* pcpe,
	__in UINT_PTR upAdviseContext
)
{
	DebugPrint(__FUNCTION__);

	if (_config->provider.pCredentialProviderEvents != nullptr)
	{
		_config->provider.pCredentialProviderEvents->Release();
	}

	_config->provider.pCredentialProviderEvents = pcpe;
	_config->provider.pCredentialProviderEvents->AddRef();
	_config->provider.upAdviseContext = upAdviseContext;

	return S_OK;
}

// Called by LogonUI when the callback is no longer valid
HRESULT CProvider::UnAdvise()
{
	DebugPrint(__FUNCTION__);

	if (_config->provider.pCredentialProviderEvents != nullptr)
	{
		_config->provider.pCredentialProviderEvents->Release();
	}

	_config->provider.pCredentialProviderEvents = nullptr;
	_config->provider.upAdviseContext = NULL;

	return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles
HRESULT CProvider::GetFieldDescriptorCount(__out DWORD* pdwCount)
{
	DebugPrint(__FUNCTION__);
	*pdwCount = FID_NUM_FIELDS;
	return S_OK;
}

// Gets the field descriptor for a particular field
HRESULT CProvider::GetFieldDescriptorAt(
	__in DWORD dwIndex,
	__deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
)
{
	HRESULT hr = E_FAIL;
	if (!_config->provider.cpu)
	{
		return E_FAIL;
	}

	if ((dwIndex < FID_NUM_FIELDS) && ppcpfd)
	{
		hr = FieldDescriptorCoAllocCopy(s_rgScenarioCredProvFieldDescriptors[dwIndex], ppcpfd);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Sets pdwCount to the number of tiles that we wish to show
HRESULT CProvider::GetCredentialCount(
	__out DWORD* pdwCount,
	__out_range(< , *pdwCount) DWORD* pdwDefault,
	__out BOOL* pbAutoLogonWithDefault
)
{
	DebugPrint(__FUNCTION__);

	*pdwCount = 1;
	*pdwDefault = 0;
	*pbAutoLogonWithDefault = FALSE;

	if (_config->noDefault)
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
	}

	// if serialized creds are available, try using them
	if (_SerializationAvailable(SAF_USERNAME) && _SerializationAvailable(SAF_PASSWORD) && _config->provider.cpu != CPUS_CREDUI)
	{
		*pdwDefault = 0;
		*pbAutoLogonWithDefault = FALSE; // Don't auto-logon, always require OTP
	}

	return S_OK;
}

// Returns the credential at the index specified
HRESULT CProvider::GetCredentialAt(
	__in DWORD dwIndex,
	__deref_out ICredentialProviderCredential** ppcpc
)
{
	DebugPrint(__FUNCTION__);

	HRESULT hr = E_FAIL;
	const CREDENTIAL_PROVIDER_USAGE_SCENARIO usage_scenario = _config->provider.cpu;

	if (!_credential)
	{
		DebugPrint("Creating new credential");

		PWSTR serializedUser, serializedPass, serializedDomain;
		_GetSerializedCredentials(&serializedUser, &serializedPass, &serializedDomain);

		// For unlock scenario, get username from session if not provided
		if (usage_scenario == CPUS_UNLOCK_WORKSTATION && serializedUser == nullptr)
		{
			DWORD dwLen = 0;
			if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
				WTS_CURRENT_SESSION,
				WTSUserName,
				&serializedUser,
				&dwLen))
			{
				serializedUser = nullptr;
			}

			if (serializedDomain == nullptr)
			{
				if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
					WTS_CURRENT_SESSION,
					WTSDomainName,
					&serializedDomain,
					&dwLen))
				{
					serializedDomain = nullptr;
				}
			}
		}
		else if (usage_scenario == CPUS_LOGON || usage_scenario == CPUS_CREDUI)
		{
			// Get domain from computer if not provided
			if (serializedDomain == nullptr)
			{
				NETSETUP_JOIN_STATUS join_status;
				if (!NetGetJoinInformation(nullptr, &serializedDomain, &join_status) == NERR_Success ||
					join_status == NetSetupUnjoined || join_status == NetSetupUnknownStatus || join_status == NetSetupWorkgroupName)
				{
					serializedDomain = nullptr;
				}
			}
		}

		_credential = std::make_unique<CCredential>(_config);

		// Select scenario: if serialized credentials available (RDP/NLA) → fields disabled
		// Otherwise (local logon, unlock, CREDUI) → all fields editable
		const FIELD_STATE_PAIR* fieldStatePair;
		if (_SerializationAvailable(SAF_USERNAME) && _SerializationAvailable(SAF_PASSWORD))
		{
			fieldStatePair = s_rgScenarioLogonSerialized;
			DebugPrint("Using serialized scenario (RDP/NLA): username disabled, password hidden, OTP editable");
		}
		else
		{
			fieldStatePair = s_rgScenarioLogon;
			DebugPrint("Using local scenario: all fields editable");
		}

		hr = _credential->Initialize(
			s_rgScenarioCredProvFieldDescriptors,
			fieldStatePair,
			serializedUser, serializedDomain, serializedPass);
	}
	else
	{
		hr = S_OK;
	}

	if (FAILED(hr))
	{
		DebugPrint("Initialization failed");
		return hr;
	}

	if (!_credential)
	{
		DebugPrint("Instantiation failed");
		return E_OUTOFMEMORY;
	}

	if ((dwIndex == 0) && ppcpc)
	{
		if (usage_scenario == CPUS_CREDUI)
		{
			hr = _credential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
		}
		else
		{
			hr = _credential->QueryInterface(IID_IConnectableCredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	HRESULT hr;

	CProvider* pProvider = new CProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

void CProvider::_GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain)
{
	DebugPrint(__FUNCTION__);

	if (username)
	{
		if (_SerializationAvailable(SAF_USERNAME))
		{
			*username = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.UserName.Length + sizeof(wchar_t));
			CopyMemory(*username, _pkiulSetSerialization->Logon.UserName.Buffer, _pkiulSetSerialization->Logon.UserName.Length);
		}
		else
		{
			*username = NULL;
		}
	}

	if (password)
	{
		if (_SerializationAvailable(SAF_PASSWORD))
		{
			*password = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.Password.Length + sizeof(wchar_t));
			CopyMemory(*password, _pkiulSetSerialization->Logon.Password.Buffer, _pkiulSetSerialization->Logon.Password.Length);
		}
		else
		{
			*password = NULL;
		}
	}

	if (domain)
	{
		if (_SerializationAvailable(SAF_DOMAIN))
		{
			*domain = (PWSTR)LocalAlloc(LMEM_ZEROINIT, _pkiulSetSerialization->Logon.LogonDomainName.Length + sizeof(wchar_t));
			CopyMemory(*domain, _pkiulSetSerialization->Logon.LogonDomainName.Buffer, _pkiulSetSerialization->Logon.LogonDomainName.Length);
		}
		else
		{
			*domain = NULL;
		}
	}
}

bool CProvider::_SerializationAvailable(SERIALIZATION_AVAILABLE_FOR checkFor)
{
	DebugPrint(__FUNCTION__);

	bool result = false;

	if (!_pkiulSetSerialization)
	{
		DebugPrint("No serialized creds set");
	}
	else
	{
		switch (checkFor)
		{
		case SAF_USERNAME:
			result = _pkiulSetSerialization->Logon.UserName.Length && _pkiulSetSerialization->Logon.UserName.Buffer;
			break;
		case SAF_PASSWORD:
			result = _pkiulSetSerialization->Logon.Password.Length && _pkiulSetSerialization->Logon.Password.Buffer;
			break;
		case SAF_DOMAIN:
			result = _pkiulSetSerialization->Logon.LogonDomainName.Length && _pkiulSetSerialization->Logon.LogonDomainName.Buffer;
			break;
		}
	}

	return result;
}

// This function will be called by LogonUI after SetUsageScenario succeeds
HRESULT CProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
{
	if (_pCredProviderUserArray)
	{
		_pCredProviderUserArray->Release();
	}
	_pCredProviderUserArray = users;
	_pCredProviderUserArray->AddRef();

	return S_OK;
}
