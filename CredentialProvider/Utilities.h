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

#pragma once
#include "Configuration.h"
#include "Logger.h"
#include <scenario.h>
#include <memory>
#include <Windows.h>
#include <wincred.h>

#define CLEAR_FIELDS_CRYPT 0
#define CLEAR_FIELDS_EDIT_AND_CRYPT 1
#define CLEAR_FIELDS_ALL 2
#define CLEAR_FIELDS_ALL_DESTROY 3

#define MAX_SIZE_DOMAIN 64
#define MAX_SIZE_USERNAME 512

enum class SCENARIO
{
	NO_CHANGE = 0,
	LOGON = 1,
	UNLOCK_BLOCKED = 2,
};

class Utilities
{
public:
	Utilities(std::shared_ptr<Configuration> c) noexcept;

	HRESULT KerberosLogon(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in SecureWString password,
		__in std::wstring domain
	);

	HRESULT CredPackAuthentication(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in SecureWString password,
		__in std::wstring domain
	);

	HRESULT SetScenario(
		__in ICredentialProviderCredential* pCredential,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in SCENARIO scenario
	);

	HRESULT Clear(
		wchar_t* (&field_strings)[FID_NUM_FIELDS],
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[FID_NUM_FIELDS],
		ICredentialProviderCredential* pcpc,
		ICredentialProviderCredentialEvents* pcpce,
		char clear
	);

	HRESULT SetFieldStatePairBatch(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in const FIELD_STATE_PAIR* pFSP
	);

	HRESULT InitializeField(
		LPWSTR* rgFieldStrings,
		DWORD field_index
	);

	HRESULT ReadFieldValues();

	HRESULT ResetScenario(ICredentialProviderCredential* pSelf, ICredentialProviderCredentialEvents* pCredProvCredentialEvents);

private:
	std::shared_ptr<Configuration> _config;

	HRESULT ReadUserField();
	HRESULT ReadPasswordField();
	HRESULT ReadOTPField();
};
