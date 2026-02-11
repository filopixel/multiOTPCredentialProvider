/* * * * * * * * * * * * * * * * * * * * *
**
** DasCredentialProvider Configuration
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
** * * * * * * * * * * * * * * * * * * */

#pragma once
#include "SecureString.h"
#include <string>
#include <credentialprovider.h>

class Configuration
{
public:
	Configuration();

	void printConfiguration();

	std::wstring loginText = L"Das Credential Provider";
	std::wstring bitmapPath = L"";

	bool hideFullName = false;
	bool hideDomainName = false;

	bool noDefault = false;

	bool doAutoLogon = false;
	bool userCanceled = false;
	bool clearFields = true;

	struct PROVIDER
	{
		ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
		UINT_PTR upAdviseContext = 0;

		CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
		DWORD credPackFlags = 0;

		// Possibly read-write
		CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr = nullptr;
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs = nullptr;
		PWSTR* status_text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;
		ICredentialProviderCredentialEvents* pCredProvCredentialEvents = nullptr;

		// Read-only
		ICredentialProviderCredential* pCredProvCredential = nullptr;
		wchar_t** field_strings = nullptr;
	} provider;

	struct CREDENTIAL
	{
		std::wstring username = L"";
		std::wstring domain = L"";
		SecureWString password = L"";
		std::wstring otp = L"";
	} credential;
};
