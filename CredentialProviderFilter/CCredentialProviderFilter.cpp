/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Original work Copyright 2012 Dominik Pretzsch
**                          2017 NetKnights GmbH
** Modified work Copyright 2026 Adamantic
**
** Author		Dominik Pretzsch
**				Nils Behlen
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
#include "CCredentialProviderFilter.h"
#include "guid.h"
#include "Logger.h"
#include "Shared.h"
#include <unknwn.h>

HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	DebugPrint(__FUNCTION__);
	HRESULT hr;

	CCredentialProviderFilter* pProvider = new CCredentialProviderFilter();

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

HRESULT CCredentialProviderFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID* rgclsidProviders,
	BOOL* rgbAllow, DWORD cProviders)
{
	UNREFERENCED_PARAMETER(dwFlags);
	DebugPrint(std::string(__FUNCTION__) + ": " + Shared::CPUStoString(cpus));

	switch (cpus)
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
	case CPUS_CREDUI:
		break;
	case CPUS_CHANGE_PASSWORD:
		return E_NOTIMPL;
	default:
		return E_INVALIDARG;
	}

	// Simple filter logic: Allow only DasCredentialProvider, hide all others
	// This forces users to use DasCredentialProvider for logon/unlock
	for (DWORD i = 0; i < cProviders; i++)
	{
		if (IsEqualGUID(rgclsidProviders[i], CLSID_COTP_LOGON))
		{
			rgbAllow[i] = TRUE;  // Show DasCredentialProvider
			DebugPrint("Allowing DasCredentialProvider");
		}
		else
		{
			rgbAllow[i] = FALSE; // Hide all other providers
		}
	}

	return S_OK;
}

CCredentialProviderFilter::CCredentialProviderFilter() :
	_cRef(1)
{
	DebugPrint(__FUNCTION__);
	DllAddRef();
}

CCredentialProviderFilter::~CCredentialProviderFilter()
{
	DebugPrint(__FUNCTION__);
	DllRelease();
}

HRESULT CCredentialProviderFilter::UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
	DebugPrint(__FUNCTION__);

	if (!pcpcsIn)
	{
		// no point continuing as there are no credentials
		return E_NOTIMPL;
	}

	// copy contents from pcpcsIn to pcpcsOut
	pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
	pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
	pcpcsOut->rgbSerialization = pcpcsIn->rgbSerialization;

	// set target CP to our CP (DasCredentialProvider)
	pcpcsOut->clsidCredentialProvider = CLSID_COTP_LOGON;

	// copy the buffer contents if needed
	if (pcpcsOut->cbSerialization > 0 && (pcpcsOut->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcsIn->cbSerialization)) != NULL)
	{
		CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
		return S_OK;
	}
	else
	{
		return E_NOTIMPL;
	}
}
