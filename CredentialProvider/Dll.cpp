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

#include "Dll.h"

static LONG g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = nullptr; // global dll hinstance

extern HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_CSample;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1)
    {
    }

    // IUnknown
	#pragma warning( disable : 4838 )
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv) noexcept
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef() noexcept
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release() noexcept
    {
        LONG const cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            hr = CSample_CreateInstance(riid, ppv);
        }
        else
        {
            *ppv = nullptr;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CClassFactory()
    {
    }
    long _cRef;
};

HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void **ppv)
{
    *ppv = nullptr;

    HRESULT hr;

    if (CLSID_CSample == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

void DllAddRef() noexcept
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease() noexcept
{
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void *)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;
}

// DasCredentialProvider CLSID
// {07B5C3C1-5E97-4CAE-855B-84966AC4132F}
static const wchar_t* CREDENTIAL_PROVIDER_CLSID = L"{07B5C3C1-5E97-4CAE-855B-84966AC4132F}";

STDAPI DllRegisterServer()
{
    HRESULT hr = S_OK;
    wchar_t szModulePath[MAX_PATH];

    // Get the path to this DLL
    if (!GetModuleFileNameW(g_hinst, szModulePath, ARRAYSIZE(szModulePath)))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    HKEY hKey = nullptr;
    DWORD dwDisposition = 0;

    // Register CLSID in HKCR\CLSID\{guid}
    wchar_t szClsidKey[128];
    swprintf_s(szClsidKey, ARRAYSIZE(szClsidKey), L"CLSID\\%s", CREDENTIAL_PROVIDER_CLSID);

    LONG lResult = RegCreateKeyExW(HKEY_CLASSES_ROOT, szClsidKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &dwDisposition);
    if (lResult != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(lResult);
    }

    // Set default value to description
    const wchar_t* szDescription = L"Das Credential Provider";
    RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szDescription, (DWORD)((wcslen(szDescription) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // Register InprocServer32
    wchar_t szInprocKey[160];
    swprintf_s(szInprocKey, ARRAYSIZE(szInprocKey), L"CLSID\\%s\\InprocServer32", CREDENTIAL_PROVIDER_CLSID);

    lResult = RegCreateKeyExW(HKEY_CLASSES_ROOT, szInprocKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &dwDisposition);
    if (lResult != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(lResult);
    }

    // Set default value to DLL path
    RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szModulePath, (DWORD)((wcslen(szModulePath) + 1) * sizeof(wchar_t)));

    // Set ThreadingModel
    const wchar_t* szThreadingModel = L"Apartment";
    RegSetValueExW(hKey, L"ThreadingModel", 0, REG_SZ, (BYTE*)szThreadingModel, (DWORD)((wcslen(szThreadingModel) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    // Register as Credential Provider in HKLM
    wchar_t szCPKey[256];
    swprintf_s(szCPKey, ARRAYSIZE(szCPKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        CREDENTIAL_PROVIDER_CLSID);

    lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szCPKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &dwDisposition);
    if (lResult != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(lResult);
    }

    // Set default value
    RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)szDescription, (DWORD)((wcslen(szDescription) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);

    return hr;
}

STDAPI DllUnregisterServer()
{
    // Remove Credential Provider registration from HKLM
    wchar_t szCPKey[256];
    swprintf_s(szCPKey, ARRAYSIZE(szCPKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        CREDENTIAL_PROVIDER_CLSID);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, szCPKey);

    // Remove InprocServer32 key
    wchar_t szInprocKey[160];
    swprintf_s(szInprocKey, ARRAYSIZE(szInprocKey), L"CLSID\\%s\\InprocServer32", CREDENTIAL_PROVIDER_CLSID);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szInprocKey);

    // Remove CLSID key
    wchar_t szClsidKey[128];
    swprintf_s(szClsidKey, ARRAYSIZE(szClsidKey), L"CLSID\\%s", CREDENTIAL_PROVIDER_CLSID);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szClsidKey);

    return S_OK;
}
