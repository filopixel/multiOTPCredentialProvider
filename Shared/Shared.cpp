/* * * * * * * * * * * * * * * * * * * * *
**
** DasCredentialProvider - Shared Library
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

#include "Shared.h"
#include "Logger.h"
#include <tchar.h>

namespace Shared {
	bool IsRequiredForScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, int caller)
	{
		DebugPrint(__FUNCTION__);
		if (caller != FILTER && caller != PROVIDER)
		{
			DebugPrint("Invalid argument for caller: " + std::to_string(caller));
			return false;
		}

		switch (cpus)
		{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
			// Daemon stub: always enabled for these scenarios
			return true;
		case CPUS_CHANGE_PASSWORD:
		case CPUS_PLAP:
		case CPUS_INVALID:
			return false;
		default:
			return false;
		}
	}

#define TERMINAL_SERVER_KEY _T("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    _T("GlassSessionId")
	bool IsCurrentSessionRemote()
	{
		bool fIsRemoteable = false;
		DebugPrint("check for remote session...");
		if (GetSystemMetrics(SM_REMOTESESSION))
		{
			fIsRemoteable = true;
		}
		else
		{
			HKEY hRegKey = nullptr;
			LONG lResult;

			lResult = RegOpenKeyEx(
				HKEY_LOCAL_MACHINE,
				TERMINAL_SERVER_KEY,
				0, // ulOptions
				KEY_READ,
				&hRegKey
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwGlassSessionId = 0;
				DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
				DWORD dwType = 0;

				lResult = RegQueryValueEx(
					hRegKey,
					GLASS_SESSION_ID,
					NULL, // lpReserved
					&dwType,
					(BYTE*)&dwGlassSessionId,
					&cbGlassSessionId
				);

				if (lResult == ERROR_SUCCESS)
				{
					DWORD dwCurrentSessionId;

					if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
					{
						fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
					}
				}
			}

			if (hRegKey)
			{
				RegCloseKey(hRegKey);
			}
		}

		DebugPrint(fIsRemoteable ? "session is remote" : "session is not remote");

		return fIsRemoteable;
	}

	std::string CPUStoString(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
	{
		switch (cpus)
		{
		case CPUS_LOGON:
			return "CPUS_LOGON";
		case CPUS_UNLOCK_WORKSTATION:
			return "CPUS_UNLOCK_WORKSTATION";
		case CPUS_CREDUI:
			return "CPUS_CREDUI";
		case CPUS_CHANGE_PASSWORD:
			return "CPUS_CHANGE_PASSWORD";
		case CPUS_PLAP:
			return "CPUS_PLAP";
		case CPUS_INVALID:
			return "CPUS_INVALID";
		default:
			return ("Unknown CPUS: " + std::to_string(cpus));
		}
	}
}
