/* * * * * * * * * * * * * * * * * * * * *
**
** Original work Copyright 2012 Dominik Pretzsch
**                          2020-2026 SysCo systemes de communication sa
** Modified work Copyright 2026 Adamantic
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

#ifndef _FILTER_GUID_H
#define _FILTER_GUID_H
#pragma once

#include <guiddef.h>

// DasCredentialProviderFilter CLSID
// {D1CA3136-738F-4466-A973-1C46BD9F0385}
DEFINE_GUID(CLSID_CSample,
	0xd1ca3136, 0x738f, 0x4466, 0xa9, 0x73, 0x1c, 0x46, 0xbd, 0x9f, 0x03, 0x85);

// DasCredentialProvider CLSID (referenced by Filter)
// {07B5C3C1-5E97-4CAE-855B-84966AC4132F}
DEFINE_GUID(CLSID_COTP_LOGON,
	0x07b5c3c1, 0x5e97, 0x4cae, 0x85, 0x5b, 0x84, 0x96, 0x6a, 0xc4, 0x13, 0x2f);

#endif
