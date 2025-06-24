#include "utils/DeviceNameResolver.h"
#include "core/AllycsApi.h"

DeviceNameResolver::DeviceNameResolver()
{
    AllycsApi::initialize();
	initDeviceNameList();
}

DeviceNameResolver::~DeviceNameResolver()
{
	deviceNameList.clear();
}

void DeviceNameResolver::initDeviceNameList()
{
	TCHAR shortName[3] = {0};
	TCHAR longName[MAX_PATH] = {0};
    HardDisk hardDisk{};

	shortName[1] = TEXT(':');

	deviceNameList.reserve(3);

	for (TCHAR shortD = TEXT('a'); shortD <= TEXT('z'); shortD++)
	{
		shortName[0] = shortD;
		if (QueryDosDevice(shortName, longName, MAX_PATH) > 0)
		{
			hardDisk.shortName[0] = _totupper(shortD);
			hardDisk.shortName[1] = TEXT(':');
			hardDisk.shortName[2] = 0;

			hardDisk.longNameLength = _tcslen(longName);
			
			_tcscpy_s(hardDisk.longName, longName);
			deviceNameList.push_back(hardDisk);
		}
	}

    fixVirtualDevices();
}

bool DeviceNameResolver::resolveDeviceLongNameToShort(const TCHAR* sourcePath, TCHAR* targetPath)
{
	for (unsigned int i = 0; i < deviceNameList.size(); i++)
	{
		if (!_tcsnicmp(deviceNameList[i].longName, sourcePath, deviceNameList[i].longNameLength) && 
            sourcePath[deviceNameList[i].longNameLength] == TEXT('\\'))
		{
			_tcscpy_s(targetPath, MAX_PATH, deviceNameList[i].shortName);
			_tcscat_s(targetPath, MAX_PATH, sourcePath + deviceNameList[i].longNameLength);
			return true;
		}
	}

	return false;
}

void DeviceNameResolver::fixVirtualDevices()
{
    const USHORT BufferSize = MAX_PATH * 2 * sizeof(WCHAR);
    WCHAR longCopy[MAX_PATH] = {0};
    OBJECT_ATTRIBUTES_ALLYCS oa{};
    UNICODE_STRING_ALLYCS unicodeInput{};
    UNICODE_STRING_ALLYCS unicodeOutput{};
    HANDLE hFile = nullptr;
    ULONG retLen = 0;
    HardDisk hardDisk{};

    unicodeOutput.Buffer = static_cast<PWSTR>(malloc(BufferSize));
    if (!unicodeOutput.Buffer)
        return;

    for (unsigned int i = 0; i < deviceNameList.size(); i++)
    {
        wcscpy_s(longCopy, deviceNameList[i].longName);

        AllycsApi::RtlInitUnicodeString(&unicodeInput, longCopy);
        InitializeObjectAttributes(&oa, &unicodeInput, 0, 0, 0);

        NTSTATUS status = SysOpenSymbolicLinkObject(
            &hFile, 
            SYMBOLIC_LINK_QUERY, 
            reinterpret_cast<POBJECT_ATTRIBUTES>(&oa)
        );

        if(NT_SUCCESS(status))
        {
            unicodeOutput.Length = BufferSize;
            unicodeOutput.MaximumLength = unicodeOutput.Length;
            ZeroMemory(unicodeOutput.Buffer, unicodeOutput.Length);

            status = SysQuerySymbolicLinkObject(
                hFile, 
                reinterpret_cast<PUNICODE_STRING>(&unicodeOutput), 
                &retLen
            );

            if (NT_SUCCESS(status))
            {
                hardDisk.longNameLength = wcslen(unicodeOutput.Buffer);
                wcscpy_s(hardDisk.shortName, deviceNameList[i].shortName);
                wcscpy_s(hardDisk.longName, unicodeOutput.Buffer);
                deviceNameList.push_back(hardDisk);
            }  

            SysClose(hFile);
        }
    }

    free(unicodeOutput.Buffer);
}