#include "core/IATSearch.h"
#include "app/Allycs.h"
#include "core/Architecture.h"

//#define DEBUG_COMMENTS

bool IATSearch::searchImportAddressTableInProcess( DWORD_PTR startAddress, DWORD_PTR* addressIAT, DWORD* sizeIAT, bool advanced )
{
	DWORD_PTR addressInIAT = 0;

	*addressIAT = 0;
	*sizeIAT = 0;

	if (advanced)
	{
		return findIATAdvanced(startAddress, addressIAT, sizeIAT);
	}
	
	addressInIAT = findAPIAddressInIAT(startAddress);
	
	if (!addressInIAT)
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"searchImportAddressTableInProcess :: addressInIAT not found, startAddress " PRINTF_DWORD_PTR_FULL, startAddress);
#endif
		return false;
	}
	
	return findIATStartAndSize(addressInIAT, addressIAT, sizeIAT);
}

bool IATSearch::findIATAdvanced( DWORD_PTR startAddress, DWORD_PTR* addressIAT, DWORD* sizeIAT )
{
	BYTE *dataBuffer = nullptr;
	DWORD_PTR baseAddress = 0;
	SIZE_T memorySize = 0;

	findExecutableMemoryPagesByStartAddress(startAddress, &baseAddress, &memorySize);

	if (memorySize == 0)
		return false;

	dataBuffer = new BYTE[memorySize];

	if (!dataBuffer)
		return false;

	if (!readMemoryFromProcess(baseAddress, memorySize, dataBuffer))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"findAPIAddressInIAT2 :: error reading memory");
#endif
		delete[] dataBuffer;
		return false;
	}

	std::set<DWORD_PTR> iatPointers;
	DWORD_PTR next = 0;
	BYTE* tempBuf = dataBuffer;
	
	while(decomposeMemory(tempBuf, memorySize, baseAddress) && decomposerInstructionsCount != 0)
	{
		findIATPointers(iatPointers);

		next = static_cast<DWORD_PTR>(decomposerResult[decomposerInstructionsCount - 1].addr - baseAddress);
		next += decomposerResult[decomposerInstructionsCount - 1].size;
		
		// Advance ptr and recalc offset.
		tempBuf += next;

		if (memorySize <= next)
		{
			break;
		}
		
		memorySize -= next;
		baseAddress += next;
	}

	if (iatPointers.empty())
	{
		delete[] dataBuffer;
		return false;
	}

	filterIATPointersList(iatPointers);

	if (iatPointers.empty())
	{
		delete[] dataBuffer;
		return false;
	}

	*addressIAT = *(iatPointers.begin());
	*sizeIAT = static_cast<DWORD>(*(--iatPointers.end()) - *(iatPointers.begin()) + sizeof(DWORD_PTR));

	//some check, more than 2 million addresses?
	if (static_cast<DWORD>(2000000*sizeof(DWORD_PTR)) < *sizeIAT)
	{
		*addressIAT = 0;
		*sizeIAT = 0;
		delete[] dataBuffer;
		return false;
	}

	Allycs::windowLog.log(L"IAT Search Adv: Found %d (0x%X) possible IAT entries.", iatPointers.size(), iatPointers.size());
	Allycs::windowLog.log(L"IAT Search Adv: Possible IAT first " PRINTF_DWORD_PTR_FULL L" last " PRINTF_DWORD_PTR_FULL L" entry.", *(iatPointers.begin()), *(--iatPointers.end()));

	delete[] dataBuffer;

	return true;
}

DWORD_PTR IATSearch::findAPIAddressInIAT(DWORD_PTR startAddress)
{
	const size_t MEMORY_READ_SIZE = 200;
	BYTE dataBuffer[MEMORY_READ_SIZE];

	DWORD_PTR iatPointer = 0;
	int counter = 0;

	// to detect stolen api
	memoryAddress = 0;
	memorySize = 0;

	do 
	{
		counter++;

		if (!readMemoryFromProcess(startAddress, sizeof(dataBuffer), dataBuffer))
		{
#ifdef DEBUG_COMMENTS
			Allycs::debugLog.log(L"findAPIAddressInIAT :: error reading memory " PRINTF_DWORD_PTR_FULL, startAddress);
#endif
			return 0;
		}

		if (decomposeMemory(dataBuffer, sizeof(dataBuffer), startAddress))
		{
			iatPointer = findIATPointer();
			if (iatPointer)
			{
				if (isIATPointerValid(iatPointer, true))
				{
					return iatPointer;
				}
			}
		}

		startAddress = findNextFunctionAddress();
		//printf("startAddress %08X\n",startAddress);
	} while (startAddress != 0 && counter != 8);

	return 0;
}

DWORD_PTR IATSearch::findNextFunctionAddress()
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{

		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
					if (decomposerResult[i].ops[0].type == O_PC)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Allycs::debugLog.log(L"%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_TARGET(&decomposerResult[i]));
#endif
						return (DWORD_PTR)INSTRUCTION_GET_TARGET(&decomposerResult[i]);
					}
				}
			}
		}
	}

	return 0;
}

DWORD_PTR IATSearch::findIATPointer()
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{
		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
#ifdef _WIN64
					if (decomposerResult[i].flags & FLAG_RIP_RELATIVE)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Allycs::debugLog.log(L"%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
#endif
						return INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]);
					}
#else
					if (decomposerResult[i].ops[0].type == O_DISP)
					{
						//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Allycs::debugLog.log(L"%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, decomposerResult[i].disp);
#endif
						return (DWORD_PTR)decomposerResult[i].disp;
					}
#endif
				}
			}
		}
	}

	return 0;
}

bool IATSearch::isIATPointerValid(DWORD_PTR iatPointer, bool checkRedirects)
{
	DWORD_PTR apiAddress = 0;

	if (!readMemoryFromProcess(iatPointer, sizeof(DWORD_PTR), &apiAddress))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"isIATPointerValid :: error reading memory");
#endif
		return false;
	}

	//printf("Win api ? %08X\n",apiAddress);

	if (isApiAddressValid(apiAddress) != 0)
	{
		return true;
	}
	else
	{
        if (checkRedirects)
        {
            //maybe redirected import?
            //if the address is 2 times inside a memory region it is possible a redirected api
            if (apiAddress > memoryAddress && apiAddress < (memoryAddress+memorySize))
            {
                return true;
            }
            else
            {
                getMemoryRegionFromAddress(apiAddress, &memoryAddress, &memorySize);
            }
        } 
	}

    return false;
}

bool IATSearch::findIATStartAndSize(DWORD_PTR address, DWORD_PTR * addressIAT, DWORD * sizeIAT)
{
	BYTE *dataBuffer = nullptr;
    DWORD_PTR baseAddress = 0;
    DWORD baseSize = 0;

    getMemoryBaseAndSizeForIat(address, &baseAddress, &baseSize);

    if (!baseAddress)
        return false;

	dataBuffer = new BYTE[baseSize * (sizeof(DWORD_PTR)*3)];

    if (!dataBuffer)
        return false;

	ZeroMemory(dataBuffer, baseSize * (sizeof(DWORD_PTR)*3));

	if (!readMemoryFromProcess(baseAddress, baseSize, dataBuffer))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"findIATStartAddress :: error reading memory");
#endif
		delete [] dataBuffer;
		return false;
	}

	//printf("address %X memBasic.BaseAddress %X memBasic.RegionSize %X\n",address,memBasic.BaseAddress,memBasic.RegionSize);

	*addressIAT = findIATStartAddress(baseAddress, address, dataBuffer);
	*sizeIAT = findIATSize(baseAddress, *addressIAT, dataBuffer, baseSize);

	delete [] dataBuffer;

	return true;
}

DWORD_PTR IATSearch::findIATStartAddress(DWORD_PTR baseAddress, DWORD_PTR startAddress, BYTE * dataBuffer)
{
	DWORD_PTR *pIATAddress = 0;

	pIATAddress = (DWORD_PTR *)((startAddress - baseAddress) + (DWORD_PTR)dataBuffer);

	while((DWORD_PTR)pIATAddress != (DWORD_PTR)dataBuffer)
	{
		if (isInvalidMemoryForIat(*pIATAddress))
		{
            if ((DWORD_PTR)(pIATAddress - 1) >= (DWORD_PTR)dataBuffer)
            {
                if (isInvalidMemoryForIat(*(pIATAddress - 1)))
                {
                    if ((DWORD_PTR)(pIATAddress - 2) >= (DWORD_PTR)dataBuffer)
                    {
                        if (!isApiAddressValid(*(pIATAddress - 2)))
                        {
                            return (((DWORD_PTR)pIATAddress - (DWORD_PTR)dataBuffer) + baseAddress);
                        }
                    }
                }
            }
		}

		pIATAddress--;
	}

	return baseAddress;
}

DWORD IATSearch::findIATSize(DWORD_PTR baseAddress, DWORD_PTR iatAddress, BYTE * dataBuffer, DWORD bufferSize)
{
	DWORD_PTR *pIATAddress = 0;

	pIATAddress = (DWORD_PTR *)((iatAddress - baseAddress) + (DWORD_PTR)dataBuffer);

#ifdef DEBUG_COMMENTS
	Allycs::debugLog.log(L"findIATSize :: baseAddress %X iatAddress %X dataBuffer %X pIATAddress %X", baseAddress, iatAddress, dataBuffer, pIATAddress);
#endif

	while((DWORD_PTR)pIATAddress < ((DWORD_PTR)dataBuffer + bufferSize - 1))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"findIATSize :: %X %X %X", pIATAddress, *pIATAddress, *(pIATAddress + 1));
#endif
		if (isInvalidMemoryForIat(*pIATAddress)) //normal is 0
		{
			if (isInvalidMemoryForIat(*(pIATAddress + 1)))
			{
				//IAT end
				if (!isApiAddressValid(*(pIATAddress + 2)))
				{
					return (DWORD)((DWORD_PTR)pIATAddress - (DWORD_PTR)dataBuffer - (iatAddress - baseAddress));
				}
			}
		}

		pIATAddress++;
	}

	return bufferSize;
}

void IATSearch::findIATPointers(std::set<DWORD_PTR> & iatPointers)
{
#ifdef DEBUG_COMMENTS
	_DecodedInst inst;
#endif

	for (unsigned int i = 0; i < decomposerInstructionsCount; i++)
	{
		if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
		{
			if (META_GET_FC(decomposerResult[i].meta) == FC_CALL || META_GET_FC(decomposerResult[i].meta) == FC_UNC_BRANCH)
			{
				if (decomposerResult[i].size >= 5)
				{
#ifdef _WIN64
					if (decomposerResult[i].flags & FLAG_RIP_RELATIVE)
					{
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Allycs::debugLog.log(L"%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
#endif
						iatPointers.insert(INSTRUCTION_GET_RIP_TARGET(&decomposerResult[i]));
					}
#else
					if (decomposerResult[i].ops[0].type == O_DISP)
					{
						//jmp dword ptr || call dword ptr
#ifdef DEBUG_COMMENTS
						distorm_format(&decomposerCi, &decomposerResult[i], &inst);
						Allycs::debugLog.log(L"%S %S %d %d - target address: " PRINTF_DWORD_PTR_FULL, inst.mnemonic.p, inst.operands.p, decomposerResult[i].ops[0].type, decomposerResult[i].size, decomposerResult[i].disp);
#endif
						iatPointers.insert((DWORD_PTR)decomposerResult[i].disp);
					}
#endif
				}
			}
		}
	}


}

void IATSearch::findExecutableMemoryPagesByStartAddress(DWORD_PTR startAddress, DWORD_PTR* baseAddress, SIZE_T* memorySize)
{
	MEMORY_BASIC_INFORMATION memBasic{};
	DWORD_PTR tempAddress;

	*memorySize = 0;
	*baseAddress = 0;

	NTSTATUS status = SysQueryVirtualMemory(
		hProcess,
		reinterpret_cast<PVOID>(startAddress),
		MemoryBasicInformation,
		&memBasic,
		sizeof(memBasic),
		nullptr
	);

	if (!NT_SUCCESS(status))
	{
#ifdef DEBUG_COMMENTS
		Allycs::debugLog.log(L"findIATStartAddress :: SysQueryVirtualMemory error %u", GetLastError());
#endif
		return;
	}

	//search down
	do
	{
		*memorySize = memBasic.RegionSize;
		*baseAddress = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
		tempAddress = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress) - 1;

		status = SysQueryVirtualMemory(
			hProcess,
			reinterpret_cast<PVOID>(tempAddress),
			MemoryBasicInformation,
			&memBasic,
			sizeof(memBasic),
			nullptr
		);

		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (isPageExecutable(memBasic.Protect));

	tempAddress = *baseAddress;
	memBasic.RegionSize = *memorySize;
	*memorySize = 0;
	//search up
	do
	{
		tempAddress += memBasic.RegionSize;
		*memorySize += memBasic.RegionSize;

		status = SysQueryVirtualMemory(
			hProcess,
			reinterpret_cast<PVOID>(tempAddress),
			MemoryBasicInformation,
			&memBasic,
			sizeof(memBasic),
			nullptr
		);

		if (!NT_SUCCESS(status))
		{
			break;
		}
	} while (isPageExecutable(memBasic.Protect));
}

void IATSearch::filterIATPointersList( std::set<DWORD_PTR> & iatPointers )
{
	std::set<DWORD_PTR>::iterator iter;

	if (iatPointers.size() <= 2)
	{
		return;
	}

	iter = iatPointers.begin();
	std::advance(iter, iatPointers.size() / 2); //start in the middle, important!

	DWORD_PTR lastPointer = *iter;
	iter++;

	for (; iter != iatPointers.end(); iter++)
	{
		if ((*iter - lastPointer) > 0x100) //check difference
		{
            if (isIATPointerValid(lastPointer, false) == false || isIATPointerValid(*iter, false) == false)
            {
                iatPointers.erase(iter, iatPointers.end());
                break;
            }
            else
            {
                lastPointer = *iter;
            }
		}
		else
		{
			lastPointer = *iter;
		}
	}

	if (iatPointers.empty()) {
		return;
	}

	//delete bad code pointers.

	bool erased = true;

	while(erased)
	{
		if (iatPointers.size() <= 1)
			break;

		iter = iatPointers.begin();
		lastPointer = *iter;
		iter++;

		for (; iter != iatPointers.end(); iter++)
		{
			if ((*iter - lastPointer) > 0x100) //check pointer difference, a typical difference is 4 on 32bit systems
			{
				bool isLastValid = isIATPointerValid(lastPointer, false);
				bool isCurrentValid = isIATPointerValid(*iter, false);
                if (isLastValid == false || isCurrentValid == false)
                {
					if (isLastValid == false)
					{
						iter--;
					}
                    
                    iatPointers.erase(iter);
                    erased = true;
                    break;
                }
                else
                {
                    erased = false;
                    lastPointer = *iter;
                }
			}
			else
			{
				erased = false;
				lastPointer = *iter;
			}
		}
	}

}

//A big section size is a common anti-debug/anti-dump trick, limit the max size to 100 000 000 bytes

void adjustSizeForBigSections(DWORD* badValue)
{
	if (*badValue > 100000000)
	{
		*badValue = 100000000;
	}
}

bool isSectionSizeTooBig(SIZE_T sectionSize) 
{
	return (sectionSize > 100000000);
}

void IATSearch::getMemoryBaseAndSizeForIat(DWORD_PTR address, DWORD_PTR* baseAddress, DWORD* baseSize)
{
    MEMORY_BASIC_INFORMATION memBasic1{};
    MEMORY_BASIC_INFORMATION memBasic2{};
    MEMORY_BASIC_INFORMATION memBasic3{};

    DWORD_PTR start = 0, end = 0;
    *baseAddress = 0;
    *baseSize = 0;

    NTSTATUS status = SysQueryVirtualMemory(
        hProcess,
        reinterpret_cast<PVOID>(address),
        MemoryBasicInformation,
        &memBasic2,
        sizeof(memBasic2),
        nullptr
    );

    if (!NT_SUCCESS(status))
    {
        return;
    }

    *baseAddress = reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress);
    *baseSize = static_cast<DWORD>(memBasic2.RegionSize);

    adjustSizeForBigSections(baseSize);

    //Get the neighbours
    DWORD_PTR prevAddress = reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) - 1;
    status = SysQueryVirtualMemory(
        hProcess,
        reinterpret_cast<PVOID>(prevAddress),
        MemoryBasicInformation,
        &memBasic1,
        sizeof(memBasic1),
        nullptr
    );

    if (NT_SUCCESS(status))
    {
        DWORD_PTR nextAddress = reinterpret_cast<DWORD_PTR>(memBasic2.BaseAddress) + 
                               static_cast<DWORD_PTR>(memBasic2.RegionSize);
        
        status = SysQueryVirtualMemory(
            hProcess,
            reinterpret_cast<PVOID>(nextAddress),
            MemoryBasicInformation,
            &memBasic3,
            sizeof(memBasic3),
            nullptr
        );

        if (NT_SUCCESS(status))
        {
            if (memBasic3.State != MEM_COMMIT || 
                memBasic1.State != MEM_COMMIT || 
                memBasic3.Protect & PAGE_NOACCESS || 
                memBasic1.Protect & PAGE_NOACCESS)
            {
                return;
            }
            else
            {
                if (isSectionSizeTooBig(memBasic1.RegionSize) || 
                    isSectionSizeTooBig(memBasic2.RegionSize) || 
                    isSectionSizeTooBig(memBasic3.RegionSize)) {
                    return;
                }

                start = reinterpret_cast<DWORD_PTR>(memBasic1.BaseAddress);
                end = reinterpret_cast<DWORD_PTR>(memBasic3.BaseAddress) + 
                     static_cast<DWORD_PTR>(memBasic3.RegionSize);

                *baseAddress = start;
                *baseSize = static_cast<DWORD>(end - start);
            }
        }
    }
}
