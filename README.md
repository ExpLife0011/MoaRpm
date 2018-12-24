# MoaRpm

MoaRpm is the mother-of-all ReadProcessMemory classes.  It can use the standard winapis, hidden ntdll functions, or even a driver to read/write memory without handles.

All reading/writing syntax is identical no matter what method you use, simply specify in the constructor.

### Driver Loading

This even contains the code to check if you're running the tool as administrator, if you're in test mode (able to load unsigned drivers), and it creates the driver service and loads it for you.

It can read/write memory in templates, as well char*s (thanks to magicm8).  Driver source based on work by kcorj2244.

### Usage

```cpp
#include "kRpm.h"
#include <iostream>

int main()
{
	MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::KERNEL);
	//MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::NTDLL);
	//MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::STANDARD);
	auto pGameContext = rpm.read<DWORD_PTR>(0x142AE8080);
	auto pPlayerManager = rpm.read<DWORD_PTR>(pGameContext + 0x68);
	auto pLocalPlayer = rpm.read<DWORD_PTR>(pPlayerManager + 0x550);
	auto pLocalSoldier = rpm.read<DWORD_PTR>(pLocalPlayer + 0x2cb8);
	rpm.write<byte>(pLocalSoldier + 0x02AC, 240);
	auto playerName = rpm.readString(rpm.read<DWORD_PTR>(pLocalPlayer + 0x18));
	std::cout <<  "player name\t" << playerName << std::endl;
	getchar();
	return 0;
}
```
Yep, it's that easy.

## Modes

*Standard* (ReadProcessMemory/WriteProcessMemory)
```cpp
MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::STANDARD);
```

*NTDLL* (ReadVirtualMemory/WriteVirtualMemory)
```cpp
MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::NTDLL);
```

*kernel* (MmCopyVirtualMemory)
```cpp
MoaRpm rpm("star wars battlefront", MoaRpm::MOA_MODE::KERNEL);
```