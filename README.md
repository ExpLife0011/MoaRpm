# MoaRpm

MoaRpm is the mother-of-all ReadProcessMemory classes.  It can use the standard winapis, hidden ntdll functions, or even a driver to read/write memory without handles.

All reading/writing syntax is identical no matter what method you use, simply specify in the constructor.

### Driver Loading

This even contains the code to check if you're running the tool as administrator, if you're in test mode (able to load unsigned drivers), and it creates the driver service and loads it for you.

It can read/write memory in templates, as well char*s (thanks to magicm8).  Driver source based on work by kcorj2244.