# GetVirtualDesktopAPI_DIA

## How does it works

Uses Microsft MSDIA interface to parse PDB & get the corresponding symbols

## How to use it

1. You'll have to install requests & comtypes dependency
2. Make sure the msdia dll is present at target path (Mine is at C:\Program Files (x86)\Common Files\Microsoft Shared\VC\amd64\msdia80.dll)
3. simply run the DiaGetVDInfo.py in python.

## Example

see VirtualDesktopAPI_25247.log

## Develop

Use jupyter notebook to open DiaGetVDInfo.ipynb
