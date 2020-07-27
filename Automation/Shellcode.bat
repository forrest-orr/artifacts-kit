@echo off
rem 10 total

echo +++ Payload: shellcode - allocation type: load library - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-load-hollow
echo.
echo +++ Payload: shellcode - allocation type: load library - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-load-hollow --stealth dotnet
echo.

echo +++ Payload: shellcode - allocation type: image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-map-hollow
echo.
echo +++ Payload: shellcode - allocation type: image mapping - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-map-hollow --stealth dotnet
echo.

echo +++ Payload: shellcode - allocation type: TxF image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type txf-dll-map-hollow
echo.
echo +++ Payload: shellcode - allocation type: TxF image mapping - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type txf-dll-map-hollow --stealth dotnet
echo.

echo +++ Payload: shellcode - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private --stealth rw-rx
echo.
echo +++ Payload: shellcode - allocation type: private - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private --stealth rw-rx moat
echo.

echo +++ Payload: shellcode - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped --stealth rw-rx
echo.
echo +++ Payload: shellcode - allocation type: mapped - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped --stealth rw-rx moat
echo.

pause