@echo off

echo +++ Payload: none - allocation type: private - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type private
echo.
echo +++ Payload: none - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type private --stealth rw-rx
echo.

echo +++ Payload: shellcode - allocation type: private - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private
echo.
echo +++ Payload: shellcode - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private --stealth rw-rx
echo.

echo +++ Payload: shellcode - allocation type: private - stealth: moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private --stealth moat
echo.
echo +++ Payload: shellcode - allocation type: private - stealth: RW + RX + moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private --stealth rw-rx moat
echo.

echo +++ Payload: PE - allocation type: private - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private
echo.
echo +++ Payload: PE - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private --stealth rw-rx
echo.

echo +++ Payload: PE - allocation type: private - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private --stealth rw-rx moat
echo.
echo +++ Payload: PE - allocation type: private - stealth: moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private --stealth moat
echo.

echo +++ Payload: PE - allocation type: private - stealth: RW + RX, header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private --stealth rw-rx wipe-headers
echo.
echo +++ Payload: PE - allocation type: private - stealth: header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type private --stealth wipe-headers
echo.