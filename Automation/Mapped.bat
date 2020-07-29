@echo off

echo +++ Payload: none - allocation type: mapped - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type mapped
echo.
echo +++ Payload: none - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type mapped --stealth rw-rx
echo.

echo +++ Payload: shellcode - allocation type: mapped - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped
echo.
echo +++ Payload: shellcode - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped --stealth rw-rx
echo.

echo +++ Payload: shellcode - allocation type: mapped - stealth: moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped --stealth moat
echo.
echo +++ Payload: shellcode - allocation type: mapped - stealth: RW + RX + moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type mapped --stealth rw-rx moat
echo.

echo +++ Payload: PE - allocation type: mapped - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped
echo.
echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped --stealth rw-rx
echo.

echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped --stealth rw-rx moat
echo.
echo +++ Payload: PE - allocation type: mapped - stealth: moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped --stealth moat
echo.

echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX, header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped --stealth rw-rx wipe-headers
echo.
echo +++ Payload: PE - allocation type: mapped - stealth: header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type pe --payload-file Payloads\TestExe32.exe --alloc-type mapped --stealth wipe-headers
echo.