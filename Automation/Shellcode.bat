@echo off
echo +++ Payload: shellcode - allocation type: load library - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-load-hollow
echo.
echo +++ Payload: shellcode - allocation type: image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type dll-map-hollow
echo.
echo +++ Payload: shellcode - allocation type: TxF image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type txf-dll-map-hollow
echo +++ Payload: shellcode - allocation type: private - stealth: RW -> RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MsgboxShellcode32.bin --alloc-type private
pause