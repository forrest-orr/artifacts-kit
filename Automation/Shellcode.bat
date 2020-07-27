@echo off
echo Payload: shellcode - allocation type: load library - stealthL none
..\ArtifactsKit\Release\ArtifactsKit32.exe --payload-type shellcode --payload-file Payloads\MessageBox32.bin
pause