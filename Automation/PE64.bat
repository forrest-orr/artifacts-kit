@echo off
rem 10 total

echo +++ Payload: PE - allocation type: load library - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow
echo.
echo +++ Payload: PE - allocation type: load library - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow --stealth dotnet
echo.
echo +++ Payload: PE - allocation type: load library - stealth: header mirroring
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow --stealth mirror-headers
echo.
echo +++ Payload: PE - allocation type: load library - stealth: header wiping
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow --stealth wipe-headers
echo.

echo +++ Payload: PE - allocation type: image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow --stealth dotnet
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: header mirroring
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow --stealth mirror-headers
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: header wiping
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow --stealth wipe-headers
echo.

echo +++ Payload: PE - allocation type: TxF image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow
echo.
echo +++ Payload: PE - allocation type: TxF image mapping - stealth: .NET
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --stealth dotnet
echo.
echo +++ Payload: PE - allocation type: TxF image mapping - stealth: header mirroring
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --stealth mirror-headers
echo.
echo +++ Payload: PE - allocation type: TxF image mapping - stealth: header wiping
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --stealth wipe-headers
echo.

pause