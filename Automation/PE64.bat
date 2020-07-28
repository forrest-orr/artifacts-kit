@echo off
rem 18 total

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
echo +++ Payload: PE - allocation type: load library - stealth: moating
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow --stealth moat
echo.

echo +++ Payload: PE - allocation type: image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: header mirroring
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow --stealth mirror-headers
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: header wiping
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-map-hollow --stealth wipe-headers
echo.
echo +++ Payload: PE - allocation type: image mapping - stealth: moating
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type dll-load-hollow --stealth moat
echo.

echo +++ Payload: PE - allocation type: TxF image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow
echo.
echo +++ Payload: PE - allocation type: TxF image mapping - stealth: header mirroring
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --stealth mirror-headers
echo.
echo +++ Payload: PE - allocation type: TxF image mapping - stealth: header wiping
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type txf-dll-map-hollow --stealth wipe-headers
echo.


echo +++ Payload: PE - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type private --stealth rw-rx
echo.

echo +++ Payload: PE - allocation type: private - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type private --stealth rw-rx moat
echo.

echo +++ Payload: PE - allocation type: private - stealth: RW + RX, header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type private --stealth rw-rx wipe-headers
echo.


echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type mapped --stealth rw-rx
echo.

echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX, moat
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type mapped --stealth rw-rx moat
echo.

echo +++ Payload: PE - allocation type: mapped - stealth: RW + RX, header wipe
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\x64\Release\ArtifactsKit64.exe --payload-type pe --payload-file Payloads\TestExe64.exe --alloc-type mapped --stealth rw-rx wipe-headers
echo.

rem Note that header wipe and moating can be combined but are not in this series of tests


pause