@echo off

echo +++ Payload: none - allocation type: image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type dll-map-hollow
echo.

echo +++ Payload: none - allocation type: TxF image mapping - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type txf-dll-map-hollow
echo.

echo +++ Payload: none - allocation type: private - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type private
echo.

echo +++ Payload: none - allocation type: private - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type private --stealth rw-rx
echo.

echo +++ Payload: none - allocation type: mapped - stealth: none
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type mapped
echo.

echo +++ Payload: none - allocation type: mapped - stealth: RW + RX
echo ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
..\ArtifactsKit\Release\ArtifactsKit32.exe --alloc-type mapped --stealth rw-rx
echo.

pause