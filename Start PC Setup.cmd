@echo off
cls
echo.
echo Before running this script, ensure you have a decent internet connection
echo PC should be named correctly, added to the domain, and proxy disabled
echo Portable Apps should be pre-downloaded and located in C:\OneDrive\Apps
echo I need to be run from C:\Temp and need 'Custom_Build_PC.ps1' and 'Win10_Tweaks.ps1' in same folder
echo.
pause
powershell set-executionpolicy unrestricted
powershell "C:\Temp\Custom_Build_PC.ps1"