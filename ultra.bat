set ext=.vnc
set ass=VncViewer.Config
set exe=%%ProgramFiles%%\uvnc bvba\UltraVNC\vncviewer.exe
set opt=-config \"%%1\"

reg add "HKCR\%ext%" /f /ve /t REG_SZ /d %ass%

reg add "HKCR\%ass%" /f /ve /t REG_SZ /d "VNCviewer Config File"
reg add "HKCR\%ass%\DefaultIcon" /f /ve /t REG_SZ /d "%exe%,0"
reg add "HKCR\%ass%\shell\open\command" /f /ve /t REG_EXPAND_SZ /d "\"%exe%\" %opt%"

assoc %ext%
ftype %ass%
start hp%ext%

pause