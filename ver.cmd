cd /d %~dp0
attrib VERSION|find "A            "&&call :newVer
attrib winres\*|find "A            "&&call :newWinres
goto :EOF

:newVer
attrib -a VERSION
set /p VERSION=<VERSION
git tag v%VERSION%-lw
git push origin --tags

:newWinres
attrib -a winres\*
go-winres make --product-version=git-tag --file-version=git-tag