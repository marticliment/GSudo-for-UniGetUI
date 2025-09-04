@echo off

pushd src\gsudo
rmdir /q /s bin
dotnet clean
dotnet publish --nologo -c Release
popd

rmdir /q /s output
mkdir output
move "src\gsudo\bin\Release\net9.0\win-x64\publish\UniGetUI Elevator.exe" output\
move "src\gsudo\bin\Release\net9.0\win-x64\publish\getfilesiginforedist.dll" output\

:sign_retry
%SIGNCOMMAND% "%cd%\output\UniGetUI Elevator.exe"
if errorlevel 1 (
    echo Signing failed. Press 'r' to retry, any other key to continue.
    set /p userinput=Your choice: 
    if /i "%userinput%"=="r" goto sign_retry
)

echo "Resulting files from build available at %cd%\output"
pause