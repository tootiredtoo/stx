@echo off
setlocal enabledelayedexpansion

:: File to store the generated data
set "output_file=test_file.dat"

:: Generate 5MB of random data using PowerShell
powershell -Command ^
$rand = [System.Security.Cryptography.RandomNumberGenerator]::Create(); ^
$bytes = New-Object byte[] 5242880; ^
$rand.GetBytes($bytes); ^
[System.IO.File]::WriteAllBytes('!output_file!', $bytes)

echo 5MB file created: %output_file%
