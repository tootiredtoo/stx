@echo off

:: Generate 5 MB of random data using PowerShell
powershell -Command "Add-Type -TypeDefinition 'using System; using System.IO; using System.Security.Cryptography; public class RandomGen { public static void GenerateFile(string path, long size) { byte[] data = new byte[8192]; RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider(); using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write)) { for (long i = 0; i < size; i += data.Length) { rng.GetBytes(data); fs.Write(data, 0, data.Length); } } } }'" 
powershell -Command "RandomGen.GenerateFile('test_file.dat', 5242880)"

:: Start stx-recv in the background to listen for the file
start /B stx-recv --port 12345

:: Wait a moment for stx-recv to be ready
timeout /t 2 /nobreak

:: Start stx-send to send the generated test_file.dat
stx-send --file test_file.dat --port 12345

:: Wait for stx-recv to finish receiving the file
timeout /t 10 /nobreak

:: Verify the file using certutil (sha256sum equivalent for Windows)
certutil -hashfile test_file.dat SHA256 > original_hash.txt
certutil -hashfile received_file.dat SHA256 > received_hash.txt

:: Compare the hashes
fc original_hash.txt received_hash.txt > nul
if %errorlevel% equ 0 (
    echo File is authentic. Saving the received file.
) else (
    echo File is not authentic. Transfer failed.
    exit /b 1
)
