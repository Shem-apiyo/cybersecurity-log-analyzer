# Cybersecurity Log Analyzer

A C++ console application that analyzes mixed security log formats and scans local Chrome/Chromium profile configuration files for potentially risky browser settings or extension permissions.

## About

Cybersecurity Log Analyzer is a Windows-friendly C++ security tool for reviewing sample or real log files, identifying suspicious activity, and checking local Chrome-based browser profiles for risky extension permissions. It is built for learning, auditing, and practicing basic defensive security analysis from the command line.

## Features

- Parses custom application login logs.
- Parses Apache/Nginx-style web access logs.
- Parses Linux SSH authentication logs.
- Detects suspicious activity such as brute-force attempts, admin-page probing, SQL injection patterns, path traversal attempts, and unusual HTTP errors.
- Exports summary reports as text and CSV files.
- Scans real local Chrome, Chromium, and Edge profile folders for:
  - profile `Preferences`
  - browser `Local State`
  - extension `manifest.json` files

The Chrome scan does not read saved passwords, cookies, or decrypted secret data.

## Build

This project is configured for MinGW on Windows.

```powershell
C:\MinGW\bin\g++.exe -fdiagnostics-color=always -g Untitled-1.cpp -o Untitled-1.exe
```

You can also use the included VS Code tasks and launch configuration.

## Run

```powershell
.\Untitled-1.exe
```

Choose option `3` to scan real local Chrome/Chromium profile data. Press Enter to scan detected folders, or paste a custom Chrome `User Data` path.
