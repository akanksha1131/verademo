@echo off
REM Define the database path
set DB_PATH=C:\Users\AKANKSHA KALE\AppData\Roaming\Code\User\workspaceStorage\4ce96addddc27736cd7edc303aa8a1a2\GitHub.vscode-codeql\akanksha1131-verademo-1\java

REM Define the paths for the query
set QUERY_PATH_1=C:\Users\AKANKSHA KALE\Desktop\verademo\codeql-custom-queries-java\path3.ql

REM Define the output files for each query
set REPORT_FILE_1=C:\Users\AKANKSHA KALE\Desktop\verademo\path.sarif


REM Step 1: Check if the database exists
if exist "%DB_PATH%" (
    echo Using existing CodeQL database at: %DB_PATH%
) else (
    echo Error: CodeQL database not found at %DB_PATH%.
    exit /b 1
)

REM Step 2: Delete old report files if they exist
if exist "%REPORT_FILE_1%" (
    echo Deleting old sarif report file: %REPORT_FILE_1%
    del "%REPORT_FILE_1%"
)

REM Step 3: Run analysis for each query and generate sarif reports
echo Finding Paths
"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe" database analyze --rerun "%DB_PATH%" "%QUERY_PATH_1%" --format=sarif-latest --output="%REPORT_FILE_1%" --sarif-add-snippets

REM Step 4: Notify the user that the analyses are complete
echo Analysis complete. Reports generated as:
echo %REPORT_FILE_1%

pause
