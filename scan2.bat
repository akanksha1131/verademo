@echo off
REM Define the database path
set DB_PATH=C:\Users\AKANKSHA KALE\AppData\Roaming\Code\User\workspaceStorage\4ce96addddc27736cd7edc303aa8a1a2\GitHub.vscode-codeql\akanksha1131-verademo-1\java

REM Define the paths for the query
set QUERY_PATH_1=C:\Users\AKANKSHA KALE\Desktop\verademo\codeql-custom-queries-java\example.ql

REM Define the output files for each query
set CSV_REPORT_FILE_1=C:\Users\AKANKSHA KALE\Desktop\verademo\source_candidates_with_body.csv


REM Step 1: Check if the database exists
if exist "%DB_PATH%" (
    echo Using existing CodeQL database at: %DB_PATH%
) else (
    echo Error: CodeQL database not found at %DB_PATH%.
    exit /b 1
)

REM Step 2: Delete old report files if they exist
if exist "%CSV_REPORT_FILE_1%" (
    echo Deleting old CSV report file: %CSV_REPORT_FILE_1%
    del "%CSV_REPORT_FILE_1%"
)

REM Step 3: Run analysis for each query and generate CSV reports
echo Running analysis for example2.ql and generating CSV report...
"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe" database analyze --rerun "%DB_PATH%" "%QUERY_PATH_1%" --format=csv --output="%CSV_REPORT_FILE_1%"

REM Step 4: Notify the user that the analyses are complete
echo Analysis complete. CSV reports generated as:
echo %CSV_REPORT_FILE_1%
pause
