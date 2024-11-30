@echo off
REM CWE 113: Define the database path
set "DB_PATH=C:\Users\AKANKSHA KALE\AppData\Roaming\Code\User\workspaceStorage\4ce96addddc27736cd7edc303aa8a1a2\GitHub.vscode-codeql\akanksha1131-verademo-1\java"

REM CWE 113: Define the paths for the three queries
set "QUERY_PATH_1=C:\Users\AKANKSHA KALE\Desktop\verademo\codeql-custom-queries-java\cwe113\src113.ql"
set "QUERY_PATH_2=C:\Users\AKANKSHA KALE\Desktop\verademo\codeql-custom-queries-java\cwe113\snk113.ql"
set "QUERY_PATH_3=C:\Users\AKANKSHA KALE\Desktop\verademo\codeql-custom-queries-java\cwe113\path113.ql"

REM CWE 113: Define the output files for each query
set "CSV_REPORT_FILE_1=C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\src113.csv"
set "CSV_REPORT_FILE_2=C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\snk113.csv"
set "SARIF_REPORT_FILE=C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\path113.sarif"

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
if exist "%CSV_REPORT_FILE_2%" (
    echo Deleting old CSV report file: %CSV_REPORT_FILE_2%
    del "%CSV_REPORT_FILE_2%"
)
if exist "%SARIF_REPORT_FILE%" (
    echo Deleting old SARIF report file: %SARIF_REPORT_FILE%
    del "%SARIF_REPORT_FILE%"
)

REM Step 3: Run analysis for each query and generate CSV reports
echo Running analysis for src113.ql and generating CSV report...
"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe" database analyze --rerun "%DB_PATH%" "%QUERY_PATH_1%" --format=csv --output="%CSV_REPORT_FILE_1%"

echo Running analysis for snk113.ql and generating CSV report...
"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe" database analyze --rerun "%DB_PATH%" "%QUERY_PATH_2%" --format=csv --output="%CSV_REPORT_FILE_2%"

echo Step 3: Analysis complete. CSV reports generated:
echo %CSV_REPORT_FILE_1%
echo %CSV_REPORT_FILE_2%

REM Step 4: Remove duplicates from src and snk CSV
echo Removing duplicates from src and snk CSV files...
python "C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\removeDuplicates.py"

REM Step 5: LLM validation for source and sink candidates
echo Validating source and sink candidates using LLM...
python "C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\step2.py"

REM Step 6: Run the path query and generate SARIF report
echo Running path query and generating SARIF report...
"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe" database analyze --rerun "%DB_PATH%" "%QUERY_PATH_3%" --format=sarif-latest --output="%SARIF_REPORT_FILE%" --sarif-add-snippets

echo SARIF report generated:
echo %SARIF_REPORT_FILE%

REM Step 7: Convert SARIF to JSON
echo Converting SARIF to JSON...
python "C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\sarifToJson.py"

REM Step 8: Extract paths with text
echo Extracting paths with text...
python "C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\extractPathWithText.py"

REM Step 9: Contextual analysis and report generation
echo Performing contextual analysis and generating report using LLM...
python "C:\Users\AKANKSHA KALE\Desktop\verademo\113cwe\step4.py"

echo CWE-113: All tasks completed successfully!
pause
