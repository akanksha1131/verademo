import json
import subprocess
import os

# Define the database path
DB_PATH = r"C:\Users\AKANKSHA KALE\AppData\Roaming\Code\User\workspaceStorage\4ce96addddc27736cd7edc303aa8a1a2\GitHub.vscode-codeql\akanksha1131-verademo-1\java"

# Define the output CSV report path
CSV_REPORT_FILE = r"C:\Users\AKANKSHA KALE\Desktop\verademo\cwe_89_path.csv"

# Define paths for the source and sink JSON files
SOURCE_JSON_PATH = r"C:\Users\AKANKSHA KALE\Desktop\verademo\source.json"
SINK_JSON_PATH = r"C:\Users\AKANKSHA KALE\Desktop\verademo\sink.json"

# Load source and sink JSON files
with open(SOURCE_JSON_PATH, 'r') as source_file:
    source_data = json.load(source_file)

with open(SINK_JSON_PATH, 'r') as sink_file:
    sink_data = json.load(sink_file)

# Extract source and sink method signatures from the JSON files
source_signatures = [entry["signature"] for entry in source_data.get("response", [])]
sink_signatures = [entry["signature"] for entry in sink_data.get("response", [])]

# Prepare the dynamic predicates for sources and sinks
source_predicates = " or ".join([f'this.getSignature() = "{sig}"' for sig in source_signatures])
sink_predicates = " or ".join([f'this.getSignature() = "{sig}"' for sig in sink_signatures])

# Define the query template with placeholders
query_template = """
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjectionQuery
import QueryInjectionFlow::PathGraph

// Define dynamic allowed source methods
class SourceMethod extends Method {{
  predicate isAllowedSource() {{
    {source_predicates}
  }}
}}

// Define dynamic allowed sink methods
class SinkMethod extends Method {{
  predicate isAllowedSink() {{
    {sink_predicates}
  }}
}}

// Define the query flow from user-controlled sources to sinks
from QueryInjectionSink query, QueryInjectionFlow::PathNode source, QueryInjectionFlow::PathNode sink
where
  queryIsTaintedBy(query, source, sink) and
  source.getMethod().isAllowedSource() and
  query.getMethod().isAllowedSink()
select query, source, sink, 
  "This query depends on a user-provided value", 
  source.getNode(), 
  "user-provided value"
"""

# Format the query by inserting the predicates
query = query_template.format(source_predicates=source_predicates, sink_predicates=sink_predicates)

# Save the dynamically generated query to a .ql file
generated_query_path = r"C:\Users\AKANKSHA KALE\Desktop\verademo\generated_query.ql"
with open(generated_query_path, 'w') as query_file:
    query_file.write(query)

# Check if the database exists
if not os.path.exists(DB_PATH):
    print(f"Error: CodeQL database not found at {DB_PATH}.")
    exit(1)

# Run the CodeQL query using the dynamically generated query file
command = [
    r"C:\Users\AKANKSHA KALE\Downloads\codeql-bundle-win64\codeql\codeql.exe",
    "database", "analyze", "--rerun", DB_PATH, generated_query_path,
    "--format=csv", "--output", CSV_REPORT_FILE
]

# Execute the CodeQL command and wait for it to finish
subprocess.run(command)

# Notify the user that the analysis is complete
print(f"Analysis complete. CSV report generated at: {CSV_REPORT_FILE}")
