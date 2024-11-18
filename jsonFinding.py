import json

def extract_required_labels(json_file_path, output_file_path, function_names_file_path):
    """
    Extracts specific labels from every JSON element in the findings list
    and writes the results to text files.

    Args:
        json_file_path (str): Path to the JSON file.
        output_file_path (str): Path to the output text file for detailed findings.
        function_names_file_path (str): Path to the text file for function names.
    """
    with open(json_file_path, 'r') as file:
        data = json.load(file)
    
    findings = data.get("findings", [])
    extracted_data = []
    
    for finding in findings:
        source_file = finding.get("files", {}).get("source_file", {})
        extracted_data.append({
            "title": finding.get("title"),
            "issue_id": finding.get("issue_id"),
            "gob": finding.get("gob"),
            "severity": finding.get("severity"),
            "issue_type_id": finding.get("issue_type_id"),
            "issue_type": finding.get("issue_type"),
            "cwe_id": finding.get("cwe_id"),
            "display_text": finding.get("display_text"),
            "file": source_file.get("file"),
            "line": source_file.get("line"),
            "function_name": source_file.get("function_name"),
            "qualified_function_name": source_file.get("qualified_function_name"),
            "function_prototype": source_file.get("function_prototype"),
            "scope": source_file.get("scope"),
        })

    # Write detailed findings and function names to separate files
    with open(output_file_path, 'w') as output_file, open(function_names_file_path, 'w') as function_file:
        for item in extracted_data:
            function_name = item["function_name"]
            if function_name:
                function_file.write(f"{function_name}\n")

            output_file.write(json.dumps(item, indent=4))
            output_file.write("\n\n")

# Example usage
if __name__ == "__main__":
    json_file_path = input("Enter the path to the JSON file: ")
    output_file_path = input("Enter the path for the output text file: ")
    function_names_file_path = input("Enter the path for the function names file: ")

    extract_required_labels(json_file_path, output_file_path, function_names_file_path)
    print(f"Results have been written to {output_file_path}")
    print(f"Function names have been written to {function_names_file_path}")
