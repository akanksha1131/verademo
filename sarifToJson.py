import json

# Input and output file paths
input_file = r"C:\Users\AKANKSHA KALE\Desktop\verademo\path.sarif"  # Use raw string
output_file = r"C:\Users\AKANKSHA KALE\Desktop\verademo\paths.json"  # Use raw string

# Load the SARIF file
with open(input_file, 'r') as file:
    sarif_data = json.load(file)

# Extract results from the SARIF data
results = []
if "runs" in sarif_data:
    for run in sarif_data["runs"]:
        if "results" in run:
            results.extend(run["results"])

# Save the extracted results to a new JSON file
with open(output_file, 'w') as file:
    json.dump(results, file, indent=4)

print(f"Extracted results saved to {output_file}")
