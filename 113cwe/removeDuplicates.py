import csv

# Define file paths
source_input_file = "C:\\Users\\AKANKSHA KALE\\Desktop\\verademo\\113cwe\\src113.csv"
sink_input_file = "C:\\Users\\AKANKSHA KALE\\Desktop\\verademo\\113cwe\\snk113.csv"
source_output_file = "C:\\Users\\AKANKSHA KALE\\Desktop\\verademo\\113cwe\\distinct_src113.csv"
sink_output_file = "C:\\Users\\AKANKSHA KALE\\Desktop\\verademo\\113cwe\\distinct_snk113.csv"


# Clear content of output files to start afresh
open(source_output_file, 'w').close()
open(sink_output_file, 'w').close()

def remove_duplicates(input_file, output_file, key_column_index=3):
    # Set to store unique records based on specific columns
    unique_records = set()
    deduplicated_rows = []

    # Open the input CSV file
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.reader(infile)
        
        # Extract header and add it to deduplicated rows
        header = next(reader)
        deduplicated_rows.append(header)

        # Iterate over each row in the CSV file
        for row in reader:
            # Select columns to use for duplicate detection (description in this case)
            record_key = (row[key_column_index],)  # Using the description field as a unique key
            
            # Add row to deduplicated list if it hasn't been seen before
            if record_key not in unique_records:
                unique_records.add(record_key)
                deduplicated_rows.append(row)

    # Write deduplicated rows to output CSV file
    with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(deduplicated_rows)

# Run deduplication for both source and sink files
remove_duplicates(source_input_file, source_output_file)
remove_duplicates(sink_input_file, sink_output_file)

print("Deduplication complete. Distinct rows saved to output files.")
