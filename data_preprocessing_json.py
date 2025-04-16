import json
import pandas as pd
import re
from openpyxl import Workbook
from openpyxl.styles import Font, Alignment

# Load the JSON rules
with open('json_final.json', 'r') as file:
    data = json.load(file)

# Access the "checks" key
checks = data.get("checks", [])

# Load keyword mapping from JSON
keyword_mapping = data.get("keyword_mapping", {})

# Function to search for a keyword in a log file and extract the next bits or value based on JSON rules
def search_keyword_in_log(log_file_path, keyword, rule):
    """
    Search for a keyword in a log file and extract the next value based on JSON rules.
    """
    with open(log_file_path, 'r') as file:
        lines = file.readlines()
    
    for line in lines:
        if keyword in line:
            print(f"Keyword found: {keyword} in line: {line.strip()}")  # Debugging print
            # Extract the part of the line after the keyword
            start_index = line.find(keyword) + len(keyword) + rule.get("start_index_offset", 0)
            extracted_line = line[start_index:].strip()
            print(f"Extracted line: {extracted_line}")  # Debugging print
            
            # Apply regex pattern from JSON
            regex_pattern = rule.get("regex_pattern", "")
            match = re.search(regex_pattern, extracted_line)
            if match:
                result = match.group(0)  # Extract the matched value
                print(f"Extracted result: {result}")  # Debugging print
            else:
                result = "Invalid or empty result"
            
            # Remove excluded characters if specified in JSON
            exclude_chars = rule.get("exclude_chars", [])
            for char in exclude_chars:
                result = result.replace(char, '')
            
            return result
    
    print(f"Keyword not found: {keyword}")  # Debugging print
    return "Invalid or empty result"

# Function to analyze IA32_TME_ACTIVATE MSR
def analyze_ia32_tme_activate(keyword, result, rule, worksheet, row_num):
    """
    Analyze IA32_TME_ACTIVATE MSR dynamically based on JSON rules and update the worksheet.
    """
    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=4).value = f"{rule.get('name', 'Keyword')} status is not present in log"
        return

    result = result.strip().replace(" ", "")
    hex_pattern = re.compile(rule.get("pattern", ""))
    
    if not hex_pattern.match(result):
        improper_message = rule.get("improper_print_message", "")
        worksheet.cell(row=row_num, column=4).value = improper_message.format(
            ia32_tme_activate_text=result, ia32_tme_capability_text="N/A"
        )
        return

    try:
        analysis = []
        binary_value = bin(int(result, 16))[2:].zfill(64)
        result_key = "result_text_ia32_tme_activate"

        for output in rule[result_key]:
            bits_range = output.get("bits_range", [])
            if len(bits_range) != 2 or not all(isinstance(b, int) for b in bits_range):
                continue

            start = bits_range[0] if bits_range[0] >= 0 else len(binary_value) + bits_range[0]
            end = bits_range[1] if bits_range[1] >= 0 else len(binary_value) + bits_range[1]
            hex_value = binary_value[start:end]

            if not hex_value or not re.match(r"^[01]+$", hex_value):
                raise ValueError(f"Invalid or empty hex_value extracted: '{hex_value}'")

            bits_as_int = int(hex_value, 2)
            hex_value_formatted = f"0x{bits_as_int:X}"

            if output.get("calculation"):
                calculated_value = eval(output["calculation"].replace("bits", str(bits_as_int)))
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    calculated_value=calculated_value,
                    bits_as_int=bits_as_int
                ))
            elif "algorithm_map" in output:
                algorithm = output["algorithm_map"].get(hex_value_formatted, "Unknown algorithm")
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    algorithm=algorithm,
                    bits_as_int=bits_as_int
                ))
            else:
                bits_as_int_minus_1 = bits_as_int - 1 if bits_as_int > 0 else 0
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    total_keys_text=bits_as_int_minus_1,
                    bits_as_int=bits_as_int,
                    bits_as_int_minus_1=bits_as_int_minus_1
                ))

        worksheet.cell(row=row_num, column=4).value = "\n".join(analysis)
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing result: {result} ({str(e)})"

# Function to analyze IA32_TME_CAPABILITY MSR
def analyze_ia32_tme_capability(keyword, result, rule, worksheet, row_num):
    """
    Analyze IA32_TME_CAPABILITY MSR dynamically based on JSON rules and update the worksheet.
    """
    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=4).value = f"{rule.get('name', 'Keyword')} status is not present in log"
        return

    result = result.strip().replace(" ", "")
    hex_pattern = re.compile(rule.get("pattern", ""))
    
    if not hex_pattern.match(result):
        improper_message = rule.get("improper_print_message", "")
        worksheet.cell(row=row_num, column=4).value = improper_message.format(
            ia32_tme_activate_text="N/A", ia32_tme_capability_text=result
        )
        return

    try:
        analysis = []
        binary_value = bin(int(result, 16))[2:].zfill(64)
        result_key = "result_text_ia32_tme_capability"

        for output in rule[result_key]:
            bits_range = output.get("bits_range", [])
            if len(bits_range) != 2 or not all(isinstance(b, int) for b in bits_range):
                continue

            start = bits_range[0] if bits_range[0] >= 0 else len(binary_value) + bits_range[0]
            end = bits_range[1] if bits_range[1] >= 0 else len(binary_value) + bits_range[1]
            hex_value = binary_value[start:end]

            if not hex_value or not re.match(r"^[01]+$", hex_value):
                raise ValueError(f"Invalid or empty hex_value extracted: '{hex_value}'")

            bits_as_int = int(hex_value, 2)
            hex_value_formatted = f"0x{bits_as_int:X}"

            if output.get("calculation"):
                calculated_value = eval(output["calculation"].replace("bits", str(bits_as_int)))
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    calculated_value=calculated_value,
                    bits_as_int=bits_as_int
                ))
            elif "algorithm_map" in output:
                algorithm = output["algorithm_map"].get(hex_value_formatted, "Unknown algorithm")
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    algorithm=algorithm,
                    bits_as_int=bits_as_int
                ))
            else:
                bits_as_int_minus_1 = bits_as_int - 1 if bits_as_int > 0 else 0
                analysis.append(output["output_format"].format(
                    hex_value=hex_value_formatted,
                    total_keys_text=bits_as_int_minus_1,
                    bits_as_int=bits_as_int,
                    bits_as_int_minus_1=bits_as_int_minus_1
                ))

        worksheet.cell(row=row_num, column=4).value = "\n".join(analysis)
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing result: {result} ({str(e)})"

# Function to analyze MKTME: total keys
def analyze_total_keys(keyword, result, rule, worksheet, row_num):
    """
    Analyze MKTME: total keys dynamically based on JSON rules and update the worksheet.
    """
    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=4).value = f"{rule.get('name', 'Keyword')} status is not present in log"
        return

    try:
        analysis = []
        result_key = "result_text_total_keys"

        # Extract total_keys_text from the result
        total_keys_text = int(result)  # Convert the result to an integer

        for output in rule[result_key]:
            if "output_format" in output:
                analysis.append(output["output_format"].format(
                    total_keys_text=total_keys_text
                ))

        worksheet.cell(row=row_num, column=4).value = "\n".join(analysis)
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing result: {result} ({str(e)})"

# Function to analyze mktme key-ids
def analyze_mktme_keys(keyword, result, rule, worksheet, row_num):
    """
    Analyze mktme key-ids dynamically based on JSON rules and update the worksheet.
    """
    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=4).value = f"{rule.get('name', 'Keyword')} status is not present in log"
        return

    result = result.strip().replace(" ", "")
    hex_pattern = re.compile(rule.get("pattern", ""))
    
    if not hex_pattern.match(result):
        worksheet.cell(row=row_num, column=4).value = "Invalid result format"
        return

    try:
        analysis = []
        result_key = "result_text_mktme_keys"
        total_keys_text = worksheet.cell(row=row_num - 1, column=3).value
        mktme_key_text = result

        for output in rule[result_key]:
            if "condition" in output:
                condition = output["condition"]
                condition_evaluated = eval(condition.replace("total_keys_text", str(total_keys_text)).replace("mktme_key_text", str(mktme_key_text)))
                if condition_evaluated:
                    analysis.append(output["output_format"].format(
                        total_keys_text=total_keys_text,
                        mktme_key_text=mktme_key_text
                    ))
            else:
                analysis.append(output["output_format"].format(
                    total_keys_text=total_keys_text,
                    mktme_key_text=mktme_key_text
                ))

        worksheet.cell(row=row_num, column=4).value = "\n".join(analysis)
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing result: {result} ({str(e)})"

# Function to analyze ACTM location
def analyze_actm_location(keyword, result, rule, worksheet, row_num):
    """
    Analyze ACTM location dynamically based on JSON rules and update the worksheet.
    """
    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=4).value = rule.get("improper_print_message", "ACTM location is not present in log")
        return

    result = result.strip().replace(" ", "")
    validation_pattern = rule.get("validation_pattern", "")
    
    if not re.match(validation_pattern, result):
        validation_failure_message = rule.get("validation_failure_message", "Invalid ACTM location format")
        worksheet.cell(row=row_num, column=4).value = validation_failure_message.format(actm_location_text=result)
        return

    try:
        # Write the ACTM location to the worksheet
        worksheet.cell(row=row_num, column=3).value = result  # Column C for actm_location_text
        worksheet.cell(row=row_num, column=4).value = f"ACTM location: {result}"  # Column D for analysis
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing ACTM location: {result} ({str(e)})"

# Function to analyze start ACTM
def analyze_start_actm(keyword, result, rule, worksheet, row_num, log_file_path):
    """
    Analyze the start ACTM status dynamically based on JSON rules and update the worksheet.
    """
    worksheet.cell(row=row_num, column=2).value = rule["output_cells"].get("B7", "Is ACTM launch started?")  # Column B

    if result and result != "Invalid or empty result":
        worksheet.cell(row=row_num, column=3).value = rule["output_cells"].get("C7", "ACTM launch started")  # Column C
        worksheet.cell(row=row_num, column=4).value = rule["output_cells"].get("D7", "ACTM launch started")  # Column D
    else:
        secondary_keyword = rule.get("secondary_keyword", "")
        secondary_result = search_keyword_in_log(log_file_path, secondary_keyword, rule) if secondary_keyword else None
        if secondary_result and secondary_result != "Invalid or empty result":
            worksheet.cell(row=row_num, column=3).value = rule.get("secondary_output", "ACTM launch is skipped")  # Column C
            worksheet.cell(row=row_num, column=4).value = rule.get("secondary_output", "ACTM launch is skipped")  # Column D
        else:
            worksheet.cell(row=row_num, column=3).value = rule["default_result"].get("C7", "ACTM launch status is not present in log")  # Column C
            worksheet.cell(row=row_num, column=4).value = rule["default_result"].get("D7", "ACTM launch status is not present in log")  # Column D

    worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

# Function to analyze ACTM error code
def analyze_actm_error_code(keyword, result, rule, worksheet, row_num):
    """
    Analyze the ACTM error code dynamically based on JSON rules and update the worksheet.
    """
    worksheet.cell(row=row_num, column=2).value = "ACTM ErrorCode"  # Column B

    if not result or result == "Invalid or empty result":
        worksheet.cell(row=row_num, column=3).value = rule["default_result"].get("C8", "0x0")  # Default value for Column C
        worksheet.cell(row=row_num, column=4).value = rule["default_result"].get("D8", "ACTM error code is not present in log")  # Column D
        return

    try:
        # Write the ACTM error code to the worksheet
        worksheet.cell(row=row_num, column=3).value = result  # Column C for actm_error_code_text
        worksheet.cell(row=row_num, column=4).value = f"ACTM ErrorCode: {result}"  # Column D for analysis
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing ACTM error code: {result} ({str(e)})"

# Function to analyze PROD SKU
def analyze_prod_sku(keyword, result, rule, worksheet, row_num):
    """
    Analyze the PROD SKU status dynamically based on JSON rules and update the worksheet.
    """
    print(f"Analyzing PROD SKU for keyword '{keyword}' with result: {result}")  # Debugging print
    worksheet.cell(row=row_num, column=2).value = rule["output_cells"].get("B9", "Is this PROD SKU?")  # Column B

    if not result or result == "Invalid or empty result":
        print("Result is invalid or empty.")  # Debugging print
        worksheet.cell(row=row_num, column=3).value = rule.get("improper_print_message", "Prod SKU status is not present in log")  # Column C
        worksheet.cell(row=row_num, column=4).value = rule.get("improper_print_message", "Prod SKU status is not present in log")  # Column D
        return

    result = result.strip().replace(" ", "")
    validation_pattern = rule.get("validation_pattern", "")
    
    if not re.match(validation_pattern, result):
        worksheet.cell(row=row_num, column=3).value = result  # Column C
        worksheet.cell(row=row_num, column=4).value = rule.get("validation_failure_message", "Invalid PROD SKU format").format(prod_sku_text=result)  # Column D
        return

    try:
        # Convert the result to binary and check the bit specified in the rule
        binary_value = bin(int(result, 16))[2:].zfill(32)
        bit_index = rule["result_text"][0]["bit_check"]
        bit_status = binary_value[-(bit_index + 1)]  # Get the bit value (0 or 1)

        if bit_status == "1":
            bit_status_text = rule["result_text"][0]["bit_set_text"]
            sku_type = rule["result_text"][0]["bit_set_type"]
            patch_type = rule["result_text"][0]["bit_set_patch"]
        else:
            bit_status_text = rule["result_text"][0]["bit_unset_text"]
            sku_type = rule["result_text"][0]["bit_unset_type"]
            patch_type = rule["result_text"][0]["bit_unset_patch"]

        # Format the output
        output = rule["result_text"][0]["output_format"].format(
            bit31_status=bit_status_text,
            sku_type=sku_type,
            patch_type=patch_type
        )
        worksheet.cell(row=row_num, column=3).value = result  # Column C
        worksheet.cell(row=row_num, column=4).value = output  # Column D
        worksheet.cell(row=row_num, column=4).alignment = Alignment(wrapText=True)

    except ValueError as e:
        worksheet.cell(row=row_num, column=4).value = f"Error processing PROD SKU: {result} ({str(e)})"

# Analyze the log file using the rules
def analyze_log_file(log_file_path, checks):
    results = []
    for check in checks:
        keyword = check.get('keyword', '')
        result = search_keyword_in_log(log_file_path, keyword, check)
        print(f"Result for keyword '{keyword}': {result}")  # Debugging print
        results.append((keyword, result, check))
    return results

# Save the results to an Excel file
def save_to_excel(results, output_file, log_file_path):
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Analysis Results"

    # Add headers
    headers = ["Security Features", "Feature check", "Results from log", "Analysis from Result"]
    for col_num, header in enumerate(headers, start=1):
        cell = worksheet.cell(row=1, column=col_num)
        cell.value = header
        cell.font = Font(bold=True)

    # Add results
    for row_num, (keyword, result, rule) in enumerate(results, start=2):
        security_feature, feature_check = keyword_mapping.get(keyword, ["Unknown", "Unknown"])
        worksheet.cell(row=row_num, column=1).value = security_feature
        worksheet.cell(row=row_num, column=2).value = feature_check
        worksheet.cell(row=row_num, column=3).value = result

        # Call the appropriate analyze function
        if rule.get("name") == "IA32_TME_ACTIVATE MSR":
            analyze_ia32_tme_activate(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "IA32_TME_CAPABILITY MSR":
            analyze_ia32_tme_capability(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "MKTME: total keys":
            analyze_total_keys(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "mktme key-ids":
            analyze_mktme_keys(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "ACTM location":
            analyze_actm_location(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "start ACTM":
            analyze_start_actm(keyword, result, rule, worksheet, row_num, log_file_path)
        elif rule.get("name") == "ACTM error code":
            analyze_actm_error_code(keyword, result, rule, worksheet, row_num)
        elif rule.get("name") == "PROD SKU":
            analyze_prod_sku(keyword, result, rule, worksheet, row_num)

    # Adjust column widths
    for col in worksheet.columns:
        max_length = 0
        col_letter = col[0].column_letter
        for cell in col:
            try:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))
            except:
                pass
        worksheet.column_dimensions[col_letter].width = max_length + 2

    # Adjust row heights dynamically based on content
    for row in worksheet.iter_rows():
        for cell in row:
            if cell.value:
                cell.alignment = Alignment(wrapText=True)
        max_content_length = max(len(str(cell.value)) if cell.value else 0 for cell in row)
        worksheet.row_dimensions[row[0].row].height = max(15, min(max_content_length // 10 * 15, 100))

    workbook.save(output_file)
    print(f"Analysis results saved to {output_file}")

# Main function to process the log file
def process_log_file(log_file_path):
    results = analyze_log_file(log_file_path, checks)
    save_to_excel(results, "output.xlsx", log_file_path)
    print(f"Analysis results saved to output.xlsx")

# Input log file path
log_file_path = 'SGX_enablement_putty.log'
process_log_file(log_file_path)