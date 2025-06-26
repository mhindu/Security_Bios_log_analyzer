import json
import re
import os
import pandas as pd

def load_rules():
    rules_path = os.path.join("c:\\Users\\hindum\\Desktop\\my personal\\VSCode_projects\\pandas\\security1", "json_final.json")
    with open(rules_path, "r") as f:
        return json.load(f)

def parse_log(log_path, rules):
    with open(log_path, "r") as f:
        log_data = f.read()
    for check in rules.get("checks", []):
        keyword = check.get("keyword", "")
        if keyword in log_data:
            regex_pattern = check.get("regex_pattern", "")
            match = re.search(regex_pattern, log_data)
            if match:
                extracted_value = match.group(1)  # this will serve as ia32_tme_activate_text
                result_text_str = process_result(extracted_value, check.get("result_text", []))
                return {"ia32_tme_activate_text": extracted_value, "result_text_str": result_text_str}
    return {"ia32_tme_activate_text": "", "result_text_str": ""}

def process_result(value, result_text_rules):
    results = []
    for rule in result_text_rules:
        bits_range = rule.get("bits_range", [0, len(value)])
        hex_value = value[bits_range[0]:bits_range[1]]
        calculated_value = ""
        if "calculation" in rule:
            calculated_value = eval(rule["calculation"].replace("bits", str(int(hex_value, 16))))
        output = rule["output_format"].format(
            hex_value=hex_value,
            calculated_value=calculated_value,
            algorithm=rule.get("algorithm_map", {}).get(hex_value, "Unknown")
        )
        results.append(output)
    return "\n".join(results)

def output_results(parsed_data):
    # Define fixed headers from script headers
    output_data = {
        "Security Features": "MKTME info",
        "Feature check": "TME_ACTIVATE MSR 982h",
        "Results from log": parsed_data.get("ia32_tme_activate_text", ""),
        "Analysis from Result": parsed_data.get("result_text_str", "")
    }
    out_path = os.path.join("c:\\Users\\hindum\\Desktop\\my personal\\VSCode_projects\\pandas\\security1", "bios_log_output.json")
    with open(out_path, "w") as f:
        json.dump(output_data, f, indent=4)

def analyse_ia32_tme_activate(keyword, result, rule):
    """
    Analyze IA32_TME_ACTIVATE MSR dynamically based on JSON rules and return a dictionary
    with keys:
       "Results from log": the raw extracted value (ia32_tme_activate_text)
       "Analysis from Result": the computed analysis.
    """
    if not result:
        return {
            "Results from log": "",
            "Analysis from Result": f"{rule.get('name', 'Keyword')} status is not present in log"
        }
    result_clean = result.strip().replace(" ", "")
    hex_pattern = re.compile(rule.get("pattern", ""))
    if not hex_pattern.match(result_clean):
        improper_message = rule.get("improper_print_message", "")
        return {
            "Results from log": result_clean,
            "Analysis from Result": improper_message.format(
                ia32_tme_activate_text=result_clean, ia32_tme_capability_text="N/A"
            )
        }
    try:
        analysis = []
        binary_value = bin(int(result_clean, 16))[2:].zfill(64)
        for output in rule.get("result_text_ia32_tme_activate", []):
            bits_range = output.get("bits_range", [])
            if len(bits_range) != 2 or not all(isinstance(b, int) for b in bits_range):
                continue
            start = bits_range[0] if bits_range[0] >= 0 else len(binary_value) + bits_range[0]
            end = bits_range[1] if bits_range[1] >= 0 else len(binary_value) + bits_range[1]
            hex_segment = binary_value[start:end]
            if not hex_segment or not re.match(r"^[01]+$", hex_segment):
                raise ValueError(f"Invalid or empty hex_segment extracted: '{hex_segment}'")
            bits_as_int = int(hex_segment, 2)
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
        return {
            "Results from log": result_clean,
            "Analysis from Result": "\n".join(analysis)
        }
    except ValueError as e:
        return {
            "Results from log": result_clean,
            "Analysis from Result": f"Error processing result: {result_clean} ({str(e)})"
        }

def analyze_ia32_tme_capability(keyword, result, rule):
    """
    Analyze IA32_TME_CAPABILITY MSR dynamically based on JSON rules and return a dictionary with:
      "Results from log": the raw extracted value
      "Analysis from Result": the computed analysis string
    """
    if not result:
        return {
            "Results from log": "",
            "Analysis from Result": f"{rule.get('name', 'Keyword')} status is not present in log"
        }
    result_clean = result.strip().replace(" ", "")
    hex_pattern = re.compile(rule.get("pattern", ""))
    if not hex_pattern.match(result_clean):
        improper_message = rule.get("improper_print_message", "")
        return {
            "Results from log": result_clean,
            "Analysis from Result": improper_message.format(
                ia32_tme_activate_text="N/A", ia32_tme_capability_text=result_clean
            )
        }
    try:
        analysis = []
        binary_value = bin(int(result_clean, 16))[2:].zfill(64)
        result_key = "result_text_ia32_tme_capability"
        for output in rule.get(result_key, []):
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
        return {
            "Results from log": result.strip(),
            "Analysis from Result": "\n".join(analysis)
        }
    except ValueError as e:
        return {
            "Results from log": result_clean,
            "Analysis from Result": f"Error processing result: {result_clean} ({str(e)})"
        }

def analyze_total_keys(keyword, log_file_path, rule):
    """
    Analyze 'MKTME: total keys' from the log file using the rule from JSON.
    Returns a dict with 'Results from log' and 'Analysis from Result' (as a list of strings).
    """
    # Flexible regex: allow any whitespace or punctuation between keyword and number
    pattern = re.compile(r"{}[\s:=-]*([0-9]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    if not extracted:
        return {
            "Results from log": "",
            "Analysis from Result": [rule.get("improper_print_message", "Keys allocation is not present in log")]
        }
    # Format analysis output as a list of strings
    analysis = []
    for output in rule.get("result_text_total_keys", []):
        try:
            total_keys_text = int(extracted)
        except Exception:
            total_keys_text = extracted
        analysis.append(output["output_format"].format(total_keys_text=total_keys_text))
    return {
        "Results from log": extracted,
        "Analysis from Result": analysis
    }

def search_keyword_in_log(log_file_path, keyword, num_bits, skip_bits=0, exclude_chars=None):
    if exclude_chars is None:
        exclude_chars = []
    with open(log_file_path, 'r') as file:
        lines = file.readlines()
    extracted = None
    for line in lines:
        if keyword.lower() in line.lower():
            start_index = line.lower().find(keyword.lower()) + len(keyword) + skip_bits
            extracted = line[start_index:start_index+num_bits]
            for c in exclude_chars:
                extracted = extracted.replace(c, '')
    if extracted:
        return extracted.strip()
    return None

def analyze_mktme_keys(keyword, log_file_path, rule, total_keys_text):
    """
    Analyze 'mktme key-ids' from the log file using the rule from JSON and total_keys_text.
    Returns a dict with 'Results from log' and 'Analysis from Result' (as a list of strings).
    """
    # Flexible regex: allow any whitespace or punctuation between keyword and number
    pattern = re.compile(r"{}[\s:=-]*([0-9]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    if not extracted:
        return {
            "Results from log": "",
            "Analysis from Result": [rule.get("improper_print_message", "MKTME keys are not enabled")]
        }
    # Format analysis output as a list of strings
    analysis = []
    mktme_key_text = int(extracted)
    for output in rule.get("result_text_mktme_keys", []):
        if "condition" in output:
            # Evaluate the condition using total_keys_text and mktme_key_text
            try:
                condition = output["condition"]
                condition_evaluated = eval(condition, {}, {"total_keys_text": int(total_keys_text), "mktme_key_text": mktme_key_text})
                if condition_evaluated:
                    analysis.append(output["output_format"].format(
                        total_keys_text=total_keys_text,
                        mktme_key_text=mktme_key_text
                    ))
            except Exception:
                continue
        else:
            analysis.append(output["output_format"].format(
                total_keys_text=total_keys_text,
                mktme_key_text=mktme_key_text
            ))
    return {
        "Results from log": extracted,
        "Analysis from Result": analysis
    }

def analyze_actm_location(keyword, log_file_path, rule):
    """
    Analyze ACTM location from the log file using the rule from JSON.
    Returns a dict with 'Results from log' and 'Analysis from Result' (as a list of strings).
    """
    # Flexible: find the keyword, then extract the first 0x... value after it
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    if not extracted:
        return {
            "Results from log": "",
            "Analysis from Result": [rule.get("improper_print_message", "ACTM location is not present in log")]
        }
    result = extracted.strip().replace(" ", "")
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, result):
        validation_failure_message = rule.get("validation_failure_message", "Invalid ACTM location format")
        return {
            "Results from log": result,
            "Analysis from Result": [validation_failure_message.format(actm_location_text=result)]
        }
    # If valid, output the ACTM location
    return {
        "Results from log": result,
        "Analysis from Result": [f"ACTM location: {result}"]
    }

def analyze_start_actm(rule, log_file_path):
    """
    Analyze the start ACTM status dynamically based on JSON rules and return a dict for JSON output.
    """
    keyword = rule.get("keyword", "")
    secondary_keyword = rule.get("secondary_keyword", "")
    improper_message = rule.get("improper_print_message", "ACTM launch status is not present in log")
    default_result = rule.get("default_result", {})
    # Search for the primary keyword in the log
    found_primary = False
    found_secondary = False
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found_primary = True
                break
    if found_primary:
        return {
            "Results from log": "ACTM launch started",
            "Analysis from Result": ["ACTM launch started"]
        }
    # If not found, check for secondary keyword
    if secondary_keyword:
        with open(log_file_path, 'r') as file:
            for line in file:
                if secondary_keyword in line:
                    found_secondary = True
                    break
    if found_secondary:
        return {
            "Results from log": rule.get("secondary_output", "ACTM launch is skipped"),
            "Analysis from Result": [rule.get("secondary_output", "ACTM launch is skipped")]
        }
    # If neither found, return default
    return {
        "Results from log": default_result.get("C7", improper_message),
        "Analysis from Result": [default_result.get("D7", improper_message)]
    }

def analyze_actm_error_code(keyword, log_file_path, rule):
    """
    Analyze the ACTM error code from the log file using the rule from JSON.
    Returns a dict with 'Results from log' and 'Analysis from Result' (as a list of strings).
    """
    # Flexible: find the keyword, then extract the first 0x... value after it
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    if not extracted:
        default_result = rule.get("default_result", {})
        return {
            "Results from log": default_result.get("C8", "0x0"),
            "Analysis from Result": [default_result.get("D8", rule.get("improper_print_message", "ACTM error code is not present in log"))]
        }
    # If valid, output the ACTM error code
    return {
        "Results from log": extracted,
        "Analysis from Result": [f"ACTM ErrorCode: {extracted}"]
    }

def analyze_prod_sku(keyword, log_file_path, rule):
    """
    Analyze the PROD SKU status from the log file using the rule from JSON.
    Returns a dict with 'Results from log' and 'Analysis from Result' (as a list of strings).
    """
    # Flexible: find the keyword, then extract the first 0x... value after it
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "Prod SKU status is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "Prod SKU status is not present in log")]
        }
    result = extracted.strip().replace(" ", "")
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, result):
        return {
            "Results from log": result,
            "Analysis from Result": [rule.get("validation_failure_message", "Invalid PROD SKU format").format(prod_sku_text=result)]
        }
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
        return {
            "Results from log": result,
            "Analysis from Result": [output]
        }
    except Exception as e:
        return {
            "Results from log": result,
            "Analysis from Result": [f"Error processing PROD SKU: {result} ({str(e)})"]
        }

def analyze_mcheck_error_code(keyword, log_file_path, rule):
    """
    Analyze Mcheck Error Code dynamically based on JSON rules and return a dict for JSON output.
    Attempts to look up error description from Excel if possible.
    """
    # Try to extract the code using the primary keyword
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
    # If not found, try secondary keyword if present
    if not extracted:
        secondary_keyword = rule.get("secondary_keyword", "")
        if secondary_keyword:
            pattern2 = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(secondary_keyword)), re.IGNORECASE)
            with open(log_file_path, 'r') as file:
                for line in file:
                    match = pattern2.search(line)
                    if match:
                        extracted = match.group(1)
        if not extracted:
            # Default/fallback output
            return {
                "Results from log": rule.get("default_result", {}).get("C10", "0x0"),
                "Analysis from Result": [rule.get("secondary_output", "No Mcheck - SGX enabled successfully")]
            }
    # Trim/processing as per rule
    trim_processing = rule.get("trim_processing", {})
    if trim_processing.get("trim_whitespace", False):
        extracted = extracted.strip()
    if trim_processing.get("if_starts_with") and extracted.startswith(trim_processing["if_starts_with"]):
        replacement_prefix = trim_processing.get("replacement_prefix", "")
        remove_chars_count = trim_processing.get("remove_chars_count", 0)
        extracted = replacement_prefix + extracted[remove_chars_count:]
    # Validate
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, extracted):
        return {
            "Results from log": extracted,
            "Analysis from Result": [rule.get("validation_failure_message", "improper print - {mcheck_code_text}").format(mcheck_code_text=extracted)]
        }
    # Try to look up error description from Excel if possible
    error_description = "Unknown error"
    try:
        result_text = rule.get("result_text", [{}])[0]
        error_code_file_path = result_text.get("error_code_file_path", "Mcheck_error_codes.xlsx")
        error_code_column = result_text.get("error_code_column", 0)
        error_description_column = result_text.get("error_description_column", 1)
        df = pd.read_excel(error_code_file_path)
        match_row = df[df.iloc[:, error_code_column] == extracted]
        if not match_row.empty:
            error_description = match_row.iloc[0, error_description_column]
    except Exception:
        pass
    return {
        "Results from log": extracted,
        "Analysis from Result": [f"Mcheck Error is {error_description}"]
    }

def analyze_sgx_enabled(keyword, log_file_path, rule):
    """
    Analyze SGX enabled status dynamically based on JSON rules and return a dict for JSON output.
    Extracts only the phrase 'SGX (Secure Enclaves) feature enabled.' if present.
    """
    found = False
    found_line = None
    extracted_phrase = None
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found = True
                found_line = line.strip()
                # Try to extract the phrase
                match = re.search(r'(SGX \(Secure Enclaves\) feature enabled\.)', found_line)
                if match:
                    extracted_phrase = match.group(1)
                break
    if found:
        return {
            "Results from log": extracted_phrase if extracted_phrase else (found_line or keyword),
            "Analysis from Result": [rule.get("pass_message", "Pass: SGX feature is enabled")]
        }
    else:
        return {
            "Results from log": rule.get("not_found_message", "Not Found"),
            "Analysis from Result": [rule.get("fail_message", "Fail: SGX feature is not enabled")]
        }

def analyze_tdx_build_date(keyword, log_file_path, rule):
    """
    Process the TDX build date check dynamically based on JSON rules and return a dict for JSON output.
    Extracts only the 'build_date ... build_num ...' substring if present.
    """
    extracted = None
    build_info = None
    regex_pattern = rule.get("regex_pattern", None)
    if regex_pattern:
        pattern = re.compile(regex_pattern, re.IGNORECASE)
        with open(log_file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    extracted = match.group(1) if match.groups() else line.strip()
                    break
    else:
        with open(log_file_path, 'r') as file:
            for line in file:
                if keyword and keyword in line:
                    extracted = line.strip()
                    break
    if extracted:
        # Try to extract 'build_date ... build_num ...' substring
        match = re.search(r'(build_date\s+\d+,\s*build_num\s+\d+)', extracted)
        if match:
            build_info = match.group(1)
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "TDX build date is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "TDX build date is not present in log")]
        }
    return {
        "Results from log": build_info if build_info else extracted,
        "Analysis from Result": [build_info if build_info else extracted]
    }

def analyze_tdx_module_initialization(keyword, log_file_path, rule):
    """
    Process the TDX module initialization check dynamically based on JSON rules and return a dict for JSON output.
    """
    found = False
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found = True
                break
    if found:
        return {
            "Results from log": "TDX module is initialized",
            "Analysis from Result": ["TDX module is initialized"]
        }
    else:
        return {
            "Results from log": "TDX module is not initialized",
            "Analysis from Result": ["TDX module is not initialized"]
        }

def analyze_seamrr_initialization(keyword, log_file_path, rule):
    """
    Process the SEAMRR initialization check dynamically based on JSON rules and return a dict for JSON output.
    """
    found = None
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found = line.strip()
                break
    if found:
        return {
            "Results from log": found,
            "Analysis from Result": ["SEAMRR target are initialized"]
        }
    else:
        return {
            "Results from log": "Seamrr target not initialized",
            "Analysis from Result": ["SEAMRR target are not initialized"]
        }

def analyze_seamrr_base_range(keyword, log_file_path, rule):
    """
    Process the SEAMRR base range check dynamically based on JSON rules and return a dict for JSON output.
    Extracts and combines two consecutive hex groups if needed.
    """
    found = None
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found = line.strip()
                break
    if found:
        # Try to match and combine two hex groups (with or without 0x)
        match = re.search(r'(0x[0-9A-Fa-f]{8})\s*([0-9A-Fa-f]{8})', found)
        if match:
            cleaned_result = match.group(1) + match.group(2)
        else:
            # fallback: try to find a single 16-digit hex
            match = re.search(r'(0x[0-9A-Fa-f]{16}|[0-9A-Fa-f]{16})', found)
            cleaned_result = match.group(1) if match else None
        if cleaned_result:
            hex_pattern = re.compile(r'^(0x)?[0-9A-Fa-f]{16}$')
            if hex_pattern.match(cleaned_result):
                seamrr_base_value = int(cleaned_result, 16)
                if seamrr_base_value & (1 << 3):
                    analysis = "Bit 3 is set, Bios configured SEAMRR_Base"
                else:
                    analysis = "Bit 3 is not set, Bios does not configure SEAMRR_Base"
                return {
                    "Results from log": cleaned_result,
                    "Analysis from Result": [analysis]
                }
            else:
                return {
                    "Results from log": f"improper print - {cleaned_result}",
                    "Analysis from Result": [f"improper print - {cleaned_result}"]
                }
        else:
            return {
                "Results from log": f"improper print - {found}",
                "Analysis from Result": [f"improper print - {found}"]
            }
    else:
        return {
            "Results from log": "SEAMRR Base range is not present in log",
            "Analysis from Result": ["SEAMRR Base range is not present in log"]
        }

def analyze_seamrr_mask_range(keyword, log_file_path, rule):
    """
    Process the SEAMRR mask range check dynamically based on JSON rules and return a dict for JSON output.
    Extracts and combines two consecutive hex groups if needed.
    """
    found = None
    with open(log_file_path, 'r') as file:
        for line in file:
            if keyword and keyword in line:
                found = line.strip()
                break
    if found:
        # Try to match and combine two hex groups (with or without 0x)
        match = re.search(r'(0x[0-9A-Fa-f]{8})\s*([0-9A-Fa-f]{8})', found)
        if match:
            cleaned_result = match.group(1) + match.group(2)
        else:
            # fallback: try to find a single 16-digit hex
            match = re.search(r'(0x[0-9A-Fa-f]{16}|[0-9A-Fa-f]{16})', found)
            cleaned_result = match.group(1) if match else None
        if cleaned_result:
            hex_pattern = re.compile(r'^(0x)?[0-9A-Fa-f]{16}$')
            if hex_pattern.match(cleaned_result):
                seamrr_mask_value = int(cleaned_result, 16)
                bit10_set = seamrr_mask_value & (1 << 10)
                bit11_set = seamrr_mask_value & (1 << 11)
                if bit10_set and bit11_set:
                    analysis = "bit 10 lock bit and bit 11 valid bit are set"
                elif bit10_set:
                    analysis = "only bit 10 lock bit is set"
                elif bit11_set:
                    analysis = "only bit 11 valid bit is set"
                else:
                    analysis = "neither bit 10 nor bit 11 is set on SEAMRR_MASK"
                return {
                    "Results from log": cleaned_result,
                    "Analysis from Result": [analysis]
                }
            else:
                return {
                    "Results from log": f"improper print - {cleaned_result}",
                    "Analysis from Result": [f"improper print - {cleaned_result}"]
                }
        else:
            return {
                "Results from log": f"improper print - {found}",
                "Analysis from Result": [f"improper print - {found}"]
            }
    else:
        return {
            "Results from log": "SEAMRR Mask range is not present in log",
            "Analysis from Result": ["SEAMRR Mask range is not present in log"]
        }

def analyze_lt_status_info(keyword, log_file_path, rule):
    """
    Process the LT_STATUS info dynamically based on JSON rules and return a dict for JSON output.
    """
    extracted = None
    # Try to extract the first hex value after the keyword
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "LT_status is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "LT_status is not present in log")]
        }
    result = extracted.strip()
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, result):
        return {
            "Results from log": result,
            "Analysis from Result": [rule.get("validation_failure_message", "improper print - {lt_status_info_text}").format(lt_status_info_text=result, lt_status_text=result)]
        }
    try:
        lt_status_value = int(result, 16)
        analysis = []
        for output in rule.get("result_text", []):
            bit_check = output["bit_check"]
            if lt_status_value & (1 << bit_check):
                analysis.append(output["output_format"].format(
                    bit_position=bit_check,
                    bit_status=output["bit_set_text"],
                    bit_message=output["bit_set_message"]
                ))
            else:
                analysis.append(output["output_format"].format(
                    bit_position=bit_check,
                    bit_status=output["bit_unset_text"],
                    bit_message=output["bit_unset_message"]
                ))
        return {
            "Results from log": result,
            "Analysis from Result": analysis
        }
    except Exception as e:
        return {
            "Results from log": result,
            "Analysis from Result": [f"Error processing LT_STATUS info: {result} ({str(e)})"]
        }

def analyze_lt_extended_status_info(keyword, log_file_path, rule):
    """
    Process the LT_EXTENDED_STATUS info dynamically based on JSON rules and return a dict for JSON output.
    """
    extracted = None
    # Try to extract the first hex value after the keyword
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "LT_extended_status is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "LT_extended_status is not present in log")]
        }
    result = extracted.strip()
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, result):
        return {
            "Results from log": result,
            "Analysis from Result": [rule.get("validation_failure_message", "improper print - {lt_extended_status_info_text}").format(lt_extended_status_info_text=result)]
        }
    try:
        value = int(result, 16)
        output = rule["result_text"][0]
        bit0 = output["bit_check"]
        if value & (1 << bit0):
            bit0_status = output["bit_set_text"]
            poison_status = output["bit_set_poison_status"]
        else:
            bit0_status = output["bit_unset_text"]
            poison_status = output["bit_unset_poison_status"]
        analysis = output["output_format"].format(
            bit0_status=bit0_status,
            poison_status=poison_status
        )
        return {
            "Results from log": result,
            "Analysis from Result": [analysis]
        }
    except Exception as e:
        return {
            "Results from log": result,
            "Analysis from Result": [f"Error processing LT_EXTENDED_STATUS info: {result} ({str(e)})"]
        }

def analyze_lt_boot_status_info(keyword, log_file_path, rule):
    """
    Process the LT_BOOT_STATUS info dynamically based on JSON rules and return a dict for JSON output.
    """
    extracted = None
    # Try to extract the first hex value after the keyword
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "LT_boot_status is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "LT_boot_status is not present in log")]
        }
    result = extracted.strip()
    validation_pattern = rule.get("validation_pattern", "")
    if not re.match(validation_pattern, result):
        return {
            "Results from log": result,
            "Analysis from Result": [rule.get("validation_failure_message", "improper print - {lt_boot_status_info_text}").format(lt_boot_status_info_text=result)]
        }
    try:
        value = int(result, 16)
        output = rule["result_text"][0]
        # Check all required bits
        bit30 = output["bit30_check"]
        bit31 = output["bit31_check"]
        bit59 = output["bit59_check"]
        bit62 = output["bit62_check"]
        bit63 = output["bit63_check"]
        # Bit 30
        if value & (1 << bit30):
            bit30_status = output["bit_set_text"].format(bit=30)
            txt_status = output["bit30_set_txt_status"]
        else:
            bit30_status = output["bit_unset_text"].format(bit=30)
            txt_status = output["bit30_unset_txt_status"]
        # Bit 31
        if value & (1 << bit31):
            bit31_status = output["bit_set_text"].format(bit=31)
            btg_status = output["bit31_set_btg_status"]
        else:
            bit31_status = output["bit_unset_text"].format(bit=31)
            btg_status = output["bit31_unset_btg_status"]
        # Bit 59
        if value & (1 << bit59):
            bit59_status = output["bit_set_text"].format(bit=59)
            bios_status = output["bit59_set_bios_status"]
        else:
            bit59_status = output["bit_unset_text"].format(bit=59)
            bios_status = output["bit59_unset_bios_status"]
        # Bit 62
        if value & (1 << bit62):
            bit62_status = output["bit_set_text"].format(bit=62)
            cpu_error_status = output["bit62_set_cpu_error_status"]
        else:
            bit62_status = output["bit_unset_text"].format(bit=62)
            cpu_error_status = output["bit62_unset_cpu_error_status"]
        # Bit 63
        if value & (1 << bit63):
            bit63_status = output["bit_set_text"].format(bit=63)
            sacm_status = output["bit63_set_sacm_status"]
        else:
            bit63_status = output["bit_unset_text"].format(bit=63)
            sacm_status = output["bit63_unset_sacm_status"]
        analysis = output["output_format"].format(
            bit30_status=bit30_status,
            txt_status=txt_status,
            bit31_status=bit31_status,
            btg_status=btg_status,
            bit59_status=bit59_status,
            bios_status=bios_status,
            bit62_status=bit62_status,
            cpu_error_status=cpu_error_status,
            bit63_status=bit63_status,
            sacm_status=sacm_status
        )
        # Split analysis by newlines so each line is a separate list element
        analysis_lines = [line for line in analysis.split("\n") if line.strip()]
        return {
            "Results from log": result,
            "Analysis from Result": analysis_lines
        }
    except Exception as e:
        return {
            "Results from log": result,
            "Analysis from Result": [f"Error processing LT_BOOT_STATUS info: {result} ({str(e)})"]
        }

def analyze_lt_error_code_info(keyword, log_file_path, rule):
    """
    Analyze LT_ERROR_CODE info dynamically based on JSON rules and return a dict for JSON output.
    """
    # Extract the first hex value after the keyword
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "LT_error_status is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "LT_error_status is not present in log")]
        }
    result = extracted.strip()
    hex_pattern = re.compile(rule.get("validation_pattern", "^(0x)?[0-9A-Fa-f]{16}$"))
    if not hex_pattern.match(result):
        return {
            "Results from log": result,
            "Analysis from Result": [f"improper print - {result}"]
        }
    value = int(result, 16)
    output = rule["result_text"][0]
    rep = {}
    if value & (1 << output.get("bit31_check", 31)):
        rep["bit31_status"] = "set"
        rep["register_status"] = output.get("bit31_set_register_status", "valid")
        if value & (1 << output.get("bit15_check", 15)):
            rep["bit15_status"] = "set"
            rep["sacm_status"] = output.get("bit15_set_sacm_status", "started successfully")
        else:
            rep["bit15_status"] = "unset"
            rep["sacm_status"] = output.get("bit15_unset_sacm_status", "didnt start")
        if value & (1 << output.get("bit30_check", 30)):
            rep["bit30_status"] = "set"
            rep["error_status"] = output.get("bit30_set_error_status", "generated errorcodes")
        else:
            rep["bit30_status"] = "unset"
            rep["error_status"] = output.get("bit30_unset_error_status", "not generated errorcodes")
    else:
        rep["bit31_status"] = "unset"
        rep["register_status"] = output.get("bit31_unset_register_status", "invalid from bits 30:0")
    analysis = output["output_format"].format(**rep)
    analysis_lines = [line for line in analysis.split("\n") if line.strip()]
    return {
        "Results from log": result,
        "Analysis from Result": analysis_lines
    }

def analyze_lt_crash_info(keyword, log_file_path, rule):
    """
    Analyze LT_CRASH info dynamically based on JSON rules and return a dict for JSON output.
    """
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": rule.get("improper_print_message", "LT_crash is not present in log"),
            "Analysis from Result": [rule.get("improper_print_message", "LT_crash is not present in log")]
        }
    result = extracted.strip()
    hex_pattern = re.compile(rule.get("validation_pattern", "^(0x)?[0-9A-Fa-f]{16}$"))
    if not hex_pattern.match(result):
        return {
            "Results from log": result,
            "Analysis from Result": [f"improper print - {result}"]
        }
    value = int(result, 16)
    output = rule["result_text"][0]
    rep = {}
    if value & (1 << output.get("bit31_check", 31)):
        rep["bit31_status"] = output.get("bit_set_text", "set")
        rep["crash_status"] = output.get("bit31_set_crash_status", "set")
        if value & (1 << output.get("bit30_check", 30)):
            rep["crash_source"] = output.get("bit30_set_crash_source", "internal CPU")
        else:
            rep["crash_source"] = output.get("bit30_unset_crash_source", "external ACM, MLE")
        analysis = output["output_format"].format(**rep)
    else:
        rep["bit31_status"] = output.get("bit_unset_text", "unset")
        rep["crash_status"] = output.get("bit31_unset_crash_status", "not seen")
        analysis = f"Bit 31 is {rep['bit31_status']} - LT_Crash is {rep['crash_status']}"
    analysis_lines = [line for line in analysis.split("\n") if line.strip()]
    return {
        "Results from log": result,
        "Analysis from Result": analysis_lines
    }

def analyze_sacm_info(keyword, log_file_path, rule):
    """
    Analyze SACM_INFO info dynamically based on JSON rules and return a dict for JSON output.
    """
    pattern = re.compile(r"{}.*?(0x[0-9A-Fa-f]+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1)
                break
    if not extracted:
        return {
            "Results from log": "SACM_INFO is not present in log",
            "Analysis from Result": ["SACM_INFO is not present in log"]
        }
    result = extracted.strip()
    hex_pattern = re.compile(r'^(0x)?[0-9A-Fa-f]{16}$')
    if not hex_pattern.match(result):
        return {
            "Results from log": result,
            "Analysis from Result": [f"improper print - {result}"]
        }
    value = int(result, 16)
    bit3_set  = bool(value & (1 << 3))
    bit34_set = bool(value & (1 << 34))
    bit32_set = bool(value & (1 << 32))
    bit0_set  = bool(value & (1 << 0))
    bit2_set  = bool(value & (1 << 2))
    bit4_set  = bool(value & (1 << 4))
    bit5_set  = bool(value & (1 << 5))
    bit6_set  = bool(value & (1 << 6))
    result_text = []
    if bit34_set:
        result_text.append("Bit 34 set - LT_SX_EN Fuse is enabled")
    else:
        result_text.append("Bit 34 is unset - LT_SX_EN Fuse is disabled")
    if bit32_set:
        result_text.append("Bit 32 set - BTG is enabled")
        if bit0_set and bit2_set and bit3_set and bit4_set and bit5_set and bit6_set:
            result_text.append("BTG-5 profile is enabled & TPM Success")
        elif bit0_set and bit2_set and bit3_set and bit5_set and bit6_set:
            result_text.append("BTG-3 profile is enabled & TPM Success")
        elif bit0_set and bit4_set and bit6_set:
            result_text.append("BTG-4 profile is enabled")
        else:
            result_text.append("No BTG profile enabled")
    else:
        result_text.append("Bit 32 is unset - BTG is not enabled")
    return {
        "Results from log": result,
        "Analysis from Result": result_text
    }

def analyze_bios_id_info(keyword, log_file_path, rule):
    """
    Analyze BIOS ID info dynamically based on JSON rules and return a dict for JSON output.
    """
    pattern = re.compile(r"{}(.+)".format(re.escape(keyword)), re.IGNORECASE)
    extracted = None
    with open(log_file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                extracted = match.group(1).strip()
                break
    if not extracted:
        return {
            "Results from log": "Bios_ID is not present in log",
            "Analysis from Result": ["Bios_ID is not present in log"]
        }
    return {
        "Results from log": extracted,
        "Analysis from Result": [extracted]
    }

def process_log_file_to_json(log_file_path, json_rules_path, output_json_path):
    with open(json_rules_path, 'r') as f:
        rules = json.load(f)
    results = []
    tme_activate_rule = None
    tme_capability_rule = None
    total_keys_rule = None
    mktme_keys_rule = None
    actm_location_rule = None
    start_actm_rule = None
    actm_error_code_rule = None
    prod_sku_rule = None
    mcheck_error_code_rule = None
    sgx_enabled_rule = None
    tdx_build_date_rule = None
    tdx_module_init_rule = None
    seamrr_init_rule = None
    seamrr_base_rule = None
    seamrr_mask_rule = None
    lt_status_rule = None
    lt_extended_status_rule = None
    lt_boot_status_rule = None
    lt_error_code_rule = None
    lt_crash_rule = None
    sacm_info_rule = None
    bios_id_rule = None
    for rule in rules.get("checks", []):
        if rule.get("msr") == "982h":
            tme_activate_rule = rule
        elif rule.get("msr") == "981h":
            tme_capability_rule = rule
        elif rule.get("name", "").lower().startswith("mktme: total keys"):
            total_keys_rule = rule
        elif rule.get("name", "").lower().startswith("mktme key-ids"):
            mktme_keys_rule = rule
        elif rule.get("name", "").lower().startswith("actm location"):
            actm_location_rule = rule
        elif rule.get("name", "").lower().startswith("start actm"):
            start_actm_rule = rule
        elif rule.get("name", "").lower().startswith("actm error code"):
            actm_error_code_rule = rule
        elif rule.get("name", "").lower().startswith("prod_sku"):
            prod_sku_rule = rule
        elif rule.get("name", "").lower().startswith("mcheck error code"):
            mcheck_error_code_rule = rule
        elif rule.get("name", "").lower().startswith("sgx enabled"):
            sgx_enabled_rule = rule
        elif rule.get("name", "").lower().startswith("tdx build date"):
            tdx_build_date_rule = rule
        elif rule.get("name", "").lower().startswith("tdx module initialization"):
            tdx_module_init_rule = rule
        elif rule.get("name", "").lower().startswith("seamrr initialization"):
            seamrr_init_rule = rule
        elif rule.get("name", "").lower().startswith("seamrr_base"):
            seamrr_base_rule = rule
        elif rule.get("name", "").lower().startswith("seamrr_mask"):
            seamrr_mask_rule = rule
        elif rule.get("name", "").lower().startswith("lt_status"):
            lt_status_rule = rule
        elif rule.get("name", "").lower().startswith("lt_extended_status"):
            lt_extended_status_rule = rule
        elif rule.get("name", "").lower().startswith("lt_boot_status"):
            lt_boot_status_rule = rule
        elif rule.get("name", "").lower().startswith("lt_error_code"):
            lt_error_code_rule = rule
        elif rule.get("name", "").lower().startswith("lt_crash"):
            lt_crash_rule = rule
        elif rule.get("name", "").lower().startswith("sacm_info"):
            sacm_info_rule = rule
        elif rule.get("name", "").lower().startswith("bios id"):
            bios_id_rule = rule
    total_keys_text = None
    if tme_activate_rule:
        keyword = tme_activate_rule.get("keyword", "")
        num_bits = tme_activate_rule.get("num_bits", 0)
        skip_bits = tme_activate_rule.get("skip_bits", 0)
        exclude_chars = tme_activate_rule.get("exclude_chars", [])
        extracted_value = search_keyword_in_log(log_file_path, keyword, num_bits, skip_bits, exclude_chars)
        analysis_dict = analyse_ia32_tme_activate(keyword, extracted_value, tme_activate_rule)
        analysis_lines = analysis_dict["Analysis from Result"].split("\n") if isinstance(analysis_dict["Analysis from Result"], str) else analysis_dict["Analysis from Result"]
        results.append({
            "Security Features": "MKTME info",
            "Feature check": "TME_ACTIVATE MSR 982h",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_lines
        })
    if tme_capability_rule:
        keyword = tme_capability_rule.get("keyword", "")
        num_bits = tme_capability_rule.get("num_bits", 0)
        skip_bits = tme_capability_rule.get("skip_bits", 0)
        exclude_chars = tme_capability_rule.get("exclude_chars", [])
        extracted_value = search_keyword_in_log(log_file_path, keyword, num_bits, skip_bits, exclude_chars)
        analysis_dict = analyze_ia32_tme_capability(keyword, extracted_value, tme_capability_rule)
        analysis_lines = analysis_dict["Analysis from Result"].split("\n") if isinstance(analysis_dict["Analysis from Result"], str) else analysis_dict["Analysis from Result"]
        results.append({
            "Security Features": "MKTME info",
            "Feature check": "TME_CAPABILITY MSR 981h",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_lines
        })
    if total_keys_rule:
        keyword = total_keys_rule.get("keyword", "")
        analysis_dict = analyze_total_keys(keyword, log_file_path, total_keys_rule)
        results.append({
            "Security Features": "MKTME info",
            "Feature check": "MKTME: total keys",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
        total_keys_text = analysis_dict["Results from log"]
    if mktme_keys_rule and total_keys_text is not None:
        keyword = mktme_keys_rule.get("keyword", "")
        analysis_dict = analyze_mktme_keys(keyword, log_file_path, mktme_keys_rule, total_keys_text)
        results.append({
            "Security Features": "MKTME info",
            "Feature check": "mktme key-ids",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if actm_location_rule:
        keyword = actm_location_rule.get("keyword", "")
        analysis_dict = analyze_actm_location(keyword, log_file_path, actm_location_rule)
        results.append({
            "Security Features": "ACTM info",
            "Feature check": "ACTM location",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if start_actm_rule:
        analysis_dict = analyze_start_actm(start_actm_rule, log_file_path)
        results.append({
            "Security Features": "ACTM info",
            "Feature check": "Is ACTM launch started?",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if actm_error_code_rule:
        keyword = actm_error_code_rule.get("keyword", "")
        analysis_dict = analyze_actm_error_code(keyword, log_file_path, actm_error_code_rule)
        results.append({
            "Security Features": "ACTM info",
            "Feature check": "ACTM ErrorCode",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if prod_sku_rule:
        keyword = prod_sku_rule.get("keyword", "")
        analysis_dict = analyze_prod_sku(keyword, log_file_path, prod_sku_rule)
        results.append({
            "Security Features": "ACTM info",
            "Feature check": "Is this PROD SKU?",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if mcheck_error_code_rule:
        keyword = mcheck_error_code_rule.get("keyword", "")
        analysis_dict = analyze_mcheck_error_code(keyword, log_file_path, mcheck_error_code_rule)
        results.append({
            "Security Features": "Mcheck info",
            "Feature check": "Mcheck Error Code",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if sgx_enabled_rule:
        keyword = sgx_enabled_rule.get("keyword", "")
        analysis_dict = analyze_sgx_enabled(keyword, log_file_path, sgx_enabled_rule)
        results.append({
            "Security Features": "SGX info",
            "Feature check": "Is SGX enabled?",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if tdx_build_date_rule:
        keyword = tdx_build_date_rule.get("keyword", "")
        analysis_dict = analyze_tdx_build_date(keyword, log_file_path, tdx_build_date_rule)
        results.append({
            "Security Features": "TDX info",
            "Feature check": "TDX Build Date and version",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if tdx_module_init_rule:
        keyword = tdx_module_init_rule.get("keyword", "")
        analysis_dict = analyze_tdx_module_initialization(keyword, log_file_path, tdx_module_init_rule)
        results.append({
            "Security Features": "TDX info",
            "Feature check": "Is TDX module initialized?",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if seamrr_init_rule:
        keyword = seamrr_init_rule.get("keyword", "")
        analysis_dict = analyze_seamrr_initialization(keyword, log_file_path, seamrr_init_rule)
        results.append({
            "Security Features": "SEAMRR info",
            "Feature check": "Is SEAMRR Initialized?",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if seamrr_base_rule:
        keyword = seamrr_base_rule.get("keyword", "")
        analysis_dict = analyze_seamrr_base_range(keyword, log_file_path, seamrr_base_rule)
        results.append({
            "Security Features": "SEAMRR info",
            "Feature check": "SEAMRR_BASE MSR 1400h",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if seamrr_mask_rule:
        keyword = seamrr_mask_rule.get("keyword", "")
        analysis_dict = analyze_seamrr_mask_range(keyword, log_file_path, seamrr_mask_rule)
        results.append({
            "Security Features": "SEAMRR info",
            "Feature check": "SEAMRR_MASK MSR 1401h",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if lt_status_rule:
        keyword = lt_status_rule.get("keyword", "")
        analysis_dict = analyze_lt_status_info(keyword, log_file_path, lt_status_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "LT_STATUS[0xFED30000]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if lt_extended_status_rule:
        keyword = lt_extended_status_rule.get("keyword", "")
        analysis_dict = analyze_lt_extended_status_info(keyword, log_file_path, lt_extended_status_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "LT_EXTENDED_STATUS[0xFED30008]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if lt_boot_status_rule:
        keyword = lt_boot_status_rule.get("keyword", "")
        analysis_dict = analyze_lt_boot_status_info(keyword, log_file_path, lt_boot_status_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "LT_BOOT_STATUS[0xFED300A0]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if lt_error_code_rule:
        keyword = lt_error_code_rule.get("keyword", "")
        analysis_dict = analyze_lt_error_code_info(keyword, log_file_path, lt_error_code_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "LT_ERROR_CODE[0xFED30328]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if lt_crash_rule:
        keyword = lt_crash_rule.get("keyword", "")
        analysis_dict = analyze_lt_crash_info(keyword, log_file_path, lt_crash_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "LT_CRASH[0xFED30030]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if sacm_info_rule:
        keyword = sacm_info_rule.get("keyword", "MSR_BOOT_GUARD_SACM_INFO[0x0000013A]")
        analysis_dict = analyze_sacm_info(keyword, log_file_path, sacm_info_rule)
        results.append({
            "Security Features": "BTG & TXT info",
            "Feature check": "SACM_INFO[0x0000013A]",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    if bios_id_rule:
        keyword = bios_id_rule.get("keyword", "Bios ID: ")
        analysis_dict = analyze_bios_id_info(keyword, log_file_path, bios_id_rule)
        results.append({
            "Security Features": "SYSTEM info",
            "Feature check": "BIOS ID",
            "Results from log": analysis_dict["Results from log"],
            "Analysis from Result": analysis_dict["Analysis from Result"]
        })
    with open(output_json_path, 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    log_file = os.path.join("c:\\Users\\hindum\\Desktop\\my personal\\VSCode_projects\\pandas\\security1", "SGX_enablement_putty.log")
    json_rules = os.path.join("c:\\Users\\hindum\\Desktop\\my personal\\VSCode_projects\\pandas\\security1", "json_final.json")
    output_json = os.path.join("c:\\Users\\hindum\\Desktop\\my personal\\VSCode_projects\\pandas\\security1", "bios_log_output.json")
    process_log_file_to_json(log_file, json_rules, output_json)
