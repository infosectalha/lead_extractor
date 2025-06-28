# Agent Instructions for Lead Profiler Tool

This document provides guidance for AI agents working on the Lead Profiler Tool codebase.

## Project Structure

*   `profiler.py`: Main script containing all core logic and CLI handling.
    *   Data gathering functions are typically named `get_<feature>_info()`.
    *   `run_domain_profile()` orchestrates calls to these functions for a single domain.
    *   `main()` handles CLI argument parsing and calls `run_domain_profile()`.
*   `requirements.txt`: Lists Python dependencies.
*   `README.md`: User-facing documentation.
*   `AGENTS.md`: This file.

## Development Guidelines

### Adding New Profiling Modules

1.  **Create a new function** in `profiler.py`, typically named `get_newfeature_info(domain: str) -> dict:`.
    *   The function should take the domain string as input.
    *   It should return a dictionary containing the results for that feature.
    *   Include an `"error": None` key in the successful return dictionary. If an error occurs specific to this module, populate this key with a descriptive string.
    *   Ensure all external library calls are wrapped in appropriate `try...except` blocks to handle potential errors gracefully (e.g., network issues, library-specific exceptions). Do not let unhandled exceptions propagate from these modules.
2.  **Update `run_domain_profile()`**:
    *   Call your new `get_newfeature_info()` function.
    *   Store its result in the `master_results["profile_data"]` dictionary, using an appropriate key (e.g., `master_results["profile_data"]["newfeature"] = newfeature_data`).
    *   Add logic to append to `master_results["errors"]` if your new function's result indicates an error that should be highlighted to the user (e.g., `if newfeature_data.get("error"): master_results["errors"].append(f"NewFeature Error: {newfeature_data['error']}")`). Be mindful of what constitutes a critical error versus informational (e.g., a 404 for `robots.txt` is informational, but a connection timeout might be a critical error for that module).
3.  **Update `README.md`**:
    *   Add the new feature to the "Current Features" list.
4.  **Add Dependencies**:
    *   If your new module requires new Python libraries, add them to `requirements.txt`. Ensure `pip install -r requirements.txt` is run before testing.
5.  **Testing**:
    *   Test thoroughly with various domains (valid, invalid, domains that might lack the specific feature).

### API Key Handling

*   **VirusTotal API Key**: The `get_virustotal_info()` function is currently a placeholder. When implementing it fully:
    *   The primary method for obtaining the API key should be from an environment variable (e.g., `VIRUSTOTAL_API_KEY`).
    *   Consider a fallback to a configuration file (e.g., `.env` or `config.ini`) if the environment variable is not set. This file should be added to `.gitignore`.
    *   Do NOT hardcode API keys directly into the script for committed code.
    *   The `USER_VIRUSTOTAL_API_KEY` global variable in `profiler.py` is a temporary placeholder for development and should be replaced with robust key management.

### Output Format

*   The primary output for a single domain run is a JSON dump of the `master_results` dictionary.
*   Future work will involve CSV output and individual text/PDF reports. When implementing these, ensure data from all modules is correctly incorporated.

### General Principles
*   Prioritize passive reconnaissance techniques only.
*   Ensure all network requests have reasonable timeouts.
*   Provide clear error messages within each module's result dictionary.
*   Maintain user-friendliness in the CLI and output where possible without sacrificing accuracy or security.
*   Keep `README.md` updated with current capabilities and usage instructions.
*   Follow Python best practices for code clarity and organization.
