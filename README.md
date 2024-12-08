# Log Analysis Script

## **Project Overview**
This Python script processes a web server log file to extract and analyze key information. It performs the following tasks:
1. **Count Requests per IP Address**: Identifies and counts the number of requests made by each IP address.
2. **Find Most Frequently Accessed Endpoint**: Determines the endpoint (URL or resource path) accessed the most.
3. **Detect Suspicious Activity**: Flags IP addresses with failed login attempts exceeding a configurable threshold.
4. **Generate CSV Output**: Saves all results into a structured CSV file for further use.

## **Key Features**
- **File Handling**: Efficiently reads and processes large log files.
- **String Manipulation**: Extracts IPs, endpoints, and status codes using regular expressions.
- **Data Analysis**: Detects patterns, counts occurrences, and identifies suspicious activity.
- **Output**: Results are displayed in the terminal and saved to a CSV file.

## **Requirements**
- Python 3.6 or later
- Required libraries: 
  - `csv`
  - `collections`
  - `re`

## **Setup Instructions**

1. Clone or download this repository to your local machine.
2. Save your log file (e.g., `sample.log`) in the same directory as the Python script. You can use the sample log file provided in this project.
3. Ensure Python is installed on your system. You can check by running:
   ```bash
   python --version
   ```

## **Usage**

1. Open the script file and update the `log_file_path` variable if your log file is in a different directory:
   ```python
   log_file_path = 'path/to/your/sample.log'
   ```
   Replace `'path/to/your/sample.log'` with the actual path to your log file.

2. Run the script:
   ```bash
   python log_analysis.py
   ```

3. The script will:
   - Display results in the terminal:
     - Request counts per IP address
     - The most frequently accessed endpoint
     - Suspicious activity detected
   - Save results to a CSV file (`log_analysis_results.csv`) in the same directory as the script.

## **Expected Output**
### **Terminal Output**
The script will display the following:

#### Requests per IP Address:
```
IP Address           Request Count
192.168.1.1          8
203.0.113.5          12
10.0.0.2             6
198.51.100.23        8
192.168.1.100        7
```

#### Most Frequently Accessed Endpoint:
```
Most Frequently Accessed Endpoint:
/home (Accessed 6 times)
```

#### Suspicious Activity Detected:
```
Suspicious Activity Detected:
IP Address           Failed Login Count
203.0.113.5          12
192.168.1.100        7
```

### **CSV Output**
The CSV file `log_analysis_results.csv` will contain:
1. **Requests per IP**: IP Address and Request Count
2. **Most Accessed Endpoint**: Endpoint and Access Count
3. **Suspicious Activity**: IP Address and Failed Login Count

## **Sample Log File**
Here’s a sample log file format to test the script:
```
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
...
```

## **Customizations**
1. **Failed Login Threshold**: You can configure the threshold for suspicious activity detection by updating the `FAILED_LOGIN_THRESHOLD` variable in the script:
   ```python
   FAILED_LOGIN_THRESHOLD = 10
   ```

2. **Log File Path**: Update the `log_file_path` variable to specify a custom path to the log file.

3. **Output File Name**: Modify the `output_csv_path` variable to save the CSV file with a different name or in a different location.

---
