import re
import csv
from collections import defaultdict

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):

    """Parses the log file and returns the lines."""
    
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_lines):
    
    """Counts the number of requests per IP address."""
    
    ip_count = defaultdict(int)
    for line in log_lines:
        # Extract IP addresses using regex
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_count[ip] += 1
    return sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

def find_most_accessed_endpoint(log_lines):
    
    """Finds the most frequently accessed endpoint."""
    
    endpoint_count = defaultdict(int)
    for line in log_lines:
        # Extract endpoints (assuming they follow an HTTP method like GET/POST)
        match = re.search(r'"(GET|POST|PUT|DELETE|HEAD) (.+?) HTTP/', line)
        if match:
            endpoint = match.group(2)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(log_lines):
    
    """Detects suspicious activity based on failed login attempts."""
    
    failed_logins = defaultdict(int)
    for line in log_lines:
        # Look for failed login attempts (HTTP 401 status code or failure keywords)
        if '401' in line or 'Invalid credentials' in line:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_logins[ip] += 1
    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(results, output_file):
    
    """Saves the analysis results to a CSV file."""
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(results['requests_per_ip'])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(results['most_accessed_endpoint'])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(results['suspicious_activity'].items())

def main():
    
    log_file_path = 'sample.log'
    output_csv_path = 'log_analysis_results.csv'

    # Parse log file
    log_lines = parse_log_file(log_file_path)
    
    # Analyze log data
    requests_per_ip = count_requests_per_ip(log_lines)
    most_accessed_endpoint = find_most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)

    # Print results
    print("IP Address           Request Count")
    for ip, count in requests_per_ip:
        print(f"{ip:20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:20} {count}")

    # Save results to CSV
    results = {
        'requests_per_ip': requests_per_ip,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_activity': suspicious_activity
    }
    save_results_to_csv(results, output_csv_path)
    print(f"\nResults saved to {output_csv_path}")

if __name__ == "__main__":
    main()
