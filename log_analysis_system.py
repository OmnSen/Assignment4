import os
import re
from collections import Counter

MAX_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
DEFAULT_LOG = "log.txt"

apache_regex = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (?P<url>\S+)[^"]*" (?P<status>\d{3})'
)

def ensure_sample_log(log_path: str) -> None:
    """Creating a small sample log if it doesn't exist."""
    if os.path.exists(log_path):
        return
    sample_lines = [
        "192.168.1.1 /home 200",
        "192.168.1.2 /login 404",
        "192.168.1.3 /dashboard 200",
        "192.168.1.1 /home 500",
        "192.168.1.2 /about 200",
        "10.0.0.5 /contact 200",
        "10.0.0.5 /home 200",
        "172.16.0.3 /login 401",
        "172.16.0.3 /login 200",
        "192.168.1.3 /profile 200",
        # Some Apache-style lines for robustness:
        '203.0.113.10 - - [10/Jul/2025:21:15:32 +0530] "GET /index.html HTTP/1.1" 200 1043',
        '203.0.113.10 - - [10/Jul/2025:21:15:34 +0530] "GET /about HTTP/1.1" 200 1043',
        '198.51.100.4 - - [10/Jul/2025:21:16:01 +0530] "GET /login HTTP/1.1" 404 523',
        '198.51.100.4 - - [10/Jul/2025:21:16:22 +0530] "POST /login HTTP/1.1" 200 890',
    ]
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sample_lines))

def parse_line(line: str):
    
    parts = line.strip().split()
    if len(parts) >= 3 and parts[2].isdigit():
        ip, url, status = parts[0], parts[1], parts[2]
        return ip, url, status

    m = apache_regex.match(line)
    if m:
        return m.group("ip"), m.group("url"), m.group("status")

    return None

def analyze_log(file_path: str):
    """Analyzing the log file and return counters for IPs, URLs, and statuses."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    size = os.path.getsize(file_path)
    if size > MAX_SIZE_BYTES:
        raise ValueError(" File too large! Must be under 100 MB.")

    ip_count = Counter()
    url_count = Counter()
    status_count = Counter()

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            parsed = parse_line(line)
            if not parsed:
                # skiping malformed lines silently (could log if needed)
                continue
            ip, url, status = parsed
            ip_count[ip] += 1
            url_count[url] += 1
            status_count[status] += 1

    return ip_count, url_count, status_count

def show_top(counter: Counter, title: str, top_n: int = 5):
    print(f"\n {title} (Top {top_n}):")
    for item, count in counter.most_common(top_n):
        print(f"{item} → {count}")

def main():
    print("=====  Log Analysis System (Task 4) =====")
    print("Tip: Place your log file next to this script and name it 'log.txt'.")
    print("If no file exists, a sample 'log.txt' will be created automatically.\n")

    log_path = DEFAULT_LOG
    if not os.path.exists(log_path):
        ensure_sample_log(log_path)
        print(f"ℹ No log file found. A sample '{log_path}' has been created for you.\n")

    try:
        ip_count, url_count, status_count = analyze_log(log_path)
    except FileNotFoundError as e:
        print(str(e))
        return
    except ValueError as e:
        print(str(e))
        return

    while True:
        print("\nChoose an option:")
        print("1. Show Top IPs")
        print("2. Show Top URLs")
        print("3. Show Response Codes Summary")
        print("4. Show All Insights")
        print("5. Exit")
        choice = input("Enter choice (1-5): ").strip()

        if choice == "1":
            show_top(ip_count, "IP Addresses")
        elif choice == "2":
            show_top(url_count, "URLs")
        elif choice == "3":
            print("\n Response Codes Summary:")
            for status, count in status_count.most_common():
                print(f"{status} → {count}")
        elif choice == "4":
            show_top(ip_count, "IP Addresses")
            show_top(url_count, "URLs")
            print("\n Response Codes Summary:")
            for status, count in status_count.most_common():
                print(f"{status} → {count}")
        elif choice == "5":
            print("Exiting... Bye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
