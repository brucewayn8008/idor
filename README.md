# IDOR-BAC Hunter

A security testing tool for detecting Insecure Direct Object References (IDOR) and Broken Access Control (BAC) vulnerabilities by analyzing and comparing endpoint responses using different user sessions.

## Features

- Analyzes endpoints using multiple user sessions
- Detects potential IDOR and BAC vulnerabilities
- Supports both cookie and token-based authentication
- Handles multiple HTTP methods (GET, POST, PUT, DELETE)
- Generates detailed vulnerability reports

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/idor-bac-hunter.git
cd idor-bac-hunter
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

1. Create a `sessions.json` file in the `config` directory with your user credentials:
```json
{
    "admin": {
        "cookie": "sessionid=admin123; role=administrator"
    },
    "user1": {
        "cookie": "sessionid=user456; role=user"
    },
    "user2": {
        "token": "Bearer your-jwt-token"
    }
}
```

2. Export your target application's sitemap from Burp Suite to a text file.

## Usage

Basic usage:
```bash
python main.py -s sitemap.txt -c config/sessions.json
```

Options:
- `-s, --sitemap`: Path to Burp Suite sitemap export file
- `-c, --config`: Path to sessions configuration file
- `-o, --output`: Directory to store results (default: output/)
- `-v, --verbose`: Enable verbose output

## Output

The tool generates two types of output:
1. JSON report with detailed findings
2. Log file with scan progress and errors

Example finding:
```json
{
    "timestamp": "2024-03-20T10:30:00",
    "endpoint": "/api/users/1001",
    "type": "IDOR",
    "severity": "Medium",
    "details": {
        "description": "User2 can access User1's data",
        "evidence": {
            "status_code": 200,
            "unauthorized_access": true
        }
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 