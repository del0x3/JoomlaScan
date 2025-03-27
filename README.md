# Modern Joomla Scanner

A fast and efficient Joomla CMS vulnerability scanner written in Python 3.12+.

## Features

- 🚀 Asynchronous scanning for better performance
- 🔍 Comprehensive component detection
- 🛡️ Vulnerability checks for common issues
- 📊 Rich progress and result display
- 🔒 Modern security practices
- 🎯 Type-safe code with Pydantic

## Requirements

- Python 3.12 or higher
- Docker (optional)

## Installation

### Using pip

```bash
pip install -r requirements.txt
```

### Using Docker

```bash
docker build -t joomlascan .
```

## Usage

### Command Line

```bash
python joomla_scanner.py http://target-site.com [--threads 10] [--timeout 5.0]
```

### Docker

```bash
docker run joomlascan http://target-site.com [--threads 10] [--timeout 5.0]
```

## Options

- `url`: Target Joomla site URL (required)
- `--threads`: Number of concurrent threads (default: 10)
- `--timeout`: Request timeout in seconds (default: 5.0)

## Example Output

```
Joomla Scanner
Scanning: http://example.com
Threads: 10
Timeout: 5.0s

Found Components:
com_content
Paths: /components/com_content/, /index.php?option=com_content
Vulnerabilities: Directory listing enabled, README files exposed

com_users
Paths: /components/com_users/
Vulnerabilities: Manifest files exposed
```

## Security Note

This tool is for educational and security research purposes only. Always obtain proper authorization before scanning any systems.

## License

MIT License - See LICENSE file for details

