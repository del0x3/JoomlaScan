# JoomlaScan v2.0

A modern, fast, and efficient Joomla vulnerability scanner. Built with Python 3.12+ and designed for security professionals.

## 📋 About

This is a complete modernization of the original [JoomlaScan](https://github.com/drego85/JoomlaScan) project, which was inspired by the now-defunct [OWASP JoomScan](https://github.com/OWASP/joomscan). The original project was last updated 3 years ago and used older Python practices.

Key improvements in this version:
- Modern Python 3.12+ features and best practices
- Asynchronous scanning with asyncio
- Type-safe code with Pydantic
- Enhanced error handling and retry logic
- Improved reporting with rich console output
- Docker support with optimized builds
- Comprehensive vulnerability database
- Better performance through parallel processing

## 🚀 Features

- **Fast & Efficient**: Parallel scanning with async/await
- **Smart Detection**: Identifies common Joomla vulnerabilities
- **Detailed Reporting**: Rich console output with vulnerability details
- **Flexible Configuration**: Customizable scanning options
- **Docker Support**: Ready-to-use containerized version
- **Modern Codebase**: Type hints, async/await, and best practices
- **Enhanced Security**: Better error handling and retry mechanisms
- **Comprehensive Database**: Updated component and vulnerability database

## 🛠️ Installation

### Local Installation

```bash
# Clone the repository
git clone https://github.com/del0x3/JoomlaScan.git
cd JoomlaScan

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build the image
docker build -t joomlascan .

# Run the scanner
docker run -it joomlascan http://target-site.com
```

## 💻 Usage

Basic usage:
```bash
python joomla_scanner.py http://target-site.com
```

Advanced options:
```bash
# Scan with custom threads and timeout
python joomla_scanner.py http://target-site.com --threads 10 --timeout 30

# Save results to file
python joomla_scanner.py http://target-site.com --output scan_results.json

# Disable SSL verification
python joomla_scanner.py http://target-site.com --no-verify-ssl
```

## 🔍 What it Checks

- Directory listing vulnerabilities
- Exposed documentation files
- Component version information
- Common misconfigurations
- Security headers
- And more...

## 📝 Output Example

```
╭────────────────────────╮
│ Joomla Scanner Results │
╰────────────────────────╯
                       Scan Summary                        
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                ┃ Value                           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Target URL            │ http://example.com              │
│ Scan Time             │ 2024-03-27 15:30:00             │
│ Duration              │ 45.23 seconds                   │
│ Components Found      │ 12                              │
│ Total Vulnerabilities │ 8                               │
└───────────────────────┴─────────────────────────────────┘
```

## 🤝 Contributing

Feel free to submit issues and enhancement requests! 

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

- **del** - [@del0x3](https://github.com/del0x3)

## 🙏 Acknowledgments

- Original JoomlaScan project by [@drego85](https://github.com/drego85/JoomlaScan)
- Inspired by OWASP JoomScan project
- Thanks to all contributors who helped improve this tool
- Special thanks to the Joomla security community
- Inspired by various security tools and best practices

