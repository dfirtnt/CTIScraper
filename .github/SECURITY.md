# Security Policy

## Supported Versions

We release patches to fix high severity security issues. The following versions are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of CTI Scraper seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### **Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to our security team at `security@ctiscraper.com` (replace with your actual security contact).

### What to include in your report

To help us understand and resolve the issue, please include the following information:

1. **Type of issue** (buffer overflow, SQL injection, cross-site scripting, etc.)
2. **Full paths of source file(s) related to the vulnerability**
3. **The location of the affected source code** (tag/branch/commit or direct URL)
4. **Any special configuration required to reproduce the issue**
5. **Step-by-step instructions to reproduce the issue**
6. **Proof-of-concept or exploit code** (if possible)
7. **Impact of the issue**, including how an attacker might exploit it

### What to expect

- You will receive a response within 48 hours acknowledging receipt of your report
- We will investigate and provide updates on our findings
- We will work with you to understand and address the issue
- We will credit you in our security advisory if you wish

## Security Best Practices

### For Users

1. **Keep dependencies updated**: Regularly update your dependencies to get the latest security patches
2. **Use environment variables**: Never hardcode secrets in your configuration files
3. **Enable security features**: Use HTTPS, enable rate limiting, and configure proper authentication
4. **Monitor logs**: Regularly check application logs for suspicious activity
5. **Regular backups**: Maintain regular backups of your database and configuration

### For Contributors

1. **Follow secure coding practices**: Use parameterized queries, validate input, and sanitize output
2. **Review code carefully**: Pay special attention to authentication, authorization, and data handling
3. **Test security features**: Include security tests in your test suite
4. **Keep secrets out of code**: Never commit API keys, passwords, or other sensitive information
5. **Use security tools**: Run security linters and vulnerability scanners

## Security Features

CTI Scraper includes several built-in security features:

- **Input validation**: All user inputs are validated using Pydantic models
- **SQL injection protection**: Uses parameterized queries and SQLAlchemy ORM
- **XSS protection**: Template escaping and content sanitization
- **Rate limiting**: Built-in rate limiting for API endpoints
- **CORS protection**: Configurable CORS settings
- **Authentication**: JWT-based authentication system
- **Authorization**: Role-based access control
- **Audit logging**: Comprehensive logging of security events

## Security Updates

We regularly update our dependencies and conduct security audits. Security updates are released as patch versions (e.g., 2.1.1, 2.1.2).

### Recent Security Updates

- **v2.0.1**: Updated cryptography library to fix CVE-2023-50782
- **v2.0.0**: Major security improvements including input validation and rate limiting
- **v1.2.3**: Fixed SQL injection vulnerability in search functionality

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private reporting**: Security issues are reported privately
2. **Coordinated disclosure**: We work with reporters to coordinate public disclosure
3. **Timely fixes**: We prioritize security fixes and release them promptly
4. **Clear communication**: We provide clear information about security updates

## Security Contacts

- **Security Team**: security@ctiscraper.com
- **Maintainers**: @project-maintainers
- **Emergency**: For critical issues, contact the maintainers directly

## Acknowledgments

We would like to thank the security researchers and community members who have responsibly reported vulnerabilities to us. Your contributions help make CTI Scraper more secure for everyone.

---

**Note**: This security policy is based on best practices and should be customized for your specific project needs. Make sure to update contact information and version numbers as appropriate.
