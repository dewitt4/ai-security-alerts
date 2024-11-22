# Contributing to AI Security Monitor

## How to Contribute

1. Fork repository
2. Create feature branch (`git checkout -b feature/xyz`)
3. Make changes
4. Run tests (`python -m pytest`)
5. Submit pull request

## Guidelines

### Security
- Defensive security purposes only
- No malicious code or attack tools
- Report vulnerabilities via security@project.com

### Code Standards
- Follow PEP 8
- Add type hints
- Include docstrings
- Add tests
- Update documentation

### Testing
```bash
# Run tests
python -m pytest

# Check coverage
coverage run -m pytest
coverage report
```

### Documentation
- Update README.md
- Document security implications
- Include example usage
- Comment security-critical code

### Logging
- Use standard logging
- Log security events
- No sensitive data in logs

## Pull Request Process

1. Update documentation
2. Add/update tests
3. Pass all checks
4. Request review

## Questions?

Open an issue or discussion.

## License

By contributing, you agree to MIT License terms.