# Check Compromised

A simple Node.js tool to scan your project for compromised npm packages.

## What it does

Scans your `node_modules` and `package-lock.json` for installed package versions and compares them against a known list of compromised versions. Exits with error code 1 if any compromised packages are found.

## Why this tool complements npm audit

`npm audit` is great for finding known vulnerabilities, but it has some limitations with supply chain attacks like the one this tool was created for. This incident involved malicious versions that had no CVE at the time, so audit would report "0 vulnerabilities" while potentially running malicious code.

### Where npm audit falls short

* **Scope**: Focuses on CVEs and known vulnerabilities, not live malicious versions
* **Timing**: There's often a delay before advisories are published, giving malicious packages time to spread
* **Granularity**: Uses range-based detection rather than exact version matching
* **Coverage**: Doesn't catch supply chain techniques like malicious postinstall scripts or token theft

### Where npm audit still helps

* Finding CVE-style vulnerabilities after they're disclosed
* Setting policy gates in CI for known severities  
* Verifying you're not regressing to vulnerable version ranges

## Usage

### Via npx (recommended)
```bash
# Check for compromised packages
npx check-compromised-npm-packages

# Output results as JSON
npx check-compromised-npm-packages --json

# Show the list of known compromised packages
npx check-compromised-npm-packages --list
```

### Local usage
```bash
# Check for compromised packages
node check-compromised.js

# Output results as JSON
node check-compromised.js --json

# Show the list of known compromised packages
node check-compromised.js --list
```

## Setup

Place a `compromised.json` file in your project root with the format, or re-use mine :)

```json
{
  "packages": [
    { "name": "@ctrl/tinycolor", "badVersions": ["4.1.1", "4.1.2"] },
    { "name": "angulartics2", "badVersions": ["14.1.2"] }
  ]
}
```

**Current list of compromised packages:** [compromised.json](https://github.com/Antonhansel/check-compromised-npm-packages/blob/master/compromised.json)

**Sources:**
- [2024-12-19] [Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)

## Understanding the threat: Install script vulnerabilities

As documented in the [npm blog](https://blog.npmjs.org/post/141702881055/package-install-scripts-vulnerability), malicious packages can execute scripts during installation that can:

- **Self-replicate**: Include themselves in new packages and publish them to the registry
- **Steal credentials**: Access environment variables, tokens, and other sensitive data
- **Spread laterally**: Compromise other packages owned by the same user
- **Execute arbitrary code**: Run any malicious code during the install process

This is why `--ignore-scripts` is crucial - it prevents these attack vectors from executing during installation.

## Additional security recommendations

This tool works best as part of a broader security strategy. Here are some suggestions that might help:

1. **Use this tool alongside npm audit** - scan for exact compromised versions and fail builds on hits
2. **Always block lifecycle scripts in CI** to reduce attack surface:
   ```bash
   # For npm 8+
   npm ci --ignore-scripts
   # Or set globally in CI
   export npm_config_ignore_scripts=true
   # Or configure npm globally
   npm config set ignore-scripts true
   ```
3. **Implement 2FA for publishing** - as mentioned in the npm blog, 2FA helps prevent unauthorized package publishing
4. **Keep dependencies stable**:
   - Use `npm ci` with a committed lockfile
   - Pin direct dependencies for critical packages
   - Be careful with automatic dependency updates
   - Consider a cooldown period (48-72 hours) for new package releases
5. **Monitor network activity in CI**:
   - Consider restricting outbound connections to known endpoints
   - Watch for unexpected network activity during installs
6. **Use package integrity verification**:
   - Verify package checksums when possible
   - Consider using tools that check package integrity
7. **Have a response plan**:
   - If compromised packages are found, rotate any potentially exposed credentials
   - Review what the malicious code might have accessed
   - Report malicious packages to support@npmjs.com

### CI Integration

```yaml
# GitHub Actions example
- name: Install without scripts
  run: npm ci --ignore-scripts

- name: Scan for malicious versions
  run: npx check-compromised-npm-packages

- name: Abort on findings
  if: failure()
  run: |
    echo "Compromised packages detected. Blocking build."
    exit 1
```

### Advanced CI Security

For high-security environments, consider these additional measures:

```yaml
# Enhanced security example
- name: Set up secure npm config
  run: |
    npm config set ignore-scripts true
    npm config set audit-level moderate
    npm config set fund false

- name: Install with integrity checks
  run: npm ci --ignore-scripts --audit

- name: Scan for compromised packages
  run: npx check-compromised-npm-packages

- name: Verify no unexpected network calls
  run: |
    # Monitor for unexpected outbound connections
    # This is environment-specific but important for detecting malicious behavior
```

**Key principles from the community:**
- **Defense in depth**: Use multiple layers of security checks
- **Fail fast**: Stop builds immediately when issues are detected  
- **Audit everything**: Regular security scanning and monitoring
- **Least privilege**: Only install what you need, when you need it

## Origin

This tool was created in response to the [@ctrl/tinycolor and 40+ NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) supply chain attack.

The `compromised.json` file will be updated as more compromised packages are discovered to enhance detection capabilities.
