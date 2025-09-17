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

**Current list of compromised packages:** [compromised.json](./compromised.json)

## Additional security recommendations

This tool works best as part of a broader security strategy. Here are some suggestions that might help:

1. **Use this tool alongside npm audit** - scan for exact compromised versions and fail builds on hits
2. **Consider blocking lifecycle scripts in CI** to reduce attack surface:
   ```bash
   # For npm 8+
   npm ci --ignore-scripts
   # Or set in CI
   export npm_config_ignore_scripts=true
   ```
3. **Keep dependencies stable**:
   - Use `npm ci` with a committed lockfile
   - Pin direct dependencies for critical packages
   - Be careful with automatic dependency updates
4. **Monitor network activity in CI**:
   - Consider restricting outbound connections to known endpoints
   - Watch for unexpected network activity during installs
5. **Have a response plan**:
   - If compromised packages are found, rotate any potentially exposed credentials
   - Review what the malicious code might have accessed

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

**Optional**: You might also consider adding a cooldown period for new package releases - some teams wait 48-72 hours before auto-merging dependency updates to allow time for issues to be discovered.

## Origin

This tool was created in response to the [@ctrl/tinycolor and 40+ NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) supply chain attack.

The `compromised.json` file will be updated as more compromised packages are discovered to enhance detection capabilities.
