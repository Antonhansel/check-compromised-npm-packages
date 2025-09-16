# Check Compromised

A simple Node.js tool to scan your project for compromised npm packages.

## What it does

Scans your `node_modules` and `package-lock.json` for installed package versions and compares them against a known list of compromised versions. Exits with error code 1 if any compromised packages are found.

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

## Origin

This tool was created in response to the [@ctrl/tinycolor and 40+ NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised) supply chain attack.

The `compromised.json` file will be updated as more compromised packages are discovered to enhance detection capabilities.
