# Security Policy

## CVE-2025-55182 - React Flight Protocol RCE Vulnerability

### Status: ✅ FIXED

### Description
This application was affected by **CVE-2025-55182**, a critical Remote Code Execution (RCE) vulnerability in the React flight protocol affecting React 19.x and Next.js 15.x/16.x using the App Router.

### Severity
- **CVSS Score**: 10.0 (Critical)
- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
- **CWE**: CWE-502 (Deserialization of Untrusted Data)

### Affected Versions
- React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js: 15.x and 16.x (specifically 16.0.0-canary.0 to 16.0.6)
- Affected React packages:
  - react-server-dom-parcel
  - react-server-dom-turbopack
  - react-server-dom-webpack

### Fixed Versions
- React: ✅ Updated to 19.2.1
- React-DOM: ✅ Updated to 19.2.1
- Next.js: ✅ Updated to 16.0.7

### Mitigation Applied
The vulnerability has been fixed by updating the affected dependencies to their patched versions:

**Previous versions:**
```json
"react": "19.2.0"      // Vulnerable
"react-dom": "19.2.0"  // Vulnerable
"next": "16.0.3"       // Vulnerable (in package-lock.json)
```

**Updated versions:**
```json
"react": "19.2.1"      // Patched
"react-dom": "19.2.1"  // Patched
"next": "16.0.7"       // Patched
```

### Verification
Run `npm audit` to verify no vulnerabilities remain:
```bash
npm audit
# Expected output: found 0 vulnerabilities
```

### References
- GitHub Advisory: [GHSA-9qr9-h5gf-34mp](https://github.com/advisories/GHSA-9qr9-h5gf-34mp)
- CVE: [CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182

### Timeline
- **December 9, 2024**: Vulnerability identified through security audit
- **December 9, 2024**: Dependencies updated to patched versions
- **December 9, 2024**: Security fix verified with `npm audit`

## Reporting Security Issues

If you discover a security vulnerability in this project, please report it by:
1. Opening a security advisory on GitHub
2. Contacting the maintainers directly

Please do not disclose security vulnerabilities publicly until they have been addressed.
