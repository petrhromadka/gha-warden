# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe the problem and, if you can, include a minimal workflow file that reproduces it.

Please do not open a public issue for a vulnerability. This is a small personal project, so there is no formal response-time guarantee, but reports are read and acknowledged.

## Scope

gha-warden is a static analyzer that reads workflow files and never executes them or contacts the network. Relevant reports include crashes or hangs on crafted YAML, and any way a scanned file can make the tool run code or write outside the requested output file. Missed detections and false positives are not vulnerabilities; please use the regular issue forms for those.

## Supported versions

Only the latest release on the default branch receives fixes.
