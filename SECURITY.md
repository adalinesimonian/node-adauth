# Security Policy

## Supported Versions

The last three minor releases of the most recent major version are supported.

| Version | Supported Until        | Support Status |
| ------- | ---------------------- | -------------- |
| 1.0     | 1.3 or 2.0 is released | ✅ Supported   |
| 0.x     |                        | ❌ Unsupported |

## Reporting a Vulnerability

If you find a vulnerability in adauth, please get in touch with Adaline at [adalinesimonian@gmail.com](mailto:adalinesimonian@gmail.com). Provide the following information:

- The version of adauth affected by the vulnerability (e.g. 1.0.0)
- The type of vulnerability (e.g. buffer overflow)
- Detailed steps to reproduce the vulnerability
- Proof-of-concept or exploit code
- The potential impact of the vulnerability

## Security Response Process

When a vulnerability is reported, or if we discover a security issue, we will:

1. Investigate the issue and verify that the alleged vulnerability is exploitable.
1. If the vulnerability is validated, we will determine whether or not the vulnerability has already been addressed or if an existing mitigation is available.
1. If the vulnerability has not yet been addressed, we will [classify the vulnerability](#vulnerability-severity) as a **critical**, **high**, **medium**, or **low**-severity issue, which will determine the response time and mitigation plan.

   If a third party reported the vulnerability, we will communicate and work with the reporter throughout the response process.

## Vulnerability Severity

The response to the vulnerability depends on its severity:

<!-- prettier-ignore -->
| Severity | Response |
| -------- | -------- |
| **Critical** vulnerabilities can be easily exploited by an unauthorised user to gain elevated privileges on the targeted system. Successful exploitation completely compromises data or application security, integrity, or availability. | **Immediate response**: We will immediately take action and fix the vulnerability as promptly as possible in a patch release. |
| **High**-severity vulnerabilities: <br /><ul><li>allow authenticated users or attackers manipulating an authorised user to gain unauthorised access to data, or</li><li>allow an unathorised user to completely compromise system or application availability.</li></ul> | **Expedited response**: We will take action to fix the vulnerability as quickly as possible and release a fix in a patch release. |
| **Moderate**-severity vulnerabilities require more specific circumstances to be exploited, such as a certain configuration or factor in the environment, but can still be abused to compromise system or application integrity or availability. | **Standard response**: We will release a fix in the next major or minor release. |
| **Low**-severity vulnerabilities either have a minimal impact on application and data security or have significant hurdles that must be overcome before they can be exploited. | **Standard response**: We will release a fix in the next major or minor release. |
