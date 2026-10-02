# Phishing URL Detector

A Java Swing-based desktop application that analyzes URLs and identifies potentially phishing URLs using rule-based detection techniques.

## Features

- Detects URLs containing IP addresses
- Checks for suspicious `@` symbols
- Identifies suspicious keywords
- Analyzes subdomain patterns
- Checks for suspicious hyphen usage
- Calculates a risk score
- Classifies URLs into Low, Medium, and High risk levels
- Provides a simple graphical user interface

## Technologies Used

- Java
- Java Swing
- Object-Oriented Programming
- Regular Expressions
- Eclipse IDE

## How It Works

The application analyzes the entered URL using multiple rule-based checks.

Each suspicious characteristic contributes to the overall risk score. Based on the calculated score, the application classifies the URL into different risk levels.

### Detection Factors

| Detection Factor | Description |
|---|---|
| IP Address | Checks whether the URL uses an IP address instead of a domain name |
| `@` Symbol | Detects the use of `@` in URLs |
| Suspicious Keywords | Checks for words associated with suspicious URLs |
| Subdomains | Analyzes the subdomain structure of the URL |
| Hyphens | Checks for suspicious use of hyphens in domain names |

## Project Structure

```text
src/
└── phishingdetector/
    ├── PhishingDetector.java
    └── PhishingDetectorGUI.java
