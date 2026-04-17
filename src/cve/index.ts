/**
 * CVE Module Index
 * Export all CVE monitoring, scanning and alerting tools
 */

// CVE Monitor - NVD NIST API Client
export { CveMonitor, CveItem, CveSearchOptions, CveSearchResponse, RateLimitInfo } from './cve-monitor';

// CVE Summarizer - Smart summary generator
export { CveSummarizer, CveSummary, ReportOptions, DigestItem } from './cve-summarizer';

// CVE Alert System - Continuous monitoring
export { CveAlertSystem, AlertFilter, AlertCallback, CveAlert, MonitorConfig, MonitorState } from './cve-alert-system';

// Dependency Scanner - Scan project dependencies for vulnerabilities
export { DependencyScanner, DependencyInfo, VulnerableDependency, ScanOptions, ScanResult } from './dependency-scanner';
