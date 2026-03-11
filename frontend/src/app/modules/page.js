'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';

const MODULES = [
  {
    name: 'InjectionScanner',
    category: 'Injection',
    icon: '💉',
    checks: [
      { id: 'INJ-001', name: 'SQL Injection', severity: 'Critical', desc: 'Tests SQL injection with various payloads and monitors for SQL error responses' },
      { id: 'INJ-002', name: 'XSS Reflected', severity: 'High', desc: 'Tests for reflected Cross-Site Scripting with script, event handler, and SVG payloads' },
      { id: 'INJ-004', name: 'HTML Injection', severity: 'Medium', desc: 'Tests for HTML injection using h1, marquee, and iframe tags' },
      { id: 'INJ-005', name: 'Command Injection (OS)', severity: 'Critical', desc: 'Tests OS command injection with ls, cat /etc/passwd, whoami payloads' },
      { id: 'INJ-007', name: 'CRLF Injection', severity: 'Medium', desc: 'Tests CRLF injection in HTTP headers for response splitting' },
      { id: 'INJ-008', name: 'Host Header Injection', severity: 'Medium', desc: 'Tests Host header manipulation for cache poisoning & redirect attacks' },
      { id: 'INJ-064', name: 'NoSQL Injection', severity: 'High', desc: 'Tests NoSQL injection with operators like $gt, $ne, $regex' },
      { id: 'INJ-006', name: 'LDAP Injection', severity: 'High', desc: 'Tests LDAP injection with wildcard and filter bypass payloads' },
    ],
  },
  {
    name: 'AdvancedInjectionScanner',
    category: 'Advanced Injection',
    icon: '🧪',
    checks: [
      { id: 'ADV-089', name: 'Server-Side Template Injection (SSTI)', severity: 'Critical', desc: 'Tests SSTI on form inputs with payloads like {{7*7}}' },
      { id: 'ADV-090', name: 'Server-Side Request Forgery (SSRF)', severity: 'High', desc: 'Tests SSRF on URL parameters to load internal resources' },
      { id: 'ADV-091', name: 'XML External Entity (XXE)', severity: 'Critical', desc: 'Tests XXE injection with payloads to read internal files' },
    ],
  },
  {
    name: 'AuthSessionScanner',
    category: 'Authentication & Session',
    icon: '🔐',
    checks: [
      { id: 'AUTH-012', name: 'Cookie Security Flags Missing', severity: 'Medium', desc: 'Checks for HttpOnly, Secure, and SameSite flags on cookies' },
      { id: 'AUTH-051', name: 'Session ID in URL', severity: 'High', desc: 'Detects session IDs exposed in URL parameters (session hijacking risk)' },
      { id: 'AUTH-009', name: 'Brute Force Login Detection', severity: 'Medium', desc: 'Detects login forms without CAPTCHA or rate limiting protection' },
      { id: 'AUTH-013', name: 'Default Credentials', severity: 'Critical', desc: 'Tests login with common default credentials (admin/admin, admin/password)' },
      { id: 'AUTH-012J', name: 'JWT Vulnerability Check', severity: 'High', desc: "Checks for JWT with 'none' algorithm or exposed tokens" },
      { id: 'AUTH-056', name: 'Insecure Session Storage', severity: 'Medium', desc: 'Detects tokens stored in localStorage/sessionStorage' },
      { id: 'AUTH-054', name: 'Session ID Entropy Check', severity: 'Medium', desc: 'Checks if session ID is too short (<16 chars) for brute-force resistance' },
    ],
  },
  {
    name: 'AdvancedAuthScanner',
    category: 'Authentication Advanced',
    icon: '🛡️',
    checks: [
      { id: 'AUTH-097', name: 'Username Enumeration', severity: 'Medium', desc: 'Detects error messages that distinguish between valid/invalid usernames' },
      { id: 'AUTH-098', name: 'Password Reset Poisoning', severity: 'High', desc: 'Tests Host Header poisoning on password reset pages' },
      { id: 'AUTH-099', name: 'OAuth Misconfiguration', severity: 'High', desc: 'Detects misconfigurations in OAuth (exposed secrets, insecure redirect URIs)' },
    ],
  },
  {
    name: 'BusinessLogicScanner',
    category: 'Business Logic',
    icon: '💰',
    checks: [
      { id: 'BIZ-018', name: 'Hidden Field Manipulation', severity: 'High', desc: 'Detects sensitive hidden form fields (price, role, discount, admin flags)' },
      { id: 'BIZ-017', name: 'Price/Parameter Tampering', severity: 'Critical', desc: 'Tests if price/amount parameters can be tampered in requests' },
      { id: 'BIZ-020', name: 'Negative Value Testing', severity: 'High', desc: 'Tests if backend accepts negative values for quantities/prices' },
      { id: 'BIZ-019', name: 'Race Condition Indicator', severity: 'Medium', desc: 'Detects POST forms that may be vulnerable to race conditions' },
    ],
  },
  {
    name: 'InfoDisclosureScanner',
    category: 'Information Disclosure',
    icon: '📋',
    checks: [
      { id: 'INFO-026', name: 'Server Version Disclosure', severity: 'Low', desc: 'Detects version leakage in Server, X-Powered-By, X-AspNet-Version headers' },
      { id: 'INFO-027', name: 'Sensitive File Exposure', severity: 'High', desc: 'Checks for exposed sensitive files (.env, .git/config, config.php, etc.)' },
      { id: 'INFO-028', name: 'Directory Listing Enabled', severity: 'Medium', desc: 'Tests for enabled directory listing on web server' },
      { id: 'INFO-029', name: 'Error Message Info Leak', severity: 'Medium', desc: 'Detects PHP errors, stack traces, and database errors in responses' },
      { id: 'INFO-030', name: 'Admin Panel Finder', severity: 'Medium', desc: 'Discovers accessible admin panels (/admin, /wp-admin, /dashboard)' },
      { id: 'INFO-031', name: 'Backup File Finder', severity: 'High', desc: 'Searches for exposed backup files (.zip, .sql, .tar.gz, .bak)' },
      { id: 'INFO-032', name: 'robots.txt & Sitemap Analysis', severity: 'Info', desc: 'Analyzes robots.txt for sensitive disallowed paths' },
      { id: 'INFO-073', name: 'Debug Mode Detection', severity: 'High', desc: 'Detects active debug modes (Laravel, Django, Flask, Whoops)' },
      { id: 'INFO-178', name: 'HTML Comment Info Leakage', severity: 'Low', desc: 'Finds sensitive information leaked in HTML comments' },
    ],
  },
  {
    name: 'SecurityHeadersScanner',
    category: 'Security Headers',
    icon: '📡',
    checks: [
      { id: 'CSP-033', name: 'Missing Content-Security-Policy', severity: 'Medium', desc: 'Checks for missing CSP header (XSS protection)' },
      { id: 'HDR-034', name: 'Missing X-Frame-Options', severity: 'Medium', desc: 'Checks for missing clickjacking protection header' },
      { id: 'HDR-035', name: 'Missing X-Content-Type-Options', severity: 'Low', desc: 'Checks for missing MIME-sniffing protection' },
      { id: 'HDR-036', name: 'Missing HSTS', severity: 'Medium', desc: 'Checks for missing Strict-Transport-Security header' },
      { id: 'HDR-037', name: 'Missing X-XSS-Protection', severity: 'Low', desc: 'Checks for missing browser XSS filter header' },
      { id: 'HDR-038', name: 'Missing Referrer-Policy', severity: 'Low', desc: 'Checks for missing Referrer-Policy header' },
      { id: 'HDR-039', name: 'Missing Permissions-Policy', severity: 'Low', desc: 'Checks for missing feature/permissions policy header' },
    ],
  },
  {
    name: 'SslTlsScanner',
    category: 'SSL/TLS & Network',
    icon: '🔒',
    checks: [
      { id: 'SSL-040', name: 'SSL Certificate Validation', severity: 'High', desc: 'Tests for expired, self-signed, or invalid SSL certificates' },
      { id: 'SSL-043', name: 'HTTP to HTTPS Redirect', severity: 'Medium', desc: 'Checks if HTTP properly redirects to HTTPS' },
      { id: 'SSL-042', name: 'Mixed Content Detection', severity: 'Medium', desc: 'Detects insecure HTTP resources loaded from HTTPS pages' },
      { id: 'SSL-105', name: 'HSTS Preload Check', severity: 'Low', desc: 'Checks if HSTS header includes preload directive' },
    ],
  },
  {
    name: 'ClientSideScanner',
    category: 'Client-Side',
    icon: '🌐',
    checks: [
      { id: 'CLI-021', name: 'Open Redirect', severity: 'Medium', desc: 'Tests URL parameters for open redirect vulnerabilities' },
      { id: 'CLI-022', name: 'Clickjacking', severity: 'Medium', desc: 'Checks for X-Frame-Options and CSP frame-ancestors protection' },
      { id: 'CLI-023', name: 'CORS Misconfiguration', severity: 'High', desc: 'Tests for overly permissive CORS (wildcard, reflected origins)' },
      { id: 'CLI-024', name: 'DOM-based Vulnerability Hints', severity: 'Medium', desc: 'Detects dangerous JS sinks (innerHTML, eval) and sources (location.hash)' },
      { id: 'CLI-025', name: 'JavaScript Source Map Exposure', severity: 'Low', desc: 'Checks for exposed .js.map files leaking original source code' },
    ],
  },
  {
    name: 'ClientSideAdvancedScanner',
    category: 'Client-Side Advanced',
    icon: '⚡',
    checks: [
      { id: 'CLIADV-123', name: 'PostMessage Vulnerability', severity: 'Medium', desc: 'Checks postMessage usage without origin validation' },
      { id: 'CLIADV-126', name: 'Reverse Tabnabbing', severity: 'Low', desc: 'Detects target="_blank" links without noopener/noreferrer' },
      { id: 'COMP-106', name: 'Subresource Integrity (SRI) Missing', severity: 'Low', desc: 'Identifies external resources loaded without SRI attribute' },
    ],
  },
  {
    name: 'FileUploadScanner',
    category: 'File Upload',
    icon: '📤',
    checks: [
      { id: 'FILE-044', name: 'Unrestricted File Upload', severity: 'High', desc: 'Detects file upload forms without type restrictions' },
      { id: 'FILE-045', name: 'File Extension Bypass', severity: 'High', desc: 'Tests for dangerous file types accepted in upload restrictions' },
    ],
  },
  {
    name: 'FilePathScanner',
    category: 'File & Path Traversal',
    icon: '📂',
    checks: [
      { id: 'FILE-139', name: 'Path Traversal / LFI', severity: 'Critical', desc: 'Tests Local File Inclusion with payloads like ../../../etc/passwd' },
      { id: 'FILE-140', name: 'Remote File Inclusion (RFI)', severity: 'Critical', desc: 'Tests Remote File Inclusion by loading external payloads' },
    ],
  },
  {
    name: 'ApiSecurityScanner',
    category: 'API Security',
    icon: '🔌',
    checks: [
      { id: 'API-046', name: 'API Endpoint Discovery', severity: 'Info', desc: 'Discovers accessible API endpoints (api/users, graphql, swagger)' },
      { id: 'API-047', name: 'HTTP Method Tampering', severity: 'Medium', desc: 'Tests for dangerous HTTP methods allowed (PUT, DELETE, TRACE)' },
      { id: 'API-048', name: 'Rate Limiting Check', severity: 'Medium', desc: 'Checks if rapid requests trigger rate limiting protection' },
      { id: 'API-134', name: 'Swagger/OpenAPI Docs Exposed', severity: 'Medium', desc: 'Checks for exposed API documentation (swagger.json, openapi.json)' },
    ],
  },
  {
    name: 'ApiAdvancedScanner',
    category: 'API Advanced',
    icon: '🧩',
    checks: [
      { id: 'APIAV-129', name: 'IDOR / Broken Object Auth', severity: 'High', desc: 'Checks API endpoints for unauthorized access (api/users/1, api/order/1)' },
      { id: 'APIAV-132', name: 'GraphQL Batch Attack', severity: 'Medium', desc: 'Tests if GraphQL accepts batch queries for brute force attacks' },
      { id: 'APIAV-135', name: 'WSDL Disclosure (SOAP)', severity: 'Low', desc: 'Checks for exposed SOAP WSDL files' },
    ],
  },
  {
    name: 'CsrfScanner',
    category: 'CSRF',
    icon: '🎭',
    checks: [
      { id: 'CSRF-050', name: 'CSRF Token Missing/Weak', severity: 'High', desc: 'Checks POST forms for missing or weak CSRF token protection' },
    ],
  },
  {
    name: 'DatabaseScanner',
    category: 'Database Exposure',
    icon: '🗄️',
    checks: [
      { id: 'DB-057', name: 'Database Dump Exposure', severity: 'Critical', desc: 'Checks for exposed database dump files (.sql, .db, .sqlite)' },
      { id: 'DB-058', name: 'phpMyAdmin/Adminer Exposed', severity: 'High', desc: 'Detects exposed database administration panels' },
      { id: 'DB-062', name: 'DB Connection String Leakage', severity: 'Critical', desc: 'Finds database connection strings leaked in source code' },
      { id: 'DB-063', name: 'DB Error Message Leakage', severity: 'Medium', desc: 'Detects database error messages that leak internal info' },
    ],
  },
  {
    name: 'ServerInfraScanner',
    category: 'Server & Infrastructure',
    icon: '🖥️',
    checks: [
      { id: 'SRV-071', name: 'Server Status Page Exposed', severity: 'Medium', desc: 'Detects exposed server-status, nginx_status pages' },
      { id: 'SRV-072', name: 'PHP Info Page Exposure', severity: 'High', desc: 'Checks for publicly accessible phpinfo() pages' },
      { id: 'SRV-074', name: 'GraphQL Introspection Enabled', severity: 'Medium', desc: 'Tests if GraphQL introspection queries are allowed' },
    ],
  },
  {
    name: 'SourceCodeScanner',
    category: 'Source Code & Secrets',
    icon: '🔑',
    checks: [
      { id: 'SRC-075', name: 'Git Repository Exposure', severity: 'Critical', desc: 'Detects exposed .git directory with source code access' },
      { id: 'SRC-076', name: 'SVN Repository Exposure', severity: 'High', desc: 'Detects exposed .svn directory' },
      { id: 'SRC-082', name: '.env File Exposure', severity: 'Critical', desc: 'Checks for publicly accessible .env configuration files' },
      { id: 'SRC-078', name: 'API Key Leakage in JavaScript', severity: 'High', desc: 'Finds API keys, AWS keys, GitHub tokens in source code' },
      { id: 'SRC-079', name: 'Hardcoded Credentials', severity: 'High', desc: 'Detects hardcoded passwords and credentials in source' },
      { id: 'SRC-081', name: 'Private Key File Exposure', severity: 'Critical', desc: 'Checks for exposed private key files (.pem, .key)' },
      { id: 'SRC-162', name: 'Package/Dependency File Exposure', severity: 'Low', desc: 'Detects exposed package.json, composer.json, requirements.txt' },
    ],
  },
  {
    name: 'CmsScanner',
    category: 'CMS Specific',
    icon: '📝',
    checks: [
      { id: 'CMS-084', name: 'WordPress Version Detection', severity: 'Info', desc: 'Detects and extracts WordPress version' },
      { id: 'CMS-086', name: 'WordPress User Enumeration', severity: 'Medium', desc: 'Tests user enumeration via ?author= parameter' },
      { id: 'CMS-087', name: 'WordPress XML-RPC Enabled', severity: 'Medium', desc: 'Checks if XML-RPC is active (brute force/DDoS risk)' },
      { id: 'CMS-155', name: 'Joomla Detection', severity: 'Info', desc: 'Detects Joomla CMS and extracts version info' },
      { id: 'CMS-156', name: 'Drupal Detection', severity: 'Info', desc: 'Detects Drupal CMS and extracts version info' },
      { id: 'CMS-158', name: 'Laravel Telescope/Debug Exposed', severity: 'High', desc: 'Checks for exposed Laravel Telescope debug interface' },
      { id: 'CMS-159', name: 'Django Admin Exposed', severity: 'Medium', desc: 'Tests if Django admin panel is publicly accessible' },
      { id: 'CMS-160', name: 'Spring Boot Actuator Exposed', severity: 'High', desc: 'Checks for exposed Spring Boot Actuator endpoints' },
    ],
  },
  {
    name: 'CacheProxyScanner',
    category: 'Cache & Proxy',
    icon: '🗃️',
    checks: [
      { id: 'CACHE-111', name: 'Web Cache Poisoning', severity: 'High', desc: 'Tests cache poisoning via X-Forwarded-Host header manipulation' },
      { id: 'CACHE-112', name: 'Web Cache Deception', severity: 'High', desc: 'Tests serving HTML content for static file extensions' },
    ],
  },
  {
    name: 'EmailScanner',
    category: 'Email Vulnerabilities',
    icon: '📧',
    checks: [
      { id: 'EMAIL-114', name: 'Email Header Injection', severity: 'Medium', desc: 'Detects email/contact forms vulnerable to header injection' },
    ],
  },
  {
    name: 'WebSocketScanner',
    category: 'WebSocket',
    icon: '🔗',
    checks: [
      { id: 'WS-117', name: 'WebSocket Security Check', severity: 'Medium', desc: 'Detects WebSocket usage and checks for insecure ws:// connections' },
    ],
  },
  {
    name: 'ProtocolScanner',
    category: 'HTTP Protocol',
    icon: '📡',
    checks: [
      { id: 'PROTO-121', name: 'HTTP Method Override', severity: 'Medium', desc: 'Tests HTTP method override headers (X-HTTP-Method-Override)' },
    ],
  },
  {
    name: 'CryptoScanner',
    category: 'Cryptographic',
    icon: '🔏',
    checks: [
      { id: 'CRYPT-144', name: 'Weak Hashing Detection', severity: 'Low', desc: 'Detects weak hashes (MD5, SHA1) in response content' },
    ],
  },
  {
    name: 'CloudScanner',
    category: 'Cloud & Container',
    icon: '☁️',
    checks: [
      { id: 'CLOUD-151', name: 'Cloud Metadata SSRF Risk', severity: 'High', desc: 'Detects references to cloud metadata endpoints (169.254.169.254)' },
      { id: 'CLOUD-153', name: 'Firebase DB Misconfiguration', severity: 'Critical', desc: 'Tests for publicly accessible Firebase Realtime Database' },
      { id: 'CLOUD-149', name: 'K8s/Docker Dashboard Exposed', severity: 'Critical', desc: 'Checks for exposed Kubernetes/Docker dashboards' },
    ],
  },
  {
    name: 'SupplyChainScanner',
    category: 'Supply Chain',
    icon: '📦',
    checks: [
      { id: 'SUPPLY-161', name: 'JS Library Vulnerability', severity: 'Medium', desc: 'Detects outdated/vulnerable JS libraries (jQuery, Angular, Bootstrap)' },
    ],
  },
  {
    name: 'EncodingBypassScanner',
    category: 'Encoding & Bypass',
    icon: '🔀',
    checks: [
      { id: 'ENC-165', name: 'WAF Detection & Fingerprinting', severity: 'Info', desc: 'Identifies WAF (Cloudflare, AWS WAF, Akamai, ModSecurity)' },
      { id: 'ENC-169', name: 'HTTP Parameter Pollution (HPP)', severity: 'Low', desc: "Tests server's handling of duplicate parameters" },
    ],
  },
  {
    name: 'LoggingScanner',
    category: 'Logging & Monitoring',
    icon: '📊',
    checks: [
      { id: 'LOG-170', name: 'Log File Exposure', severity: 'High', desc: 'Detects exposed log files (error.log, laravel.log, access.log)' },
    ],
  },
  {
    name: 'MiscScanner',
    category: 'Miscellaneous',
    icon: '🔧',
    checks: [
      { id: 'MISC-175', name: 'Crossdomain.xml Misconfiguration', severity: 'Medium', desc: 'Checks overly permissive crossdomain.xml allowing Flash/Silverlight access' },
      { id: 'MISC-176', name: 'Sitemap Sensitive URL Leakage', severity: 'Low', desc: 'Analyzes sitemap.xml for sensitive or internal paths' },
      { id: 'MISC-174', name: 'JSONP Callback Injection', severity: 'Medium', desc: 'Detects JSONP callback parameters exploitable for data theft' },
      { id: 'MISC-108', name: 'Cache Control Headers Check', severity: 'Low', desc: 'Checks Cache-Control headers for sensitive data caching' },
    ],
  },
];

const SEVERITY_COLORS = {
  Critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  High: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  Low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  Info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const SEVERITY_DOT = {
  Critical: 'bg-red-500',
  High: 'bg-orange-500',
  Medium: 'bg-yellow-500',
  Low: 'bg-blue-500',
  Info: 'bg-gray-500',
};

export default function ModulesPage() {
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('All');
  const [expandedModule, setExpandedModule] = useState(null);

  const totalChecks = useMemo(() => MODULES.reduce((sum, m) => sum + m.checks.length, 0), []);

  const stats = useMemo(() => {
    const s = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    MODULES.forEach((m) => m.checks.forEach((c) => { s[c.severity] = (s[c.severity] || 0) + 1; }));
    return s;
  }, []);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return MODULES.map((m) => {
      const checks = m.checks.filter((c) => {
        const matchSev = filterSeverity === 'All' || c.severity === filterSeverity;
        const matchSearch = !q || c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q) || m.category.toLowerCase().includes(q);
        return matchSev && matchSearch;
      });
      return { ...m, checks };
    }).filter((m) => m.checks.length > 0);
  }, [search, filterSeverity]);

  const filteredTotal = useMemo(() => filtered.reduce((sum, m) => sum + m.checks.length, 0), [filtered]);

  return (
    <main className="min-h-screen">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center font-bold text-lg hover:bg-blue-700 transition-colors">VS</Link>
            <div>
              <h1 className="text-xl font-bold text-white">VulnScanner</h1>
              <p className="text-xs text-gray-400">Modules</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Home</Link>
            <Link href="/scan" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Scan All</Link>
            <Link href="/bulk" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Bulk Scan</Link>
            <Link href="/dorking" className="px-3 py-1.5 text-sm text-gray-400 hover:text-white rounded-lg transition-colors">Dorking</Link>
            <Link href="/modules" className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg font-medium">Modules</Link>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Title */}
        <div className="text-center mb-8">
          <h2 className="text-4xl font-bold text-white mb-3">Scanner Modules</h2>
          <p className="text-gray-400 text-lg">
            <span className="text-blue-400 font-semibold">{MODULES.length}</span> modules with{' '}
            <span className="text-blue-400 font-semibold">{totalChecks}</span> vulnerability checks
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-5 gap-3 mb-8">
          {Object.entries(stats).map(([sev, count]) => (
            <button key={sev} onClick={() => setFilterSeverity(filterSeverity === sev ? 'All' : sev)}
              className={`p-4 rounded-xl border text-center transition-all ${filterSeverity === sev ? SEVERITY_COLORS[sev] + ' ring-1 ring-offset-0' : 'bg-gray-900 border-gray-800 hover:border-gray-700'}`}>
              <div className={`text-2xl font-bold ${filterSeverity === sev ? '' : 'text-white'}`}>{count}</div>
              <div className={`text-xs mt-1 ${filterSeverity === sev ? '' : 'text-gray-400'}`}>{sev}</div>
            </button>
          ))}
        </div>

        {/* Search & Filter */}
        <div className="flex gap-3 mb-6">
          <div className="flex-1 relative">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input type="text" value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search modules, vulnerability ID, or description..."
              className="w-full pl-10 pr-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-all" />
          </div>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500">
            <option value="All">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        {/* Results count */}
        <div className="text-sm text-gray-500 mb-4">
          Showing {filteredTotal} checks across {filtered.length} modules
          {(search || filterSeverity !== 'All') && (
            <button onClick={() => { setSearch(''); setFilterSeverity('All'); }} className="ml-2 text-blue-400 hover:text-blue-300">
              Clear filters
            </button>
          )}
        </div>

        {/* Module list */}
        <div className="space-y-3">
          {filtered.map((mod) => {
            const isExpanded = expandedModule === mod.name;
            return (
              <div key={mod.name} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden hover:border-gray-700 transition-all">
                {/* Module header */}
                <button onClick={() => setExpandedModule(isExpanded ? null : mod.name)}
                  className="w-full px-6 py-4 flex items-center justify-between text-left">
                  <div className="flex items-center gap-4">
                    <span className="text-2xl">{mod.icon}</span>
                    <div>
                      <div className="flex items-center gap-3">
                        <span className="text-white font-semibold">{mod.category}</span>
                        <span className="text-xs text-gray-500 font-mono bg-gray-800 px-2 py-0.5 rounded">{mod.name}</span>
                      </div>
                      <div className="text-sm text-gray-400 mt-0.5">
                        {mod.checks.length} check{mod.checks.length !== 1 ? 's' : ''}
                        <span className="mx-2 text-gray-700">•</span>
                        {mod.checks.map((c) => c.severity).filter((v, i, a) => a.indexOf(v) === i).map((sev) => (
                          <span key={sev} className={`inline-block w-2 h-2 rounded-full mr-1 ${SEVERITY_DOT[sev]}`} title={sev} />
                        ))}
                      </div>
                    </div>
                  </div>
                  <svg className={`w-5 h-5 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </button>

                {/* Checks table */}
                {isExpanded && (
                  <div className="border-t border-gray-800">
                    <table className="w-full">
                      <thead>
                        <tr className="text-xs text-gray-500 uppercase">
                          <th className="px-6 py-3 text-left w-28">ID</th>
                          <th className="px-6 py-3 text-left w-20">Severity</th>
                          <th className="px-6 py-3 text-left">Vulnerability</th>
                          <th className="px-6 py-3 text-left">Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {mod.checks.map((check) => (
                          <tr key={check.id} className="border-t border-gray-800/50 hover:bg-gray-800/30 transition-colors">
                            <td className="px-6 py-3 text-xs font-mono text-gray-400">{check.id}</td>
                            <td className="px-6 py-3">
                              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_COLORS[check.severity]}`}>
                                {check.severity.toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-3 text-sm text-white font-medium">{check.name}</td>
                            <td className="px-6 py-3 text-sm text-gray-400">{check.desc}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {filtered.length === 0 && (
          <div className="text-center py-16 text-gray-500">
            <div className="text-4xl mb-3">🔍</div>
            <div>No modules match your search</div>
          </div>
        )}
      </div>
    </main>
  );
}
