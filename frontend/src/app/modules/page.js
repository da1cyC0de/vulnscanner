'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';

const MODULES = [
  {
    name: 'InjectionScanner',
    category: 'Injection',
    icon: '💉',
    checks: [
      { id: 'INJ-001', name: 'SQL Injection', severity: 'Critical', desc: 'Tests SQL injection with various payloads and monitors for SQL error responses', desc_id: 'Menguji injeksi SQL dengan berbagai payload dan memantau respons error SQL' },
      { id: 'INJ-002', name: 'XSS Reflected', severity: 'High', desc: 'Tests for reflected Cross-Site Scripting with script, event handler, and SVG payloads', desc_id: 'Menguji kerentanan XSS Reflected menggunakan payload script, event handler, dan SVG' },
      { id: 'INJ-004', name: 'HTML Injection', severity: 'Medium', desc: 'Tests for HTML injection using h1, marquee, and iframe tags', desc_id: 'Menguji injeksi HTML menggunakan tag h1, marquee, dan iframe' },
      { id: 'INJ-005', name: 'Command Injection (OS)', severity: 'Critical', desc: 'Tests OS command injection with ls, cat /etc/passwd, whoami payloads', desc_id: 'Menguji injeksi perintah OS dengan payload ls, cat /etc/passwd, whoami' },
      { id: 'INJ-007', name: 'CRLF Injection', severity: 'Medium', desc: 'Tests CRLF injection in HTTP headers for response splitting', desc_id: 'Menguji injeksi CRLF di header HTTP untuk pemisahan respons' },
      { id: 'INJ-008', name: 'Host Header Injection', severity: 'Medium', desc: 'Tests Host header manipulation for cache poisoning & redirect attacks', desc_id: 'Menguji manipulasi Host header untuk serangan cache poisoning & redirect' },
      { id: 'INJ-064', name: 'NoSQL Injection', severity: 'High', desc: 'Tests NoSQL injection with operators like $gt, $ne, $regex', desc_id: 'Menguji injeksi NoSQL dengan operator seperti $gt, $ne, $regex' },
      { id: 'INJ-006', name: 'LDAP Injection', severity: 'High', desc: 'Tests LDAP injection with wildcard and filter bypass payloads', desc_id: 'Menguji injeksi LDAP dengan payload wildcard dan bypass filter' },
      { id: 'INJ-010', name: 'XPath Injection', severity: 'High', desc: 'Tests XPath injection with payloads to bypass authentication queries', desc_id: 'Menguji injeksi XPath dengan payload untuk bypass query autentikasi' },
      { id: 'INJ-011', name: 'Expression Language Injection', severity: 'Critical', desc: 'Tests EL injection (JSP/OGNL/SpEL) to execute server-side expressions', desc_id: 'Menguji injeksi Expression Language (JSP/OGNL/SpEL) untuk eksekusi expression server-side' },
    ],
  },
  {
    name: 'AdvancedInjectionScanner',
    category: 'Advanced Injection',
    icon: '🧪',
    checks: [
      { id: 'ADV-089', name: 'Server-Side Template Injection (SSTI)', severity: 'Critical', desc: 'Tests SSTI on form inputs with payloads like {{7*7}}', desc_id: 'Menguji SSTI pada input form dengan payload seperti {{7*7}}' },
      { id: 'ADV-090', name: 'Server-Side Request Forgery (SSRF)', severity: 'High', desc: 'Tests SSRF on URL parameters to load internal resources', desc_id: 'Menguji SSRF pada parameter URL untuk mengakses resource internal' },
      { id: 'ADV-091', name: 'XML External Entity (XXE)', severity: 'Critical', desc: 'Tests XXE injection with payloads to read internal files', desc_id: 'Menguji injeksi XXE dengan payload untuk membaca file internal server' },
      { id: 'ADV-092', name: 'CRLF Injection (Response Splitting)', severity: 'High', desc: 'Tests CRLF injection for HTTP response splitting attacks', desc_id: 'Menguji injeksi CRLF untuk serangan HTTP response splitting' },
    ],
  },
  {
    name: 'AuthSessionScanner',
    category: 'Authentication & Session',
    icon: '🔐',
    checks: [
      { id: 'AUTH-012', name: 'Cookie Security Flags Missing', severity: 'Medium', desc: 'Checks for HttpOnly, Secure, and SameSite flags on cookies', desc_id: 'Memeriksa flag HttpOnly, Secure, dan SameSite pada cookie' },
      { id: 'AUTH-051', name: 'Session ID in URL', severity: 'High', desc: 'Detects session IDs exposed in URL parameters (session hijacking risk)', desc_id: 'Mendeteksi session ID yang terekspos di parameter URL (risiko pembajakan sesi)' },
      { id: 'AUTH-009', name: 'Brute Force Login Detection', severity: 'Medium', desc: 'Detects login forms without CAPTCHA or rate limiting protection', desc_id: 'Mendeteksi form login tanpa perlindungan CAPTCHA atau pembatasan percobaan' },
      { id: 'AUTH-013', name: 'Default Credentials', severity: 'Critical', desc: 'Tests login with common default credentials (admin/admin, admin/password)', desc_id: 'Menguji login dengan kredensial default umum (admin/admin, admin/password)' },
      { id: 'AUTH-012J', name: 'JWT Vulnerability Check', severity: 'High', desc: "Checks for JWT with 'none' algorithm or exposed tokens", desc_id: "Memeriksa JWT dengan algoritma 'none' atau token yang terekspos" },
      { id: 'AUTH-056', name: 'Insecure Session Storage', severity: 'Medium', desc: 'Detects tokens stored in localStorage/sessionStorage', desc_id: 'Mendeteksi token yang disimpan di localStorage/sessionStorage' },
      { id: 'AUTH-054', name: 'Session ID Entropy Check', severity: 'Medium', desc: 'Checks if session ID is too short (<16 chars) for brute-force resistance', desc_id: 'Memeriksa apakah session ID terlalu pendek (<16 karakter) untuk ketahanan brute-force' },
      { id: 'AUTH-055', name: 'Account Lockout Missing', severity: 'Medium', desc: 'Checks if login allows unlimited attempts without lockout', desc_id: 'Memeriksa apakah login mengizinkan percobaan tanpa batas tanpa penguncian akun' },
      { id: 'AUTH-057', name: 'Weak Password Policy', severity: 'Medium', desc: 'Detects login forms without minimum password length enforcement', desc_id: 'Mendeteksi form login tanpa penegakan panjang minimum password' },
      { id: 'AUTH-058', name: 'Password Autocomplete Enabled', severity: 'Low', desc: 'Detects password fields without autocomplete="off" attribute', desc_id: 'Mendeteksi field password tanpa atribut autocomplete="off"' },
    ],
  },
  {
    name: 'AdvancedAuthScanner',
    category: 'Authentication Advanced',
    icon: '🛡️',
    checks: [
      { id: 'AUTH-097', name: 'Username Enumeration', severity: 'Medium', desc: 'Detects error messages that distinguish between valid/invalid usernames', desc_id: 'Mendeteksi pesan error yang membedakan username valid/tidak valid' },
      { id: 'AUTH-098', name: 'Password Reset Poisoning', severity: 'High', desc: 'Tests Host Header poisoning on password reset pages', desc_id: 'Menguji keracunan Host Header pada halaman reset password' },
      { id: 'AUTH-099', name: 'OAuth Misconfiguration', severity: 'High', desc: 'Detects misconfigurations in OAuth (exposed secrets, insecure redirect URIs)', desc_id: 'Mendeteksi miskonfigurasi OAuth (secret terekspos, redirect URI tidak aman)' },
      { id: 'AUTH-100', name: 'JWT Token Exposure', severity: 'High', desc: 'Detects JWT tokens exposed in page source or URLs', desc_id: 'Mendeteksi token JWT yang terekspos di source halaman atau URL' },
    ],
  },
  {
    name: 'BusinessLogicScanner',
    category: 'Business Logic',
    icon: '💰',
    checks: [
      { id: 'BIZ-018', name: 'Hidden Field Manipulation', severity: 'High', desc: 'Detects sensitive hidden form fields (price, role, discount, admin flags)', desc_id: 'Mendeteksi field tersembunyi sensitif di form (harga, role, diskon, flag admin)' },
      { id: 'BIZ-017', name: 'Price/Parameter Tampering', severity: 'Critical', desc: 'Tests if price/amount parameters can be tampered in requests', desc_id: 'Menguji apakah parameter harga/jumlah bisa dimanipulasi di request' },
      { id: 'BIZ-020', name: 'Negative Value Testing', severity: 'High', desc: 'Tests if backend accepts negative values for quantities/prices', desc_id: 'Menguji apakah backend menerima nilai negatif untuk kuantitas/harga' },
      { id: 'BIZ-019', name: 'Race Condition Indicator', severity: 'Medium', desc: 'Detects POST forms that may be vulnerable to race conditions', desc_id: 'Mendeteksi form POST yang mungkin rentan terhadap race condition' },
      { id: 'BIZ-021', name: 'IDOR Reference in Links', severity: 'Medium', desc: 'Detects links with numeric ID parameters that may be vulnerable to IDOR', desc_id: 'Mendeteksi link dengan parameter ID numerik yang mungkin rentan IDOR' },
      { id: 'BIZ-022', name: 'Privilege Escalation - Unprotected Admin', severity: 'High', desc: 'Checks if admin/privileged pages are accessible without authentication', desc_id: 'Memeriksa apakah halaman admin/privileged bisa diakses tanpa autentikasi' },
    ],
  },
  {
    name: 'InfoDisclosureScanner',
    category: 'Information Disclosure',
    icon: '📋',
    checks: [
      { id: 'INFO-026', name: 'Server Version Disclosure', severity: 'Low', desc: 'Detects version leakage in Server, X-Powered-By, X-AspNet-Version headers', desc_id: 'Mendeteksi kebocoran versi di header Server, X-Powered-By, X-AspNet-Version' },
      { id: 'INFO-027', name: 'Sensitive File Exposure', severity: 'High', desc: 'Checks for exposed sensitive files (.env, .git/config, config.php, etc.)', desc_id: 'Memeriksa file sensitif yang terekspos (.env, .git/config, config.php, dll.)' },
      { id: 'INFO-028', name: 'Directory Listing Enabled', severity: 'Medium', desc: 'Tests for enabled directory listing on web server', desc_id: 'Menguji apakah directory listing aktif di web server' },
      { id: 'INFO-029', name: 'Error Message Info Leak', severity: 'Medium', desc: 'Detects PHP errors, stack traces, and database errors in responses', desc_id: 'Mendeteksi error PHP, stack trace, dan error database di respons' },
      { id: 'INFO-030', name: 'Admin Panel Finder', severity: 'Medium', desc: 'Discovers accessible admin panels (/admin, /wp-admin, /dashboard)', desc_id: 'Menemukan panel admin yang bisa diakses (/admin, /wp-admin, /dashboard)' },
      { id: 'INFO-031', name: 'Backup File Finder', severity: 'High', desc: 'Searches for exposed backup files (.zip, .sql, .tar.gz, .bak)', desc_id: 'Mencari file backup yang terekspos (.zip, .sql, .tar.gz, .bak)' },
      { id: 'INFO-032', name: 'robots.txt & Sitemap Analysis', severity: 'Info', desc: 'Analyzes robots.txt for sensitive disallowed paths', desc_id: 'Menganalisis robots.txt untuk path sensitif yang di-disallow' },
      { id: 'INFO-073', name: 'Debug Mode Detection', severity: 'High', desc: 'Detects active debug modes (Laravel, Django, Flask, Whoops)', desc_id: 'Mendeteksi mode debug yang aktif (Laravel, Django, Flask, Whoops)' },
      { id: 'INFO-178', name: 'HTML Comment Info Leakage', severity: 'Low', desc: 'Finds sensitive information leaked in HTML comments', desc_id: 'Menemukan informasi sensitif yang bocor di komentar HTML' },
      { id: 'INFO-033', name: 'Stack Trace Exposure', severity: 'Medium', desc: 'Detects stack traces exposed in web pages', desc_id: 'Mendeteksi stack trace yang terekspos di halaman web' },
      { id: 'INFO-034', name: 'Sitemap.xml Sensitive Path Disclosure', severity: 'Low', desc: 'Analyzes sitemap.xml for sensitive or internal paths like admin, api, staging', desc_id: 'Menganalisis sitemap.xml untuk path sensitif atau internal seperti admin, api, staging' },
    ],
  },
  {
    name: 'SecurityHeadersScanner',
    category: 'Security Headers',
    icon: '📡',
    checks: [
      { id: 'CSP-033', name: 'Missing Content-Security-Policy', severity: 'Medium', desc: 'Checks for missing CSP header (XSS protection)', desc_id: 'Memeriksa header CSP yang hilang (perlindungan XSS)' },
      { id: 'HDR-034', name: 'Missing X-Frame-Options', severity: 'Medium', desc: 'Checks for missing clickjacking protection header', desc_id: 'Memeriksa header perlindungan clickjacking yang hilang' },
      { id: 'HDR-035', name: 'Missing X-Content-Type-Options', severity: 'Low', desc: 'Checks for missing MIME-sniffing protection', desc_id: 'Memeriksa perlindungan MIME-sniffing yang hilang' },
      { id: 'HDR-036', name: 'Missing HSTS', severity: 'Medium', desc: 'Checks for missing Strict-Transport-Security header', desc_id: 'Memeriksa header Strict-Transport-Security yang hilang' },
      { id: 'HDR-037', name: 'Missing X-XSS-Protection', severity: 'Low', desc: 'Checks for missing browser XSS filter header', desc_id: 'Memeriksa header filter XSS browser yang hilang' },
      { id: 'HDR-038', name: 'Missing Referrer-Policy', severity: 'Low', desc: 'Checks for missing Referrer-Policy header', desc_id: 'Memeriksa header Referrer-Policy yang hilang' },
      { id: 'HDR-039', name: 'Missing Permissions-Policy', severity: 'Low', desc: 'Checks for missing feature/permissions policy header', desc_id: 'Memeriksa header permissions policy yang hilang' },
    ],
  },
  {
    name: 'SslTlsScanner',
    category: 'SSL/TLS & Network',
    icon: '🔒',
    checks: [
      { id: 'SSL-040', name: 'SSL Certificate Validation', severity: 'High', desc: 'Tests for expired, self-signed, or invalid SSL certificates', desc_id: 'Menguji sertifikat SSL yang expired, self-signed, atau tidak valid' },
      { id: 'SSL-043', name: 'HTTP to HTTPS Redirect', severity: 'Medium', desc: 'Checks if HTTP properly redirects to HTTPS', desc_id: 'Memeriksa apakah HTTP redirect ke HTTPS dengan benar' },
      { id: 'SSL-042', name: 'Mixed Content Detection', severity: 'Medium', desc: 'Detects insecure HTTP resources loaded from HTTPS pages', desc_id: 'Mendeteksi resource HTTP tidak aman yang dimuat dari halaman HTTPS' },
      { id: 'SSL-105', name: 'HSTS Preload Check', severity: 'Low', desc: 'Checks if HSTS header includes preload directive', desc_id: 'Memeriksa apakah header HSTS menyertakan direktif preload' },
      { id: 'SSL-041', name: 'Weak TLS Version', severity: 'High', desc: 'Checks if server supports outdated TLS 1.0/1.1 protocols', desc_id: 'Memeriksa apakah server mendukung protokol TLS 1.0/1.1 yang usang' },
      { id: 'SSL-044', name: 'Certificate Transparency', severity: 'Low', desc: 'Checks for Expect-CT header for certificate transparency', desc_id: 'Memeriksa header Expect-CT untuk transparansi sertifikat' },
    ],
  },
  {
    name: 'ClientSideScanner',
    category: 'Client-Side',
    icon: '🌐',
    checks: [
      { id: 'CLI-021', name: 'Open Redirect', severity: 'Medium', desc: 'Tests URL parameters for open redirect vulnerabilities', desc_id: 'Menguji parameter URL untuk kerentanan open redirect' },
      { id: 'CLI-022', name: 'Clickjacking', severity: 'Medium', desc: 'Checks for X-Frame-Options and CSP frame-ancestors protection', desc_id: 'Memeriksa perlindungan X-Frame-Options dan CSP frame-ancestors' },
      { id: 'CLI-023', name: 'CORS Misconfiguration', severity: 'High', desc: 'Tests for overly permissive CORS (wildcard, reflected origins)', desc_id: 'Menguji CORS yang terlalu permisif (wildcard, reflected origins)' },
      { id: 'CLI-024', name: 'DOM-based Vulnerability Hints', severity: 'Medium', desc: 'Detects dangerous JS sinks (innerHTML, eval) and sources (location.hash)', desc_id: 'Mendeteksi JS sink berbahaya (innerHTML, eval) dan source (location.hash)' },
      { id: 'CLI-025', name: 'JavaScript Source Map Exposure', severity: 'Low', desc: 'Checks for exposed .js.map files leaking original source code', desc_id: 'Memeriksa file .js.map yang terekspos dan membocorkan source code asli' },
      { id: 'CLI-026', name: 'Prototype Pollution Hints', severity: 'Medium', desc: 'Detects JavaScript patterns vulnerable to prototype pollution (__proto__, merge, extend)', desc_id: 'Mendeteksi pola JavaScript yang rentan prototype pollution (__proto__, merge, extend)' },
      { id: 'CLI-027', name: 'Sensitive Data in Client Storage', severity: 'Medium', desc: 'Detects tokens, passwords, or secrets stored in localStorage/sessionStorage', desc_id: 'Mendeteksi token, password, atau secret yang disimpan di localStorage/sessionStorage' },
    ],
  },
  {
    name: 'ClientSideAdvancedScanner',
    category: 'Client-Side Advanced',
    icon: '⚡',
    checks: [
      { id: 'CLIADV-123', name: 'PostMessage Vulnerability', severity: 'Medium', desc: 'Checks postMessage usage without origin validation', desc_id: 'Memeriksa penggunaan postMessage tanpa validasi origin' },
      { id: 'CLIADV-126', name: 'Reverse Tabnabbing', severity: 'Low', desc: 'Detects target="_blank" links without noopener/noreferrer', desc_id: 'Mendeteksi link target="_blank" tanpa noopener/noreferrer' },
      { id: 'COMP-106', name: 'Subresource Integrity (SRI) Missing', severity: 'Low', desc: 'Identifies external resources loaded without SRI attribute', desc_id: 'Mengidentifikasi resource eksternal yang dimuat tanpa atribut SRI' },
      { id: 'CLIADV-124', name: 'CSS Injection', severity: 'Medium', desc: 'Detects CSS injection patterns (expression, -moz-binding, JS in CSS)', desc_id: 'Mendeteksi pola CSS injection (expression, -moz-binding, JS di CSS)' },
      { id: 'CLIADV-125', name: 'Mixed Content (Active)', severity: 'Medium', desc: 'Detects active mixed content — HTTP resources on HTTPS pages', desc_id: 'Mendeteksi active mixed content — resource HTTP di halaman HTTPS' },
    ],
  },
  {
    name: 'FileUploadScanner',
    category: 'File Upload',
    icon: '📤',
    checks: [
      { id: 'FILE-044', name: 'Unrestricted File Upload', severity: 'High', desc: 'Detects file upload forms without type restrictions', desc_id: 'Mendeteksi form upload file tanpa pembatasan tipe' },
      { id: 'FILE-045', name: 'File Extension Bypass', severity: 'High', desc: 'Tests for dangerous file types accepted in upload restrictions', desc_id: 'Menguji tipe file berbahaya yang diterima dalam pembatasan upload' },
      { id: 'FILE-046', name: 'Upload Directory Listing', severity: 'High', desc: 'Checks if upload directories are browsable via directory listing', desc_id: 'Memeriksa apakah direktori upload bisa di-browse melalui directory listing' },
    ],
  },
  {
    name: 'FilePathScanner',
    category: 'File & Path Traversal',
    icon: '📂',
    checks: [
      { id: 'FILE-139', name: 'Path Traversal / LFI', severity: 'Critical', desc: 'Tests Local File Inclusion with payloads like ../../../etc/passwd', desc_id: 'Menguji Local File Inclusion dengan payload seperti ../../../etc/passwd' },
      { id: 'FILE-140', name: 'Remote File Inclusion (RFI)', severity: 'Critical', desc: 'Tests Remote File Inclusion by loading external payloads', desc_id: 'Menguji Remote File Inclusion dengan memuat payload dari luar' },
    ],
  },
  {
    name: 'ApiSecurityScanner',
    category: 'API Security',
    icon: '🔌',
    checks: [
      { id: 'API-046', name: 'API Endpoint Discovery', severity: 'Info', desc: 'Discovers accessible API endpoints (api/users, graphql, swagger)', desc_id: 'Menemukan endpoint API yang bisa diakses (api/users, graphql, swagger)' },
      { id: 'API-047', name: 'HTTP Method Tampering', severity: 'Medium', desc: 'Tests for dangerous HTTP methods allowed (PUT, DELETE, TRACE)', desc_id: 'Menguji metode HTTP berbahaya yang diizinkan (PUT, DELETE, TRACE)' },
      { id: 'API-048', name: 'Rate Limiting Check', severity: 'Medium', desc: 'Checks if rapid requests trigger rate limiting protection', desc_id: 'Memeriksa apakah request cepat memicu perlindungan rate limiting' },
      { id: 'API-134', name: 'Swagger/OpenAPI Docs Exposed', severity: 'Medium', desc: 'Checks for exposed API documentation (swagger.json, openapi.json)', desc_id: 'Memeriksa dokumentasi API yang terekspos (swagger.json, openapi.json)' },
      { id: 'API-049', name: 'API Version Info Disclosure', severity: 'Low', desc: 'Checks if API version endpoints expose information', desc_id: 'Memeriksa apakah endpoint versi API mengekspos informasi' },
    ],
  },
  {
    name: 'ApiAdvancedScanner',
    category: 'API Advanced',
    icon: '🧩',
    checks: [
      { id: 'APIAV-129', name: 'IDOR / Broken Object Auth', severity: 'High', desc: 'Checks API endpoints for unauthorized access (api/users/1, api/order/1)', desc_id: 'Memeriksa endpoint API untuk akses tidak sah (api/users/1, api/order/1)' },
      { id: 'APIAV-132', name: 'GraphQL Batch Attack', severity: 'Medium', desc: 'Tests if GraphQL accepts batch queries for brute force attacks', desc_id: 'Menguji apakah GraphQL menerima batch query untuk serangan brute force' },
      { id: 'APIAV-135', name: 'WSDL Disclosure (SOAP)', severity: 'Low', desc: 'Checks for exposed SOAP WSDL files', desc_id: 'Memeriksa file WSDL SOAP yang terekspos' },
      { id: 'APIAV-136', name: 'GraphQL Schema Introspection', severity: 'Medium', desc: 'Checks if GraphQL introspection exposes schema details', desc_id: 'Memeriksa apakah GraphQL introspection mengekspos detail schema' },
    ],
  },
  {
    name: 'CsrfScanner',
    category: 'CSRF',
    icon: '🎭',
    checks: [
      { id: 'CSRF-050', name: 'CSRF Token Missing/Weak', severity: 'High', desc: 'Checks POST forms for missing or weak CSRF token protection', desc_id: 'Memeriksa form POST yang tidak memiliki atau lemah perlindungan token CSRF' },
    ],
  },
  {
    name: 'DatabaseScanner',
    category: 'Database Exposure',
    icon: '🗄️',
    checks: [
      { id: 'DB-057', name: 'Database Dump Exposure', severity: 'Critical', desc: 'Checks for exposed database dump files (.sql, .db, .sqlite)', desc_id: 'Memeriksa file dump database yang terekspos (.sql, .db, .sqlite)' },
      { id: 'DB-058', name: 'phpMyAdmin/Adminer Exposed', severity: 'High', desc: 'Detects exposed database administration panels', desc_id: 'Mendeteksi panel administrasi database yang terekspos' },
      { id: 'DB-062', name: 'DB Connection String Leakage', severity: 'Critical', desc: 'Finds database connection strings leaked in source code', desc_id: 'Menemukan string koneksi database yang bocor di source code' },
      { id: 'DB-063', name: 'DB Error Message Leakage', severity: 'Medium', desc: 'Detects database error messages that leak internal info', desc_id: 'Mendeteksi pesan error database yang membocorkan info internal' },
      { id: 'DB-059', name: 'Redis Exposed', severity: 'Critical', desc: 'Checks if Redis is exposed and responds to PING (port 6379)', desc_id: 'Memeriksa apakah Redis terekspos dan merespons PING (port 6379)' },
      { id: 'DB-060', name: 'MongoDB Exposed', severity: 'Critical', desc: 'Checks if MongoDB is exposed without authentication (port 27017)', desc_id: 'Memeriksa apakah MongoDB terekspos tanpa autentikasi (port 27017)' },
      { id: 'DB-061', name: 'Elasticsearch Exposed', severity: 'High', desc: 'Checks if Elasticsearch is publicly accessible (port 9200)', desc_id: 'Memeriksa apakah Elasticsearch bisa diakses publik (port 9200)' },
    ],
  },
  {
    name: 'ServerInfraScanner',
    category: 'Server & Infrastructure',
    icon: '🖥️',
    checks: [
      { id: 'SRV-071', name: 'Server Status Page Exposed', severity: 'Medium', desc: 'Detects exposed server-status, nginx_status pages', desc_id: 'Mendeteksi halaman server-status, nginx_status yang terekspos' },
      { id: 'SRV-072', name: 'PHP Info Page Exposure', severity: 'High', desc: 'Checks for publicly accessible phpinfo() pages', desc_id: 'Memeriksa halaman phpinfo() yang bisa diakses publik' },
      { id: 'SRV-074', name: 'GraphQL Introspection Enabled', severity: 'Medium', desc: 'Tests if GraphQL introspection queries are allowed', desc_id: 'Menguji apakah query introspeksi GraphQL diizinkan' },
      { id: 'SRV-075', name: 'CORS Origin Reflection + Credentials', severity: 'High', desc: 'Checks if server reflects attacker origin with credentials allowed', desc_id: 'Memeriksa apakah server me-reflect origin attacker dengan credentials diizinkan' },
      { id: 'SRV-076', name: 'Default Web Server Page', severity: 'Low', desc: 'Detects default Apache, Nginx, IIS, or Tomcat pages', desc_id: 'Mendeteksi halaman default Apache, Nginx, IIS, atau Tomcat' },
    ],
  },
  {
    name: 'SourceCodeScanner',
    category: 'Source Code & Secrets',
    icon: '🔑',
    checks: [
      { id: 'SRC-075', name: 'Git Repository Exposure', severity: 'Critical', desc: 'Detects exposed .git directory with source code access', desc_id: 'Mendeteksi direktori .git yang terekspos dengan akses source code' },
      { id: 'SRC-076', name: 'SVN Repository Exposure', severity: 'High', desc: 'Detects exposed .svn directory', desc_id: 'Mendeteksi direktori .svn yang terekspos' },
      { id: 'SRC-082', name: '.env File Exposure', severity: 'Critical', desc: 'Checks for publicly accessible .env configuration files', desc_id: 'Memeriksa file konfigurasi .env yang bisa diakses publik' },
      { id: 'SRC-078', name: 'API Key Leakage in JavaScript', severity: 'High', desc: 'Finds API keys, AWS keys, GitHub tokens in source code', desc_id: 'Menemukan API key, AWS key, GitHub token di source code' },
      { id: 'SRC-079', name: 'Hardcoded Credentials', severity: 'High', desc: 'Detects hardcoded passwords and credentials in source', desc_id: 'Mendeteksi password dan kredensial yang di-hardcode di source' },
      { id: 'SRC-081', name: 'Private Key File Exposure', severity: 'Critical', desc: 'Checks for exposed private key files (.pem, .key)', desc_id: 'Memeriksa file private key yang terekspos (.pem, .key)' },
      { id: 'SRC-162', name: 'Package/Dependency File Exposure', severity: 'Low', desc: 'Detects exposed package.json, composer.json, requirements.txt', desc_id: 'Mendeteksi file package.json, composer.json, requirements.txt yang terekspos' },
      { id: 'SRC-077', name: 'Docker Config Exposed', severity: 'High', desc: 'Checks for exposed Dockerfile or docker-compose.yml files', desc_id: 'Memeriksa file Dockerfile atau docker-compose.yml yang terekspos' },
      { id: 'SRC-080', name: 'CI/CD Config Exposed', severity: 'High', desc: 'Detects exposed CI/CD configs (.github/workflows, .gitlab-ci.yml, Jenkinsfile)', desc_id: 'Mendeteksi konfigurasi CI/CD yang terekspos (.github/workflows, .gitlab-ci.yml, Jenkinsfile)' },
      { id: 'SRC-083', name: 'AWS Credentials Exposed', severity: 'Critical', desc: 'Scans for leaked AWS access keys (AKIA pattern) in source code', desc_id: 'Memindai AWS access key yang bocor (pola AKIA) di source code' },
    ],
  },
  {
    name: 'CmsScanner',
    category: 'CMS Specific',
    icon: '📝',
    checks: [
      { id: 'CMS-084', name: 'WordPress Version Detection', severity: 'Info', desc: 'Detects and extracts WordPress version', desc_id: 'Mendeteksi dan mengekstrak versi WordPress' },
      { id: 'CMS-086', name: 'WordPress User Enumeration', severity: 'Medium', desc: 'Tests user enumeration via ?author= parameter', desc_id: 'Menguji enumerasi user via parameter ?author=' },
      { id: 'CMS-087', name: 'WordPress XML-RPC Enabled', severity: 'Medium', desc: 'Checks if XML-RPC is active (brute force/DDoS risk)', desc_id: 'Memeriksa apakah XML-RPC aktif (risiko brute force/DDoS)' },
      { id: 'CMS-155', name: 'Joomla Detection', severity: 'Info', desc: 'Detects Joomla CMS and extracts version info', desc_id: 'Mendeteksi CMS Joomla dan mengekstrak info versi' },
      { id: 'CMS-156', name: 'Drupal Detection', severity: 'Info', desc: 'Detects Drupal CMS and extracts version info', desc_id: 'Mendeteksi CMS Drupal dan mengekstrak info versi' },
      { id: 'CMS-158', name: 'Laravel Telescope/Debug Exposed', severity: 'High', desc: 'Checks for exposed Laravel Telescope debug interface', desc_id: 'Memeriksa antarmuka debug Laravel Telescope yang terekspos' },
      { id: 'CMS-159', name: 'Django Admin Exposed', severity: 'Medium', desc: 'Tests if Django admin panel is publicly accessible', desc_id: 'Menguji apakah panel admin Django bisa diakses publik' },
      { id: 'CMS-160', name: 'Spring Boot Actuator Exposed', severity: 'High', desc: 'Checks for exposed Spring Boot Actuator endpoints', desc_id: 'Memeriksa endpoint Spring Boot Actuator yang terekspos' },
      { id: 'CMS-163', name: 'Next.js Debug/Internal Paths', severity: 'Low', desc: 'Detects exposed Next.js internal paths (_next/data, _next/static)', desc_id: 'Mendeteksi path internal Next.js yang terekspos (_next/data, _next/static)' },
      { id: 'CMS-164', name: 'Strapi CMS Exposed', severity: 'Medium', desc: 'Detects Strapi CMS and exposed admin endpoints', desc_id: 'Mendeteksi CMS Strapi dan endpoint admin yang terekspos' },
    ],
  },
  {
    name: 'CacheProxyScanner',
    category: 'Cache & Proxy',
    icon: '🗃️',
    checks: [
      { id: 'CACHE-111', name: 'Web Cache Poisoning', severity: 'High', desc: 'Tests cache poisoning via X-Forwarded-Host header manipulation', desc_id: 'Menguji keracunan cache via manipulasi header X-Forwarded-Host' },
      { id: 'CACHE-112', name: 'Web Cache Deception', severity: 'High', desc: 'Tests serving HTML content for static file extensions', desc_id: 'Menguji penyajian konten HTML untuk ekstensi file statis' },
      { id: 'CACHE-113', name: 'Reverse Proxy Bypass', severity: 'High', desc: 'Tests access control bypass via X-Original-URL / X-Rewrite-URL headers', desc_id: 'Menguji bypass access control via header X-Original-URL / X-Rewrite-URL' },
    ],
  },
  {
    name: 'EmailScanner',
    category: 'Email Vulnerabilities',
    icon: '📧',
    checks: [
      { id: 'EMAIL-114', name: 'Email Header Injection', severity: 'Medium', desc: 'Detects email/contact forms vulnerable to header injection', desc_id: 'Mendeteksi form email/kontak yang rentan terhadap injeksi header' },
      { id: 'EMAIL-115', name: 'Email Address Disclosure', severity: 'Low', desc: 'Detects email addresses exposed in web pages (spam/phishing risk)', desc_id: 'Mendeteksi alamat email yang terekspos di halaman web (risiko spam/phishing)' },
    ],
  },
  {
    name: 'WebSocketScanner',
    category: 'WebSocket',
    icon: '🔗',
    checks: [
      { id: 'WS-117', name: 'WebSocket Security Check', severity: 'Medium', desc: 'Detects WebSocket usage and checks for insecure ws:// connections', desc_id: 'Mendeteksi penggunaan WebSocket dan memeriksa koneksi ws:// yang tidak aman' },
      { id: 'WS-118', name: 'WebSocket Origin Validation Missing', severity: 'Medium', desc: 'Detects WebSocket without origin validation (CSWSH risk)', desc_id: 'Mendeteksi WebSocket tanpa validasi origin (risiko CSWSH)' },
    ],
  },
  {
    name: 'ProtocolScanner',
    category: 'HTTP Protocol',
    icon: '📡',
    checks: [
      { id: 'PROTO-121', name: 'HTTP Method Override', severity: 'Medium', desc: 'Tests HTTP method override headers (X-HTTP-Method-Override)', desc_id: 'Menguji header override metode HTTP (X-HTTP-Method-Override)' },
      { id: 'PROTO-120', name: 'HTTP Request Smuggling', severity: 'High', desc: 'Tests for HTTP Request Smuggling via TE/CL conflict', desc_id: 'Menguji HTTP Request Smuggling melalui konflik Transfer-Encoding/Content-Length' },
      { id: 'PROTO-122', name: 'TRACE Method Enabled (XST)', severity: 'Medium', desc: 'Checks if TRACE HTTP method is enabled (Cross-Site Tracing risk)', desc_id: 'Memeriksa apakah metode HTTP TRACE aktif (risiko Cross-Site Tracing)' },
    ],
  },
  {
    name: 'CryptoScanner',
    category: 'Cryptographic',
    icon: '🔏',
    checks: [
      { id: 'CRYPT-144', name: 'Weak Hashing Detection', severity: 'Low', desc: 'Detects weak hashes (MD5, SHA1) in response content', desc_id: 'Mendeteksi hash lemah (MD5, SHA1) di konten respons' },
      { id: 'CRYPT-145', name: 'Insecure Random Number Generator', severity: 'Medium', desc: 'Detects insecure random functions (Math.random, rand, mt_rand)', desc_id: 'Mendeteksi fungsi random tidak aman (Math.random, rand, mt_rand)' },
      { id: 'CRYPT-146', name: 'Base64 Encoded Secrets', severity: 'High', desc: 'Detects Base64-encoded secrets (passwords, API keys) in source code', desc_id: 'Mendeteksi secret yang di-encode Base64 (password, API key) di source code' },
    ],
  },
  {
    name: 'CloudScanner',
    category: 'Cloud & Container',
    icon: '☁️',
    checks: [
      { id: 'CLOUD-151', name: 'Cloud Metadata SSRF Risk', severity: 'High', desc: 'Detects references to cloud metadata endpoints (169.254.169.254)', desc_id: 'Mendeteksi referensi ke endpoint metadata cloud (169.254.169.254)' },
      { id: 'CLOUD-153', name: 'Firebase DB Misconfiguration', severity: 'Critical', desc: 'Tests for publicly accessible Firebase Realtime Database', desc_id: 'Menguji Firebase Realtime Database yang bisa diakses publik' },
      { id: 'CLOUD-149', name: 'K8s/Docker Dashboard Exposed', severity: 'Critical', desc: 'Checks for exposed Kubernetes/Docker dashboards', desc_id: 'Memeriksa dashboard Kubernetes/Docker yang terekspos' },
      { id: 'CLOUD-150', name: 'S3 Bucket Misconfiguration', severity: 'High', desc: 'Detects references to S3 buckets and checks for public access', desc_id: 'Mendeteksi referensi ke S3 bucket dan memeriksa akses publik' },
      { id: 'CLOUD-152', name: 'Azure Blob Storage Exposed', severity: 'High', desc: 'Detects references to Azure Blob Storage with public access', desc_id: 'Mendeteksi referensi ke Azure Blob Storage dengan akses publik' },
      { id: 'CLOUD-154', name: 'GCP Storage Bucket Exposed', severity: 'High', desc: 'Detects references to GCP Storage buckets with public access', desc_id: 'Mendeteksi referensi ke GCP Storage bucket dengan akses publik' },
    ],
  },
  {
    name: 'SupplyChainScanner',
    category: 'Supply Chain',
    icon: '📦',
    checks: [
      { id: 'SUPPLY-161', name: 'JS Library Vulnerability', severity: 'Medium', desc: 'Detects outdated/vulnerable JS libraries (jQuery, Angular, Bootstrap)', desc_id: 'Mendeteksi library JS yang usang/rentan (jQuery, Angular, Bootstrap)' },
      { id: 'SUPPLY-162', name: 'Outdated Frontend Framework', severity: 'Medium', desc: 'Detects outdated frontend frameworks (React, Vue, Axios, Handlebars)', desc_id: 'Mendeteksi framework frontend yang usang (React, Vue, Axios, Handlebars)' },
    ],
  },
  {
    name: 'EncodingBypassScanner',
    category: 'Encoding & Bypass',
    icon: '🔀',
    checks: [
      { id: 'ENC-165', name: 'WAF Detection & Fingerprinting', severity: 'Info', desc: 'Identifies WAF (Cloudflare, AWS WAF, Akamai, ModSecurity)', desc_id: 'Mengidentifikasi WAF (Cloudflare, AWS WAF, Akamai, ModSecurity)' },
      { id: 'ENC-169', name: 'HTTP Parameter Pollution (HPP)', severity: 'Low', desc: "Tests server's handling of duplicate parameters", desc_id: 'Menguji penanganan server terhadap parameter duplikat' },
      { id: 'ENC-166', name: 'Double Encoding Bypass', severity: 'Medium', desc: 'Tests if server is vulnerable to double encoding path traversal', desc_id: 'Menguji apakah server rentan terhadap double encoding path traversal' },
      { id: 'ENC-167', name: 'Null Byte Injection', severity: 'Medium', desc: 'Tests if server is vulnerable to null byte injection in URLs', desc_id: 'Menguji apakah server rentan terhadap null byte injection di URL' },
    ],
  },
  {
    name: 'LoggingScanner',
    category: 'Logging & Monitoring',
    icon: '📊',
    checks: [
      { id: 'LOG-170', name: 'Log File Exposure', severity: 'High', desc: 'Detects exposed log files (error.log, laravel.log, access.log)', desc_id: 'Mendeteksi file log yang terekspos (error.log, laravel.log, access.log)' },
      { id: 'LOG-171', name: 'Missing security.txt', severity: 'Info', desc: 'Checks if security.txt is available per RFC 9116 standard', desc_id: 'Memeriksa apakah security.txt tersedia sesuai standar RFC 9116' },
    ],
  },
  {
    name: 'MiscScanner',
    category: 'Miscellaneous',
    icon: '🔧',
    checks: [
      { id: 'MISC-175', name: 'Crossdomain.xml Misconfiguration', severity: 'Medium', desc: 'Checks overly permissive crossdomain.xml allowing Flash/Silverlight access', desc_id: 'Memeriksa crossdomain.xml yang terlalu permisif memungkinkan akses Flash/Silverlight' },
      { id: 'MISC-176', name: 'Sitemap Sensitive URL Leakage', severity: 'Low', desc: 'Analyzes sitemap.xml for sensitive or internal paths', desc_id: 'Menganalisis sitemap.xml untuk path sensitif atau internal' },
      { id: 'MISC-174', name: 'JSONP Callback Injection', severity: 'Medium', desc: 'Detects JSONP callback parameters exploitable for data theft', desc_id: 'Mendeteksi parameter callback JSONP yang bisa dieksploitasi untuk pencurian data' },
      { id: 'MISC-108', name: 'Cache Control Headers Check', severity: 'Low', desc: 'Checks Cache-Control headers for sensitive data caching', desc_id: 'Memeriksa header Cache-Control untuk caching data sensitif' },
      { id: 'MISC-179', name: 'Internal IP Address Disclosure', severity: 'Low', desc: 'Detects internal IP addresses leaked in web pages (10.x, 172.16.x, 192.168.x)', desc_id: 'Mendeteksi alamat IP internal yang bocor di halaman web (10.x, 172.16.x, 192.168.x)' },
      { id: 'MISC-180', name: 'ClientAccessPolicy.xml Misconfiguration', severity: 'Medium', desc: 'Checks for overly permissive clientaccesspolicy.xml', desc_id: 'Memeriksa clientaccesspolicy.xml yang terlalu permisif' },
      { id: 'MISC-181', name: 'Insecure Form Action', severity: 'Medium', desc: 'Detects forms that submit data to insecure HTTP endpoints from HTTPS pages', desc_id: 'Mendeteksi form yang submit data ke endpoint HTTP (bukan HTTPS)' },
    ],
  },
];

const UI_TEXT = {
  en: {
    title: 'Scanner Modules',
    subtitle_modules: 'modules with',
    subtitle_checks: 'vulnerability checks',
    searchPlaceholder: 'Search modules, vulnerability ID, or description...',
    allSeverity: 'All Severity',
    showing: 'Showing',
    checksAcross: 'checks across',
    modules: 'modules',
    clearFilters: 'Clear filters',
    noMatch: 'No modules match your search',
    check: 'check',
    checks_label: 'checks',
    thId: 'ID',
    thSeverity: 'Severity',
    thVuln: 'Vulnerability',
    thDesc: 'Description',
  },
  id: {
    title: 'Modul Scanner',
    subtitle_modules: 'modul dengan',
    subtitle_checks: 'pemeriksaan kerentanan',
    searchPlaceholder: 'Cari modul, ID kerentanan, atau deskripsi...',
    allSeverity: 'Semua Severity',
    showing: 'Menampilkan',
    checksAcross: 'pemeriksaan dari',
    modules: 'modul',
    clearFilters: 'Hapus filter',
    noMatch: 'Tidak ada modul yang cocok',
    check: 'cek',
    checks_label: 'cek',
    thId: 'ID',
    thSeverity: 'Severity',
    thVuln: 'Kerentanan',
    thDesc: 'Deskripsi',
  },
};

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
  const [lang, setLang] = useState('en');
  const t = UI_TEXT[lang];

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
        const matchSearch = !q || c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q) || (c.desc_id && c.desc_id.toLowerCase().includes(q)) || m.category.toLowerCase().includes(q);
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
              <p className="text-xs text-gray-400">{t.title}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setLang(lang === 'en' ? 'id' : 'en')}
              className="px-3 py-1.5 text-sm rounded-lg border border-gray-700 bg-gray-800 hover:bg-gray-700 text-white transition-colors flex items-center gap-1.5"
              title={lang === 'en' ? 'Ganti ke Bahasa Indonesia' : 'Switch to English'}>
              {lang === 'en' ? '🇮🇩 ID' : '🇬🇧 EN'}
            </button>
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
          <h2 className="text-4xl font-bold text-white mb-3">{t.title}</h2>
          <p className="text-gray-400 text-lg">
            <span className="text-blue-400 font-semibold">{MODULES.length}</span> {t.subtitle_modules}{' '}
            <span className="text-blue-400 font-semibold">{totalChecks}</span> {t.subtitle_checks}
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
              placeholder={t.searchPlaceholder}
              className="w-full pl-10 pr-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-all" />
          </div>
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl text-white focus:outline-none focus:border-blue-500">
            <option value="All">{t.allSeverity}</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Info">Info</option>
          </select>
        </div>

        {/* Results count */}
        <div className="text-sm text-gray-500 mb-4">
          {t.showing} {filteredTotal} {t.checksAcross} {filtered.length} {t.modules}
          {(search || filterSeverity !== 'All') && (
            <button onClick={() => { setSearch(''); setFilterSeverity('All'); }} className="ml-2 text-blue-400 hover:text-blue-300">
              {t.clearFilters}
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
                        {mod.checks.length} {mod.checks.length !== 1 ? t.checks_label : t.check}
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
                          <th className="px-6 py-3 text-left w-28">{t.thId}</th>
                          <th className="px-6 py-3 text-left w-20">{t.thSeverity}</th>
                          <th className="px-6 py-3 text-left">{t.thVuln}</th>
                          <th className="px-6 py-3 text-left">{t.thDesc}</th>
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
                            <td className="px-6 py-3 text-sm text-gray-400">{lang === 'id' ? check.desc_id : check.desc}</td>
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
            <div>{t.noMatch}</div>
          </div>
        )}
      </div>
    </main>
  );
}
