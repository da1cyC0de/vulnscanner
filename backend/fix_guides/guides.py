FIX_GUIDES = {
    "INJ-001": {
        "title": "SQL Injection Fix",
        "description": "SQL Injection terjadi ketika input user langsung dimasukkan ke query SQL tanpa sanitasi.",
        "risk": "Attacker bisa mengakses, memodifikasi, atau menghapus seluruh database. Bisa juga bypass authentication.",
        "fix_steps": [
            "Gunakan Prepared Statements / Parameterized Queries",
            "Gunakan ORM (Object Relational Mapping)",
            "Validasi dan sanitize semua input user",
            "Implementasi WAF sebagai layer perlindungan tambahan",
            "Terapkan prinsip least privilege pada database user"
        ],
        "code_before": """# VULNERABLE - Python
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
cursor.execute(query)

# VULNERABLE - PHP
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);

# VULNERABLE - Node.js
const query = `SELECT * FROM users WHERE username='${username}'`;
db.query(query);""",
        "code_after": """# FIXED - Python (Parameterized Query)
query = "SELECT * FROM users WHERE username=%s AND password=%s"
cursor.execute(query, (username, password))

# FIXED - PHP (Prepared Statement)
$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

# FIXED - Node.js (Parameterized)
const query = "SELECT * FROM users WHERE username = $1";
db.query(query, [username]);""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "CWE-89: SQL Injection"
        ]
    },
    "INJ-002": {
        "title": "XSS (Cross-Site Scripting) Fix",
        "description": "XSS terjadi ketika input user ditampilkan kembali di halaman web tanpa encoding yang benar.",
        "risk": "Attacker bisa mencuri cookie, session token, melakukan phishing, atau memanipulasi tampilan website.",
        "fix_steps": [
            "Encode semua output yang berasal dari user input",
            "Gunakan Content-Security-Policy header",
            "Validasi dan sanitize input di server-side",
            "Gunakan library sanitasi HTML (DOMPurify, Bleach)",
            "Set flag HttpOnly pada cookies"
        ],
        "code_before": """# VULNERABLE - Python/Flask
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"

# VULNERABLE - PHP
echo "<h1>Results for: " . $_GET['q'] . "</h1>";

# VULNERABLE - JavaScript
document.getElementById('output').innerHTML = userInput;""",
        "code_after": """# FIXED - Python/Flask (auto-escape with Jinja2)
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template('search.html', query=query)
# template: <h1>Results for: {{ query }}</h1>

# FIXED - PHP
echo "<h1>Results for: " . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . "</h1>";

# FIXED - JavaScript
document.getElementById('output').textContent = userInput;""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "CWE-79: Cross-site Scripting"
        ]
    },
    "INJ-004": {
        "title": "HTML Injection Fix",
        "description": "HTML Injection terjadi ketika attacker bisa menyisipkan tag HTML ke halaman web.",
        "risk": "Bisa digunakan untuk phishing, defacement, atau sebagai stepping stone untuk XSS.",
        "fix_steps": [
            "Encode semua HTML entities dari user input",
            "Gunakan Content-Security-Policy",
            "Validasi input di server-side"
        ],
        "code_before": "echo $_GET['name'];",
        "code_after": "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');",
        "references": ["CWE-79: Improper Neutralization of Input During Web Page Generation"]
    },
    "INJ-005": {
        "title": "Command Injection Fix",
        "description": "Command Injection terjadi ketika input user dieksekusi sebagai system command.",
        "risk": "Attacker mendapat akses penuh ke server (Remote Code Execution).",
        "fix_steps": [
            "JANGAN pernah memasukkan user input ke system commands",
            "Gunakan API/library bawaan bahasa pemrograman sebagai pengganti system calls",
            "Jika harus menggunakan command, gunakan allowlist validation",
            "Escape special characters"
        ],
        "code_before": """# VULNERABLE - Python
os.system("ping " + user_input)

# VULNERABLE - PHP
system("ping " . $_GET['host']);""",
        "code_after": """# FIXED - Python (use library instead)
import subprocess
result = subprocess.run(["ping", "-c", "4", host],
                       capture_output=True, text=True,
                       shell=False)  # shell=False is critical!

# FIXED - PHP
$host = escapeshellarg($_GET['host']);
system("ping " . $host);  // Or better: use PHP socket functions""",
        "references": ["CWE-78: OS Command Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"]
    },
    "INJ-006": {
        "title": "LDAP Injection Fix",
        "description": "LDAP Injection terjadi ketika input user dimasukkan langsung ke LDAP query.",
        "risk": "Attacker bisa bypass authentication atau mengakses data LDAP tanpa izin.",
        "fix_steps": ["Escape special LDAP characters", "Validasi input dengan allowlist", "Gunakan LDAP framework yang aman"],
        "code_before": "filter = '(uid=' + username + ')'",
        "code_after": "from ldap3.utils.conv import escape_filter_chars\nfilter = '(uid=' + escape_filter_chars(username) + ')'",
        "references": ["CWE-90: LDAP Injection"]
    },
    "INJ-007": {
        "title": "CRLF Injection Fix",
        "description": "CRLF Injection terjadi ketika attacker bisa menyisipkan line break (\\r\\n) ke HTTP headers.",
        "risk": "Bisa digunakan untuk HTTP response splitting, session fixation, atau XSS.",
        "fix_steps": ["Strip/encode karakter \\r dan \\n dari semua input yang masuk ke HTTP headers", "Gunakan framework yang otomatis handle header encoding"],
        "code_before": "response.headers['Location'] = user_input",
        "code_after": "safe_input = user_input.replace('\\r', '').replace('\\n', '')\nresponse.headers['Location'] = safe_input",
        "references": ["CWE-113: Improper Neutralization of CRLF Sequences"]
    },
    "INJ-008": {
        "title": "Host Header Injection Fix",
        "description": "Host Header Injection terjadi ketika server mempercayai Host header dari client.",
        "risk": "Bisa digunakan untuk password reset poisoning, cache poisoning, atau SSRF.",
        "fix_steps": ["Jangan gunakan Host header untuk generate URL/link", "Konfigurasi allowlist untuk hostname yang diperbolehkan", "Gunakan konfigurasi server-side untuk hostname"],
        "code_before": "link = 'http://' + request.headers['Host'] + '/reset?token=' + token",
        "code_after": "ALLOWED_HOSTS = ['mysite.com', 'www.mysite.com']\nhost = request.headers.get('Host', '')\nif host not in ALLOWED_HOSTS:\n    abort(400)\nlink = 'https://mysite.com/reset?token=' + token",
        "references": ["CWE-644: Improper Neutralization of HTTP Headers"]
    },
    "INJ-064": {
        "title": "NoSQL Injection Fix",
        "description": "NoSQL Injection terjadi saat input user langsung dimasukkan ke NoSQL query (MongoDB, dll).",
        "risk": "Bypass authentication, data leak, unauthorized data access.",
        "fix_steps": ["Validasi tipe data input (pastikan string, bukan object)", "Gunakan MongoDB driver dengan parameterized queries", "Sanitize input dari operator NoSQL ($gt, $ne, dll)"],
        "code_before": "db.users.find({username: req.body.username, password: req.body.password})",
        "code_after": "const username = String(req.body.username);\nconst password = String(req.body.password);\ndb.users.find({username: username, password: password})",
        "references": ["CWE-943: NoSQL Injection"]
    },
    "AUTH-009": {
        "title": "Brute Force Protection Fix",
        "description": "Form login tanpa proteksi brute force memungkinkan attacker mencoba password tanpa batas.",
        "risk": "Attacker bisa menebak password dengan automated tools.",
        "fix_steps": ["Implementasi rate limiting", "Tambahkan CAPTCHA setelah beberapa kali gagal", "Implementasi account lockout", "Gunakan progressive delay"],
        "code_before": """@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        return redirect('/dashboard')
    return 'Login failed'""",
        "code_after": """from flask_limiter import Limiter
limiter = Limiter(app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        return redirect('/dashboard')
    # Log failed attempt
    log_failed_login(request.form['username'], request.remote_addr)
    return 'Login failed', 401""",
        "references": ["CWE-307: Improper Restriction of Excessive Authentication Attempts"]
    },
    "AUTH-012": {
        "title": "Cookie Security Flags Fix",
        "description": "Cookies tanpa flag keamanan rentan terhadap pencurian dan manipulasi.",
        "risk": "Session hijacking via XSS (tanpa HttpOnly), man-in-the-middle (tanpa Secure).",
        "fix_steps": ["Set flag HttpOnly pada semua session cookies", "Set flag Secure untuk cookies di HTTPS", "Set SameSite=Lax atau Strict"],
        "code_before": "Set-Cookie: session=abc123",
        "code_after": "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/",
        "references": ["CWE-614: Sensitive Cookie Without Secure Flag"]
    },
    "AUTH-013": {
        "title": "Default Credentials Fix",
        "description": "Aplikasi bisa diakses dengan username/password default.",
        "risk": "Siapa saja bisa login ke admin panel tanpa effort.",
        "fix_steps": ["Ganti semua default credentials saat instalasi", "Force password change pada first login", "Implementasi strong password policy"],
        "code_before": "DEFAULT_USER = 'admin'\nDEFAULT_PASS = 'admin'",
        "code_after": "# Force user to set password during setup\n# Gunakan environment variable untuk credentials\nimport os\nADMIN_PASS = os.environ.get('ADMIN_PASSWORD')\nif not ADMIN_PASS:\n    raise ValueError('ADMIN_PASSWORD env var must be set')",
        "references": ["CWE-798: Use of Hard-coded Credentials"]
    },
    "BIZ-017": {
        "title": "Parameter Tampering / Price Manipulation Fix",
        "description": "Backend menerima nilai harga/nominal dari client tanpa validasi server-side.",
        "risk": "User bisa mengubah harga produk, total belanja, atau nominal pembayaran.",
        "fix_steps": [
            "JANGAN kirim harga dari client-side (hidden field/JS)",
            "Ambil harga dari database di server-side",
            "Validasi semua nilai yang datang dari client",
            "Implementasi hashing/signing untuk data yang harus dikirim via client"
        ],
        "code_before": """<!-- VULNERABLE - Harga di hidden field -->
<form action="/checkout" method="POST">
  <input type="hidden" name="price" value="100000">
  <input type="hidden" name="product_id" value="1">
  <button type="submit">Buy</button>
</form>

# Backend - Langsung pakai harga dari form
price = request.form['price']
create_order(product_id, price)""",
        "code_after": """<!-- FIXED - Hanya kirim product_id -->
<form action="/checkout" method="POST">
  <input type="hidden" name="product_id" value="1">
  <button type="submit">Buy</button>
</form>

# Backend - Ambil harga dari database
product = Product.query.get(request.form['product_id'])
price = product.price  # Dari database, BUKAN dari form!
create_order(product.id, price)""",
        "references": ["CWE-472: External Control of Assumed-Immutable Web Parameter"]
    },
    "BIZ-018": {
        "title": "Hidden Field Manipulation Fix",
        "description": "Hidden fields berisi data sensitif (harga, role, discount) yang bisa diubah user.",
        "risk": "User bisa memanipulasi data sensitif sebelum form disubmit.",
        "fix_steps": ["Jangan simpan data sensitif di hidden fields", "Validasi semua data di server-side", "Gunakan server-side session untuk data sensitif"],
        "code_before": '<input type="hidden" name="role" value="user">\n<input type="hidden" name="discount" value="0">',
        "code_after": "# Server-side - ambil dari session/database\nrole = current_user.role  # Dari session\ndiscount = calculate_discount(current_user)  # Dari server logic",
        "references": ["CWE-472: External Control of Assumed-Immutable Web Parameter"]
    },
    "BIZ-020": {
        "title": "Negative Value Fix",
        "description": "Backend menerima nilai negatif untuk quantity/price.",
        "risk": "User bisa mendapat credit/refund dengan mengirim quantity negatif.",
        "fix_steps": ["Validasi semua numeric input di server-side", "Tolak nilai negatif dan nol", "Gunakan unsigned integer untuk quantity/price"],
        "code_before": "quantity = int(request.form['qty'])\ntotal = price * quantity",
        "code_after": "quantity = int(request.form['qty'])\nif quantity <= 0:\n    return 'Invalid quantity', 400\ntotal = price * quantity",
        "references": ["CWE-20: Improper Input Validation"]
    },
    "CLI-021": {
        "title": "Open Redirect Fix",
        "description": "Aplikasi meredirect user ke URL yang dikontrol attacker.",
        "risk": "Phishing - user dikira masih di site asli tapi sudah di site palsu.",
        "fix_steps": ["Validasi URL redirect dengan allowlist", "Jangan gunakan URL penuh dari user input", "Gunakan relative path saja"],
        "code_before": "redirect_url = request.args.get('next')\nreturn redirect(redirect_url)",
        "code_after": "from urllib.parse import urlparse\nredirect_url = request.args.get('next', '/')\nparsed = urlparse(redirect_url)\nif parsed.netloc and parsed.netloc != 'mysite.com':\n    redirect_url = '/'\nreturn redirect(redirect_url)",
        "references": ["CWE-601: URL Redirection to Untrusted Site"]
    },
    "CLI-022": {
        "title": "Clickjacking Fix",
        "description": "Halaman bisa di-embed dalam iframe oleh situs lain.",
        "risk": "User bisa dikecoh untuk mengklik sesuatu yang sebenarnya adalah halaman target yang di-embed.",
        "fix_steps": ["Tambahkan X-Frame-Options header", "Tambahkan CSP frame-ancestors directive"],
        "code_before": "# No frame protection",
        "code_after": "# Nginx\nadd_header X-Frame-Options \"DENY\";\nadd_header Content-Security-Policy \"frame-ancestors 'none'\";",
        "references": ["CWE-1021: Clickjacking"]
    },
    "CLI-023": {
        "title": "CORS Misconfiguration Fix",
        "description": "CORS dikonfigurasi terlalu permissive (wildcard atau reflect origin).",
        "risk": "Situs lain bisa membaca data sensitif via JavaScript.",
        "fix_steps": ["Jangan gunakan Access-Control-Allow-Origin: *", "Gunakan allowlist origin yang spesifik", "Jangan set Access-Control-Allow-Credentials: true bersama wildcard origin"],
        "code_before": "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
        "code_after": "ALLOWED_ORIGINS = ['https://myapp.com', 'https://admin.myapp.com']\norigin = request.headers.get('Origin')\nif origin in ALLOWED_ORIGINS:\n    response.headers['Access-Control-Allow-Origin'] = origin",
        "references": ["CWE-942: CORS Misconfiguration"]
    },
    "CSRF-050": {
        "title": "CSRF Protection Fix",
        "description": "Form POST tidak memiliki CSRF token.",
        "risk": "Attacker bisa membuat user melakukan aksi tanpa sepengetahuan mereka (transfer uang, ganti password, dll).",
        "fix_steps": ["Tambahkan CSRF token di setiap form POST", "Validasi CSRF token di server-side", "Set SameSite cookie attribute"],
        "code_before": '<form method="POST" action="/transfer">\n  <input name="amount" value="1000000">\n  <button>Transfer</button>\n</form>',
        "code_after": '<form method="POST" action="/transfer">\n  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">\n  <input name="amount" value="1000000">\n  <button>Transfer</button>\n</form>',
        "references": ["CWE-352: Cross-Site Request Forgery"]
    },
    "DB-057": {
        "title": "Database Dump Exposure Fix",
        "description": "File dump database (.sql, .db) bisa diakses publik.",
        "risk": "Seluruh data database terekspos termasuk credentials dan data user.",
        "fix_steps": ["Hapus file dump dari web root", "Block akses ke file .sql, .db, .sqlite via web server config", "Simpan backup di luar web root"],
        "code_before": "# File backup.sql accessible at /backup.sql",
        "code_after": "# Nginx - Block database files\nlocation ~* \\.(sql|db|sqlite|sqlite3)$ {\n    deny all;\n    return 404;\n}",
        "references": ["CWE-538: File and Directory Information Exposure"]
    },
    "SRC-075": {
        "title": "Git Repository Exposure Fix",
        "description": "Folder .git terekspos dan bisa diakses publik.",
        "risk": "Attacker bisa download seluruh source code termasuk credentials dan konfigurasi.",
        "fix_steps": ["Block akses ke .git folder di web server config", "Jangan deploy .git ke production"],
        "code_before": "# .git/HEAD accessible at /.git/HEAD",
        "code_after": "# Nginx\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}\n\n# Apache (.htaccess)\n<DirectoryMatch \"^\\.git\">\n    Require all denied\n</DirectoryMatch>",
        "references": ["CWE-538: File and Directory Information Exposure"]
    },
    "SRC-082": {
        "title": ".env File Exposure Fix",
        "description": "File .env berisi konfigurasi sensitif terekspos.",
        "risk": "Database credentials, API keys, dan secrets terekspos.",
        "fix_steps": ["Block akses ke .env via web server", "Simpan .env di luar web root", "Gunakan environment variables dari OS/container"],
        "code_before": "# .env accessible at /.env",
        "code_after": "# Nginx\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}",
        "references": ["CWE-538: File and Directory Information Exposure"]
    },
    "ADV-089": {
        "title": "Server-Side Template Injection (SSTI) Fix",
        "description": "User input diproses oleh template engine tanpa sanitasi.",
        "risk": "Remote Code Execution - attacker bisa menjalankan perintah di server.",
        "fix_steps": ["Jangan masukkan user input langsung ke template string", "Gunakan sandbox mode pada template engine", "Validasi dan sanitize input"],
        "code_before": "# VULNERABLE - Python Jinja2\ntemplate = Template(user_input)\nresult = template.render()",
        "code_after": "# FIXED - Pass user input as variable, not template\ntemplate = Template('Hello {{ name }}')\nresult = template.render(name=user_input)",
        "references": ["CWE-94: Code Injection"]
    },
    "ADV-090": {
        "title": "SSRF (Server-Side Request Forgery) Fix",
        "description": "Server melakukan HTTP request ke URL yang dikontrol user.",
        "risk": "Attacker bisa mengakses internal services, cloud metadata, dan resource internal.",
        "fix_steps": ["Validasi URL dengan allowlist", "Block akses ke IP internal/private", "Jangan izinkan schemes selain http/https"],
        "code_before": "url = request.form['url']\nresponse = requests.get(url)  # No validation!",
        "code_after": "import ipaddress\nfrom urllib.parse import urlparse\n\ndef is_safe_url(url):\n    parsed = urlparse(url)\n    if parsed.scheme not in ('http', 'https'):\n        return False\n    try:\n        ip = ipaddress.ip_address(parsed.hostname)\n        if ip.is_private or ip.is_loopback:\n            return False\n    except ValueError:\n        pass\n    return True\n\nurl = request.form['url']\nif not is_safe_url(url):\n    abort(400)\nresponse = requests.get(url, timeout=5)",
        "references": ["CWE-918: Server-Side Request Forgery"]
    },
    "ADV-091": {
        "title": "XXE (XML External Entity) Fix",
        "description": "XML parser memproses external entities dari user input.",
        "risk": "File disclosure, SSRF, denial of service.",
        "fix_steps": ["Disable external entity processing", "Gunakan JSON alih-alih XML", "Validasi XML input"],
        "code_before": "import xml.etree.ElementTree as ET\ntree = ET.parse(user_xml)",
        "code_after": "import defusedxml.ElementTree as ET\ntree = ET.parse(user_xml)  # defusedxml blocks XXE",
        "references": ["CWE-611: XML External Entity"]
    },
    "FILE-139": {
        "title": "Path Traversal / LFI Fix",
        "description": "User bisa membaca file server dengan memanipulasi parameter path.",
        "risk": "Akses ke file sensitif server (/etc/passwd, konfigurasi, source code).",
        "fix_steps": ["Validasi path - hapus semua ../ sequences", "Gunakan allowlist untuk file yang boleh diakses", "Chroot atau sandbox file access"],
        "code_before": "filename = request.args.get('file')\nwith open('/var/www/' + filename) as f:\n    return f.read()",
        "code_after": "import os\nfilename = request.args.get('file')\nbase_dir = '/var/www/public/'\nfull_path = os.path.realpath(os.path.join(base_dir, filename))\nif not full_path.startswith(base_dir):\n    abort(403)\nwith open(full_path) as f:\n    return f.read()",
        "references": ["CWE-22: Path Traversal"]
    },
}

def get_fix_guide(bug_id: str) -> dict:
    return FIX_GUIDES.get(bug_id, {
        "title": "General Security Fix",
        "description": "Vulnerability terdeteksi yang perlu diperbaiki.",
        "risk": "Lihat deskripsi vulnerability untuk detail risiko.",
        "fix_steps": [
            "Identifikasi root cause dari vulnerability",
            "Terapkan perbaikan sesuai best practice OWASP",
            "Validasi semua input dari user",
            "Implementasi defense in depth",
            "Lakukan testing ulang setelah perbaikan"
        ],
        "code_before": "# Lihat evidence dari vulnerability scan untuk contoh kode rentan",
        "code_after": "# Terapkan perbaikan berdasarkan fix steps di atas",
        "references": ["https://owasp.org/www-project-top-ten/"]
    })
