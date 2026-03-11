import './globals.css';

export const metadata = {
  title: 'VulnScanner - Web Vulnerability Scanner',
  description: 'Scan websites for 180+ security vulnerabilities with fix guides',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
