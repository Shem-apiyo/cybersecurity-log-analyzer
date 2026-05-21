#include <algorithm>
#include <cstdlib>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

namespace fs {
class filesystem_error : public runtime_error {
public:
    explicit filesystem_error(const std::string& message) : runtime_error(message) {}
};

class path {
public:
    path() {}
    path(const char* value) : value_(value == nullptr ? "" : value) {}
    path(const std::string& value) : value_(value) {}

    std::string string() const {
        return value_;
    }

    path filename() const {
        std::string text = value_;
        while (text.size() > 1 && (text.back() == '\\' || text.back() == '/')) {
            text.pop_back();
        }

        size_t separator = text.find_last_of("\\/");
        if (separator == string::npos) {
            return path(text);
        }

        return path(text.substr(separator + 1));
    }

    path operator/(const path& child) const {
        if (value_.empty()) {
            return child;
        }

        if (child.value_.empty()) {
            return *this;
        }

        char last = value_[value_.size() - 1];
        if (last == '\\' || last == '/') {
            return path(value_ + child.value_);
        }

        return path(value_ + "\\" + child.value_);
    }

private:
    std::string value_;
};

bool exists(const path& value) {
    return GetFileAttributesA(value.string().c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool is_directory(const path& value) {
    DWORD attributes = GetFileAttributesA(value.string().c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY);
}

class directory_entry {
public:
    explicit directory_entry(const path& value) : value_(value) {}

    const path& path() const {
        return value_;
    }

    bool is_directory() const {
        return fs::is_directory(value_);
    }

private:
    fs::path value_;
};

class directory_iterator {
public:
    explicit directory_iterator(const path& directory) {
        std::string searchPath = directory.string();
        if (searchPath.empty()) {
            return;
        }

        char last = searchPath[searchPath.size() - 1];
        if (last != '\\' && last != '/') {
            searchPath += "\\";
        }
        searchPath += "*";

        WIN32_FIND_DATAA data;
        HANDLE handle = FindFirstFileA(searchPath.c_str(), &data);
        if (handle == INVALID_HANDLE_VALUE) {
            return;
        }

        do {
            std::string name = data.cFileName;
            if (name != "." && name != "..") {
                entries_.push_back(directory_entry(directory / name));
            }
        } while (FindNextFileA(handle, &data));

        FindClose(handle);
    }

    vector<directory_entry>::const_iterator begin() const {
        return entries_.begin();
    }

    vector<directory_entry>::const_iterator end() const {
        return entries_.end();
    }

private:
    vector<directory_entry> entries_;
};
}

struct LogEntry {
    string date = "UNKNOWN";
    string time = "UNKNOWN";
    string ip = "UNKNOWN";
    string event = "UNKNOWN";
    string username = "UNKNOWN";
    string method = "-";
    string path = "-";
    int statusCode = 0;
    string source = "UNKNOWN";
    string rawLine;
};

struct IpStats {
    int totalEvents = 0;
    int failedLogins = 0;
    int successfulLogins = 0;
    int portScans = 0;
    int sqlInjectionAttempts = 0;
    int adminAccessAttempts = 0;
    int httpUnauthorizedOrForbidden = 0;
    int notFoundErrors = 0;
    int pathTraversalAttempts = 0;
    int suspiciousHttpRequests = 0;

    set<string> usernames;
    set<string> pathsTouched;
    set<string> sourcesSeen;
    vector<string> reasons;
};

string toUpperCase(string text) {
    transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(toupper(c));
    });
    return text;
}

string toLowerCase(string text) {
    transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });
    return text;
}

string trimText(const string& text) {
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == string::npos) {
        return "";
    }

    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

string cleanPathInput(string text) {
    text = trimText(text);

    if (text.size() >= 2 &&
        ((text.front() == '"' && text.back() == '"') ||
         (text.front() == '\'' && text.back() == '\''))) {
        text = text.substr(1, text.size() - 2);
    }

    return trimText(text);
}

bool samePathText(string left, string right) {
    left = toLowerCase(cleanPathInput(left));
    right = toLowerCase(cleanPathInput(right));

    replace(left.begin(), left.end(), '/', '\\');
    replace(right.begin(), right.end(), '/', '\\');

    while (left.size() > 1 && left.back() == '\\') {
        left.pop_back();
    }

    while (right.size() > 1 && right.back() == '\\') {
        right.pop_back();
    }

    return left == right;
}

bool containsAny(const string& text, const vector<string>& needles) {
    string lower = toLowerCase(text);

    for (const string& needle : needles) {
        if (lower.find(toLowerCase(needle)) != string::npos) {
            return true;
        }
    }

    return false;
}

string extractDateFromApacheTime(const string& apacheTime) {
    // Example: 20/May/2026:10:13:45 +0300
    size_t colonPos = apacheTime.find(':');
    if (colonPos == string::npos) {
        return "UNKNOWN";
    }

    return apacheTime.substr(0, colonPos);
}

string extractClockFromApacheTime(const string& apacheTime) {
    // Example: 20/May/2026:10:13:45 +0300
    size_t colonPos = apacheTime.find(':');
    if (colonPos == string::npos || colonPos + 8 >= apacheTime.size()) {
        return "UNKNOWN";
    }

    return apacheTime.substr(colonPos + 1, 8);
}

bool looksLikeSqlInjection(const string& path) {
    vector<string> patterns = {
        "union select",
        "select%20",
        " or 1=1",
        "' or '",
        "\" or \"",
        "--",
        "%27",
        "sleep(",
        "benchmark(",
        "information_schema",
        "concat(",
        "drop table"
    };

    return containsAny(path, patterns);
}

bool looksLikePathTraversal(const string& path) {
    vector<string> patterns = {
        "../",
        "..%2f",
        "%2e%2e",
        "/etc/passwd",
        "boot.ini",
        "win.ini"
    };

    return containsAny(path, patterns);
}

bool looksLikeAdminProbe(const string& path) {
    vector<string> patterns = {
        "/admin",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/cpanel",
        "/administrator",
        "/login",
        "/dashboard"
    };

    return containsAny(path, patterns);
}

bool looksLikeSensitiveFileProbe(const string& path) {
    vector<string> patterns = {
        "/.env",
        "/config.php",
        "/backup",
        ".bak",
        ".sql",
        ".zip",
        ".tar.gz",
        "/id_rsa",
        "/.git"
    };

    return containsAny(path, patterns);
}

bool isSuspiciousEvent(const LogEntry& entry) {
    return entry.event == "LOGIN_FAILED" ||
           entry.event == "SQL_INJECTION" ||
           entry.event == "PATH_TRAVERSAL" ||
           entry.event == "ADMIN_ACCESS" ||
           entry.event == "SENSITIVE_FILE_PROBE" ||
           entry.event == "HTTP_UNAUTHORIZED_OR_FORBIDDEN" ||
           entry.event == "HTTP_NOT_FOUND" ||
           entry.event == "SUDO_AUTH_FAILURE" ||
           entry.event == "PORT_SCAN";
}

bool parseCustomLogLine(const string& line, LogEntry& entry) {
    stringstream ss(line);

    // Expected custom format:
    // YYYY-MM-DD HH:MM:SS IP_ADDRESS EVENT USERNAME
    // Example:
    // 2026-05-20 10:01:03 192.168.1.8 LOGIN_FAILED admin
    string date, time, ip, event, username;

    if (!(ss >> date >> time >> ip >> event)) {
        return false;
    }

    if (date.find('-') == string::npos || time.find(':') == string::npos) {
        return false;
    }

    entry.date = date;
    entry.time = time;
    entry.ip = ip;
    entry.event = toUpperCase(event);

    if (ss >> username) {
        entry.username = username;
    }

    entry.source = "CUSTOM";
    entry.rawLine = line;
    return true;
}

bool parseApacheOrNginxAccessLine(const string& line, LogEntry& entry) {
    // Supports common Apache/Nginx access log style:
    // 45.67.89.10 - - [20/May/2026:10:13:45 +0300] "GET /admin HTTP/1.1" 403 532 "-" "Mozilla/5.0"
    regex accessPattern(R"(^([^\s]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"(\S+)\s+([^\"]*)\s+HTTP/[0-9.]+\"\s+(\d{3}).*)");
    smatch match;

    if (!regex_match(line, match, accessPattern)) {
        return false;
    }

    entry.ip = match[1];
    string apacheTime = match[2];
    entry.method = match[3];
    entry.path = match[4];
    entry.statusCode = stoi(match[5]);
    entry.date = extractDateFromApacheTime(apacheTime);
    entry.time = extractClockFromApacheTime(apacheTime);
    entry.source = "WEB_ACCESS";
    entry.rawLine = line;

    if (looksLikeSqlInjection(entry.path)) {
        entry.event = "SQL_INJECTION";
    } else if (looksLikePathTraversal(entry.path)) {
        entry.event = "PATH_TRAVERSAL";
    } else if (looksLikeAdminProbe(entry.path)) {
        entry.event = "ADMIN_ACCESS";
    } else if (looksLikeSensitiveFileProbe(entry.path)) {
        entry.event = "SENSITIVE_FILE_PROBE";
    } else if (entry.statusCode == 401 || entry.statusCode == 403) {
        entry.event = "HTTP_UNAUTHORIZED_OR_FORBIDDEN";
    } else if (entry.statusCode == 404) {
        entry.event = "HTTP_NOT_FOUND";
    } else {
        entry.event = "HTTP_REQUEST";
    }

    return true;
}

bool parseLinuxAuthLine(const string& line, LogEntry& entry) {
    // Supports Linux auth.log / secure examples:
    // May 20 10:20:01 server sshd[1234]: Failed password for invalid user admin from 45.67.89.10 port 54321 ssh2
    // May 20 10:21:44 server sshd[1235]: Accepted password for sammy from 10.0.0.5 port 50000 ssh2
    regex failedInvalidUser(R"(^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*Failed password for invalid user\s+(\S+)\s+from\s+([^\s]+).*)");
    regex failedNormalUser(R"(^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*Failed password for\s+(\S+)\s+from\s+([^\s]+).*)");
    regex acceptedUser(R"(^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*Accepted password for\s+(\S+)\s+from\s+([^\s]+).*)");
    regex sudoFailure(R"(^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}).*sudo.*authentication failure.*user=([^\s]+).*)");

    smatch match;

    if (regex_match(line, match, failedInvalidUser)) {
        entry.date = string(match[1]) + " " + string(match[2]);
        entry.time = match[3];
        entry.username = match[4];
        entry.ip = match[5];
        entry.event = "LOGIN_FAILED";
        entry.source = "LINUX_AUTH";
        entry.rawLine = line;
        return true;
    }

    if (regex_match(line, match, failedNormalUser)) {
        entry.date = string(match[1]) + " " + string(match[2]);
        entry.time = match[3];
        entry.username = match[4];
        entry.ip = match[5];
        entry.event = "LOGIN_FAILED";
        entry.source = "LINUX_AUTH";
        entry.rawLine = line;
        return true;
    }

    if (regex_match(line, match, acceptedUser)) {
        entry.date = string(match[1]) + " " + string(match[2]);
        entry.time = match[3];
        entry.username = match[4];
        entry.ip = match[5];
        entry.event = "LOGIN_SUCCESS";
        entry.source = "LINUX_AUTH";
        entry.rawLine = line;
        return true;
    }

    if (regex_match(line, match, sudoFailure)) {
        entry.date = string(match[1]) + " " + string(match[2]);
        entry.time = match[3];
        entry.username = match[4];
        entry.ip = "LOCALHOST";
        entry.event = "SUDO_AUTH_FAILURE";
        entry.source = "LINUX_AUTH";
        entry.rawLine = line;
        return true;
    }

    return false;
}

bool parseLogLine(const string& line, LogEntry& entry) {
    if (line.empty()) {
        return false;
    }

    if (parseApacheOrNginxAccessLine(line, entry)) {
        return true;
    }

    if (parseLinuxAuthLine(line, entry)) {
        return true;
    }

    if (parseCustomLogLine(line, entry)) {
        return true;
    }

    return false;
}

vector<LogEntry> loadLogs(const string& filename) {
    vector<LogEntry> logs;
    ifstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not open file: " << filename << endl;
        return logs;
    }

    string line;
    int skippedLines = 0;

    while (getline(file, line)) {
        LogEntry entry;

        if (parseLogLine(line, entry)) {
            logs.push_back(entry);
        } else {
            skippedLines++;
        }
    }

    file.close();

    if (skippedLines > 0) {
        cout << "Note: Skipped " << skippedLines << " unsupported or invalid log lines.\n";
    }

    return logs;
}

map<string, IpStats> analyzeLogs(const vector<LogEntry>& logs) {
    map<string, IpStats> ipStats;

    for (const LogEntry& entry : logs) {
        IpStats& stats = ipStats[entry.ip];
        stats.totalEvents++;
        stats.usernames.insert(entry.username);
        stats.sourcesSeen.insert(entry.source);

        if (entry.path != "-") {
            stats.pathsTouched.insert(entry.path);
        }

        if (entry.event == "LOGIN_FAILED" || entry.event == "SUDO_AUTH_FAILURE") {
            stats.failedLogins++;
        } else if (entry.event == "LOGIN_SUCCESS") {
            stats.successfulLogins++;
        } else if (entry.event == "PORT_SCAN") {
            stats.portScans++;
        } else if (entry.event == "SQL_INJECTION") {
            stats.sqlInjectionAttempts++;
            stats.suspiciousHttpRequests++;
        } else if (entry.event == "ADMIN_ACCESS") {
            stats.adminAccessAttempts++;
            stats.suspiciousHttpRequests++;
        } else if (entry.event == "PATH_TRAVERSAL") {
            stats.pathTraversalAttempts++;
            stats.suspiciousHttpRequests++;
        } else if (entry.event == "SENSITIVE_FILE_PROBE") {
            stats.suspiciousHttpRequests++;
        } else if (entry.event == "HTTP_UNAUTHORIZED_OR_FORBIDDEN") {
            stats.httpUnauthorizedOrForbidden++;
        } else if (entry.event == "HTTP_NOT_FOUND") {
            stats.notFoundErrors++;
        }

        if (entry.statusCode == 401 || entry.statusCode == 403) {
            stats.httpUnauthorizedOrForbidden++;
        }

        if (entry.statusCode == 404) {
            stats.notFoundErrors++;
        }
    }

    for (auto& pair : ipStats) {
        IpStats& stats = pair.second;

        if (stats.failedLogins >= 3) {
            stats.reasons.push_back("Possible brute-force attack: 3 or more failed login attempts");
        }

        if (stats.failedLogins >= 3 && stats.successfulLogins >= 1) {
            stats.reasons.push_back("Successful login after multiple failures");
        }

        if (stats.usernames.size() >= 3) {
            stats.reasons.push_back("Possible username spraying: multiple usernames tried from same IP");
        }

        if (stats.portScans >= 1) {
            stats.reasons.push_back("Port scanning activity detected");
        }

        if (stats.sqlInjectionAttempts >= 1) {
            stats.reasons.push_back("Possible SQL injection attempt detected");
        }

        if (stats.pathTraversalAttempts >= 1) {
            stats.reasons.push_back("Possible path traversal attempt detected");
        }

        if (stats.adminAccessAttempts >= 2) {
            stats.reasons.push_back("Repeated admin/login page probing");
        }

        if (stats.httpUnauthorizedOrForbidden >= 3) {
            stats.reasons.push_back("Repeated 401/403 responses from same IP");
        }

        if (stats.notFoundErrors >= 5) {
            stats.reasons.push_back("High number of 404 responses: possible directory/file enumeration");
        }

        if (stats.suspiciousHttpRequests >= 3) {
            stats.reasons.push_back("Multiple suspicious HTTP requests detected");
        }
    }

    return ipStats;
}

string getRiskLevel(const IpStats& stats) {
    int score = 0;

    score += stats.failedLogins;
    score += stats.successfulLogins * 2;
    score += stats.portScans * 3;
    score += stats.sqlInjectionAttempts * 5;
    score += stats.pathTraversalAttempts * 5;
    score += stats.adminAccessAttempts * 2;
    score += stats.httpUnauthorizedOrForbidden;
    score += stats.notFoundErrors;
    score += stats.suspiciousHttpRequests * 2;

    if (stats.reasons.empty()) {
        return "LOW";
    }

    if (score >= 15) {
        return "HIGH";
    }

    if (score >= 7) {
        return "MEDIUM";
    }

    return "LOW";
}

int getRiskScore(const IpStats& stats) {
    int score = 0;

    score += stats.failedLogins;
    score += stats.successfulLogins * 2;
    score += stats.portScans * 3;
    score += stats.sqlInjectionAttempts * 5;
    score += stats.pathTraversalAttempts * 5;
    score += stats.adminAccessAttempts * 2;
    score += stats.httpUnauthorizedOrForbidden;
    score += stats.notFoundErrors;
    score += stats.suspiciousHttpRequests * 2;

    return score;
}

void printDivider(ostream& out) {
    out << "--------------------------------------------------------------------------------\n";
}

string joinSet(const set<string>& values, int maxItems = 5) {
    if (values.empty()) {
        return "-";
    }

    stringstream ss;
    int count = 0;

    for (const string& value : values) {
        if (count > 0) {
            ss << ", ";
        }

        ss << value;
        count++;

        if (count >= maxItems && static_cast<int>(values.size()) > maxItems) {
            ss << ", ...";
            break;
        }
    }

    return ss.str();
}

string csvEscape(const string& value) {
    bool mustQuote = value.find(',') != string::npos ||
                     value.find('"') != string::npos ||
                     value.find('\n') != string::npos ||
                     value.find('\r') != string::npos;

    string escaped;

    for (char ch : value) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }

    if (mustQuote) {
        return "\"" + escaped + "\"";
    }

    return escaped;
}

string joinVector(const vector<string>& values, const string& separator = " | ") {
    if (values.empty()) {
        return "-";
    }

    stringstream ss;

    for (size_t i = 0; i < values.size(); i++) {
        if (i > 0) {
            ss << separator;
        }
        ss << values[i];
    }

    return ss.str();
}

void generateReport(const map<string, IpStats>& ipStats, ostream& out) {
    int totalIps = 0;
    int suspiciousIps = 0;
    int highRiskIps = 0;
    int mediumRiskIps = 0;
    int lowRiskIps = 0;

    for (const auto& pair : ipStats) {
        totalIps++;
        string risk = getRiskLevel(pair.second);

        if (!pair.second.reasons.empty()) {
            suspiciousIps++;
        }

        if (risk == "HIGH") {
            highRiskIps++;
        } else if (risk == "MEDIUM") {
            mediumRiskIps++;
        } else {
            lowRiskIps++;
        }
    }

    out << "CYBERSECURITY LOG ANALYSIS REPORT\n";
    printDivider(out);
    out << "Total unique IP addresses: " << totalIps << "\n";
    out << "Suspicious IP addresses:   " << suspiciousIps << "\n";
    out << "High risk IPs:             " << highRiskIps << "\n";
    out << "Medium risk IPs:           " << mediumRiskIps << "\n";
    out << "Low risk IPs:              " << lowRiskIps << "\n";
    printDivider(out);

    out << left
        << setw(18) << "IP Address"
        << setw(10) << "Risk"
        << setw(8) << "Score"
        << setw(8) << "Fail"
        << setw(8) << "OK"
        << setw(8) << "401/403"
        << setw(8) << "404"
        << setw(8) << "SQLi"
        << setw(8) << "Trav"
        << setw(8) << "Admin"
        << "Sources\n";

    printDivider(out);

    for (const auto& pair : ipStats) {
        const string& ip = pair.first;
        const IpStats& stats = pair.second;

        out << left
            << setw(18) << ip
            << setw(10) << getRiskLevel(stats)
            << setw(8) << getRiskScore(stats)
            << setw(8) << stats.failedLogins
            << setw(8) << stats.successfulLogins
            << setw(8) << stats.httpUnauthorizedOrForbidden
            << setw(8) << stats.notFoundErrors
            << setw(8) << stats.sqlInjectionAttempts
            << setw(8) << stats.pathTraversalAttempts
            << setw(8) << stats.adminAccessAttempts
            << joinSet(stats.sourcesSeen, 3)
            << "\n";
    }

    printDivider(out);
    out << "DETAILED ALERTS\n";
    printDivider(out);

    bool foundAlert = false;

    for (const auto& pair : ipStats) {
        const string& ip = pair.first;
        const IpStats& stats = pair.second;

        if (!stats.reasons.empty()) {
            foundAlert = true;
            out << "IP: " << ip << "\n";
            out << "Risk Level: " << getRiskLevel(stats) << "\n";
            out << "Risk Score: " << getRiskScore(stats) << "\n";
            out << "Sources: " << joinSet(stats.sourcesSeen) << "\n";
            out << "Usernames tried: " << joinSet(stats.usernames) << "\n";
            out << "Paths touched: " << joinSet(stats.pathsTouched, 8) << "\n";
            out << "Reasons:\n";

            for (const string& reason : stats.reasons) {
                out << "  - " << reason << "\n";
            }

            printDivider(out);
        }
    }

    if (!foundAlert) {
        out << "No suspicious activity detected.\n";
    }
}

void exportIpSummaryCsv(const map<string, IpStats>& ipStats, const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not save CSV file: " << filename << "\n";
        return;
    }

    file << "ip,risk_level,risk_score,total_events,failed_logins,successful_logins,http_401_403,http_404,sql_injection,path_traversal,admin_access,suspicious_http_requests,usernames,sources,paths,reasons\n";

    for (const auto& pair : ipStats) {
        const string& ip = pair.first;
        const IpStats& stats = pair.second;

        file << csvEscape(ip) << ","
             << csvEscape(getRiskLevel(stats)) << ","
             << getRiskScore(stats) << ","
             << stats.totalEvents << ","
             << stats.failedLogins << ","
             << stats.successfulLogins << ","
             << stats.httpUnauthorizedOrForbidden << ","
             << stats.notFoundErrors << ","
             << stats.sqlInjectionAttempts << ","
             << stats.pathTraversalAttempts << ","
             << stats.adminAccessAttempts << ","
             << stats.suspiciousHttpRequests << ","
             << csvEscape(joinSet(stats.usernames, 20)) << ","
             << csvEscape(joinSet(stats.sourcesSeen, 20)) << ","
             << csvEscape(joinSet(stats.pathsTouched, 20)) << ","
             << csvEscape(joinVector(stats.reasons))
             << "\n";
    }

    file.close();
    cout << "IP summary CSV saved to: " << filename << "\n";
}

void exportAlertsCsv(const map<string, IpStats>& ipStats, const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not save CSV file: " << filename << "\n";
        return;
    }

    file << "ip,risk_level,risk_score,alert_reason,usernames,sources,paths\n";

    for (const auto& pair : ipStats) {
        const string& ip = pair.first;
        const IpStats& stats = pair.second;

        for (const string& reason : stats.reasons) {
            file << csvEscape(ip) << ","
                 << csvEscape(getRiskLevel(stats)) << ","
                 << getRiskScore(stats) << ","
                 << csvEscape(reason) << ","
                 << csvEscape(joinSet(stats.usernames, 20)) << ","
                 << csvEscape(joinSet(stats.sourcesSeen, 20)) << ","
                 << csvEscape(joinSet(stats.pathsTouched, 20))
                 << "\n";
        }
    }

    file.close();
    cout << "Alert CSV saved to: " << filename << "\n";
}

vector<LogEntry> buildTimeline(vector<LogEntry> logs, bool suspiciousOnly = true) {
    vector<LogEntry> timeline;

    for (const LogEntry& entry : logs) {
        if (!suspiciousOnly || isSuspiciousEvent(entry)) {
            timeline.push_back(entry);
        }
    }

    sort(timeline.begin(), timeline.end(), [](const LogEntry& a, const LogEntry& b) {
        string left = a.date + " " + a.time + " " + a.ip;
        string right = b.date + " " + b.time + " " + b.ip;
        return left < right;
    });

    return timeline;
}

void generateTimelineView(const vector<LogEntry>& logs, ostream& out, int maxRows = 50) {
    vector<LogEntry> timeline = buildTimeline(logs, true);

    out << "SUSPICIOUS EVENT TIMELINE\n";
    printDivider(out);

    if (timeline.empty()) {
        out << "No suspicious events found for timeline view.\n";
        return;
    }

    out << left
        << setw(14) << "Date"
        << setw(10) << "Time"
        << setw(18) << "IP"
        << setw(28) << "Event"
        << setw(8) << "Status"
        << setw(12) << "Method"
        << "Target/User\n";

    printDivider(out);

    int shown = 0;

    for (const LogEntry& entry : timeline) {
        if (shown >= maxRows) {
            out << "... timeline truncated. Increase maxRows in generateTimelineView() to show more.\n";
            break;
        }

        string target = entry.path != "-" ? entry.path : entry.username;

        out << left
            << setw(14) << entry.date
            << setw(10) << entry.time
            << setw(18) << entry.ip
            << setw(28) << entry.event
            << setw(8) << entry.statusCode
            << setw(12) << entry.method
            << target
            << "\n";

        shown++;
    }

    printDivider(out);
}

void exportTimelineCsv(const vector<LogEntry>& logs, const string& filename) {
    vector<LogEntry> timeline = buildTimeline(logs, true);
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not save timeline CSV file: " << filename << "\n";
        return;
    }

    file << "date,time,ip,event,source,username,method,path,status_code,raw_line\n";

    for (const LogEntry& entry : timeline) {
        file << csvEscape(entry.date) << ","
             << csvEscape(entry.time) << ","
             << csvEscape(entry.ip) << ","
             << csvEscape(entry.event) << ","
             << csvEscape(entry.source) << ","
             << csvEscape(entry.username) << ","
             << csvEscape(entry.method) << ","
             << csvEscape(entry.path) << ","
             << entry.statusCode << ","
             << csvEscape(entry.rawLine)
             << "\n";
    }

    file.close();
    cout << "Timeline CSV saved to: " << filename << "\n";
}

void saveTimelineTxt(const vector<LogEntry>& logs, const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not save timeline text file: " << filename << "\n";
        return;
    }

    generateTimelineView(logs, file, 1000);
    file.close();
    cout << "Timeline text report saved to: " << filename << "\n";
}

string getEnvValue(const string& name) {
    const char* value = getenv(name.c_str());
    if (value == nullptr) {
        return "";
    }
    return string(value);
}

string readFileLimited(const fs::path& path, size_t maxBytes = 750000) {
    ifstream file(path.string().c_str(), ios::binary);
    if (!file.is_open()) {
        return "";
    }

    string content;
    content.reserve(maxBytes);

    char ch;
    size_t count = 0;

    while (file.get(ch) && count < maxBytes) {
        content.push_back(ch);
        count++;
    }

    return content;
}

string extractJsonStringValue(const string& text, const string& key) {
    try {
        regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        smatch match;
        if (regex_search(text, match, pattern)) {
            return match[1];
        }
    } catch (...) {
        return "";
    }

    return "";
}

struct ChromeFinding {
    string profile;
    string item;
    string severity;
    string reason;
    string location;
};

void addChromeFinding(vector<ChromeFinding>& findings,
                      const string& profile,
                      const string& item,
                      const string& severity,
                      const string& reason,
                      const string& location) {
    ChromeFinding finding;
    finding.profile = profile;
    finding.item = item;
    finding.severity = severity;
    finding.reason = reason;
    finding.location = location;
    findings.push_back(finding);
}

void addChromeCandidatePath(vector<fs::path>& paths, const string& pathText) {
    string cleaned = cleanPathInput(pathText);
    if (cleaned.empty()) {
        return;
    }

    for (const fs::path& existing : paths) {
        if (samePathText(existing.string(), cleaned)) {
            return;
        }
    }

    paths.push_back(fs::path(cleaned));
}

vector<fs::path> getChromeUserDataCandidates() {
    vector<fs::path> paths;

    string localAppData = getEnvValue("LOCALAPPDATA");
    string home = getEnvValue("HOME");
    string userProfile = getEnvValue("USERPROFILE");

    if (!localAppData.empty()) {
        addChromeCandidatePath(paths, (fs::path(localAppData) / "Google" / "Chrome" / "User Data").string());
        addChromeCandidatePath(paths, (fs::path(localAppData) / "Chromium" / "User Data").string());
        addChromeCandidatePath(paths, (fs::path(localAppData) / "Microsoft" / "Edge" / "User Data").string());
    }

    if (!userProfile.empty()) {
        addChromeCandidatePath(paths, (fs::path(userProfile) / "AppData" / "Local" / "Google" / "Chrome" / "User Data").string());
    }

    if (!home.empty()) {
        addChromeCandidatePath(paths, (fs::path(home) / ".config" / "google-chrome").string());
        addChromeCandidatePath(paths, (fs::path(home) / ".config" / "chromium").string());
        addChromeCandidatePath(paths, (fs::path(home) / "Library" / "Application Support" / "Google" / "Chrome").string());
    }

    return paths;
}

bool isChromeProfileDirectory(const fs::path& path) {
    if (!fs::is_directory(path)) {
        return false;
    }

    string name = path.filename().string();

    if (name == "Default" || name == "Guest Profile" || name == "System Profile") {
        return true;
    }

    if (name.rfind("Profile ", 0) == 0) {
        return true;
    }

    return fs::exists(path / "Preferences") || fs::exists(path / "Extensions");
}

void scanChromeExtensionManifest(const fs::path& manifestPath,
                                 const string& profileName,
                                 const string& extensionId,
                                 vector<ChromeFinding>& findings) {
    string manifest = readFileLimited(manifestPath);
    if (manifest.empty()) {
        return;
    }

    string lower = toLowerCase(manifest);
    string extensionName = extractJsonStringValue(manifest, "name");
    string version = extractJsonStringValue(manifest, "version");

    if (extensionName.empty()) {
        extensionName = "Unknown extension";
    }

    string item = extensionName + " [" + extensionId + "]";
    if (!version.empty()) {
        item += " v" + version;
    }

    vector<pair<string, string>> riskyPermissions = {
        {"\"<all_urls>\"", "Can potentially run on all websites"},
        {"\"tabs\"", "Can inspect browser tabs"},
        {"\"history\"", "Can read browsing history"},
        {"\"cookies\"", "Can access browser cookies"},
        {"\"downloads\"", "Can monitor or manage downloads"},
        {"\"proxy\"", "Can modify proxy/network routing"},
        {"\"webrequest\"", "Can observe or modify web requests"},
        {"\"webrequestblocking\"", "Can block or modify web requests"},
        {"\"debugger\"", "Can attach to browser debugging interface"},
        {"\"nativemessaging\"", "Can communicate with native apps on the computer"},
        {"\"management\"", "Can manage other extensions/apps"},
        {"\"privacy\"", "Can change browser privacy settings"},
        {"\"bookmarks\"", "Can read or modify bookmarks"},
        {"\"clipboardread\"", "Can read clipboard data"},
        {"\"scripting\"", "Can inject scripts into web pages"},
        {"\"webnavigation\"", "Can observe browser navigation activity"}
    };

    int riskyCount = 0;

    for (const auto& permission : riskyPermissions) {
        if (lower.find(toLowerCase(permission.first)) != string::npos) {
            riskyCount++;
            string severity = "MEDIUM";

            if (permission.first == "\"cookies\"" ||
                permission.first == "\"debugger\"" ||
                permission.first == "\"proxy\"" ||
                permission.first == "\"webrequestblocking\"" ||
                permission.first == "\"nativemessaging\"") {
                severity = "HIGH";
            }

            addChromeFinding(findings,
                             profileName,
                             item,
                             severity,
                             "Risky extension permission: " + permission.second,
                             manifestPath.string());
        }
    }

    if (lower.find("externally_connectable") != string::npos) {
        addChromeFinding(findings,
                         profileName,
                         item,
                         "MEDIUM",
                         "Extension exposes externally_connectable behavior",
                         manifestPath.string());
    }

    if (lower.find("update_url") != string::npos &&
        lower.find("clients2.google.com/service/update2/crx") == string::npos) {
        addChromeFinding(findings,
                         profileName,
                         item,
                         "MEDIUM",
                         "Extension has a non-standard update_url. Review if it came from a trusted source",
                         manifestPath.string());
    }

    if (riskyCount >= 5) {
        addChromeFinding(findings,
                         profileName,
                         item,
                         "HIGH",
                         "Extension has many powerful permissions. Review carefully",
                         manifestPath.string());
    }
}

void scanChromeProfilePreferences(const fs::path& profilePath,
                                  const string& profileName,
                                  vector<ChromeFinding>& findings) {
    fs::path preferencesPath = profilePath / "Preferences";
    string preferences = readFileLimited(preferencesPath);

    if (preferences.empty()) {
        return;
    }

    string lower = toLowerCase(preferences);

    if (lower.find("\"homepage_is_newtabpage\":false") != string::npos) {
        string homepage = extractJsonStringValue(preferences, "homepage");
        addChromeFinding(findings,
                         profileName,
                         "Chrome profile settings",
                         "LOW",
                         "Homepage is not the default new tab page" + (homepage.empty() ? string("") : string(": ") + homepage),
                         preferencesPath.string());
    }

    if (lower.find("\"restore_on_startup\":4") != string::npos) {
        addChromeFinding(findings,
                         profileName,
                         "Chrome startup settings",
                         "LOW",
                         "Chrome is configured to open specific startup URLs. Review them in Chrome settings",
                         preferencesPath.string());
    }

    size_t safeBrowsingPos = lower.find("\"safe_browsing\"");
    if (safeBrowsingPos != string::npos) {
        string nearby = lower.substr(safeBrowsingPos, min<size_t>(700, lower.size() - safeBrowsingPos));
        if (nearby.find("\"enabled\":false") != string::npos) {
            addChromeFinding(findings,
                             profileName,
                             "Safe Browsing setting",
                             "HIGH",
                             "Safe Browsing appears disabled in this profile",
                             preferencesPath.string());
        }
    }

    if (lower.find("\"default_search_provider\"") != string::npos &&
        lower.find("bing.com") == string::npos &&
        lower.find("google.com") == string::npos &&
        lower.find("duckduckgo.com") == string::npos) {
        addChromeFinding(findings,
                         profileName,
                         "Search provider settings",
                         "LOW",
                         "Default search provider may be custom or uncommon. Review Chrome search settings",
                         preferencesPath.string());
    }
}

void scanChromeProfileExtensions(const fs::path& profilePath,
                                 const string& profileName,
                                 vector<ChromeFinding>& findings) {
    fs::path extensionsPath = profilePath / "Extensions";

    if (!fs::exists(extensionsPath) || !fs::is_directory(extensionsPath)) {
        return;
    }

    try {
        for (const auto& extensionDir : fs::directory_iterator(extensionsPath)) {
            if (!extensionDir.is_directory()) {
                continue;
            }

            string extensionId = extensionDir.path().filename().string();

            for (const auto& versionDir : fs::directory_iterator(extensionDir.path())) {
                if (!versionDir.is_directory()) {
                    continue;
                }

                fs::path manifestPath = versionDir.path() / "manifest.json";
                if (fs::exists(manifestPath)) {
                    scanChromeExtensionManifest(manifestPath, profileName, extensionId, findings);
                }
            }
        }
    } catch (const fs::filesystem_error& error) {
        addChromeFinding(findings,
                         profileName,
                         "Chrome extensions folder",
                         "LOW",
                         string("Could not fully scan extensions folder: ") + error.what(),
                         extensionsPath.string());
    }
}

void scanChromeLocalState(const fs::path& userDataPath, vector<ChromeFinding>& findings) {
    fs::path localStatePath = userDataPath / "Local State";
    string localState = readFileLimited(localStatePath);

    if (localState.empty()) {
        return;
    }

    string lower = toLowerCase(localState);

    if (lower.find("enabled_labs_experiments") != string::npos &&
        lower.find("\"enabled_labs_experiments\":[]") == string::npos) {
        addChromeFinding(findings,
                         "GLOBAL",
                         "Chrome flags",
                         "LOW",
                         "Some experimental Chrome flags appear enabled. Review chrome://flags if browser behavior changed unexpectedly",
                         localStatePath.string());
    }
}

void scanChromeUserDataDirectory(const fs::path& userDataPath, vector<ChromeFinding>& findings) {
    if (!fs::exists(userDataPath) || !fs::is_directory(userDataPath)) {
        return;
    }

    scanChromeLocalState(userDataPath, findings);

    try {
        for (const auto& profileDir : fs::directory_iterator(userDataPath)) {
            if (!isChromeProfileDirectory(profileDir.path())) {
                continue;
            }

            string profileName = profileDir.path().filename().string();
            scanChromeProfilePreferences(profileDir.path(), profileName, findings);
            scanChromeProfileExtensions(profileDir.path(), profileName, findings);
        }
    } catch (const fs::filesystem_error& error) {
        addChromeFinding(findings,
                         "GLOBAL",
                         "Chrome user data folder",
                         "LOW",
                         string("Could not fully scan Chrome user data folder: ") + error.what(),
                         userDataPath.string());
    }
}

void printChromeFindings(const vector<ChromeFinding>& findings, ostream& out) {
    out << "CHROME LOCAL SECURITY CHECK REPORT\n";
    printDivider(out);

    if (findings.empty()) {
        out << "No suspicious Chrome settings or extension permissions were detected by this local scan.\n";
        out << "This does not prove the browser is breach-free. Use Chrome Safety Check / Password Checkup for leaked password checks.\n";
        return;
    }

    int high = 0;
    int medium = 0;
    int low = 0;

    for (const ChromeFinding& finding : findings) {
        if (finding.severity == "HIGH") {
            high++;
        } else if (finding.severity == "MEDIUM") {
            medium++;
        } else {
            low++;
        }
    }

    out << "Total findings: " << findings.size() << "\n";
    out << "High severity:  " << high << "\n";
    out << "Medium severity:" << medium << "\n";
    out << "Low severity:   " << low << "\n";
    printDivider(out);

    out << left
        << setw(10) << "Severity"
        << setw(18) << "Profile"
        << setw(38) << "Item"
        << "Reason\n";

    printDivider(out);

    for (const ChromeFinding& finding : findings) {
        string item = finding.item;
        if (item.size() > 35) {
            item = item.substr(0, 35) + "...";
        }

        out << left
            << setw(10) << finding.severity
            << setw(18) << finding.profile
            << setw(38) << item
            << finding.reason
            << "\n";
    }

    printDivider(out);
    out << "DETAILED FINDINGS\n";
    printDivider(out);

    for (const ChromeFinding& finding : findings) {
        out << "Severity: " << finding.severity << "\n";
        out << "Profile:  " << finding.profile << "\n";
        out << "Item:     " << finding.item << "\n";
        out << "Reason:   " << finding.reason << "\n";
        out << "Location: " << finding.location << "\n";
        printDivider(out);
    }
}

void exportChromeFindingsCsv(const vector<ChromeFinding>& findings, const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not save Chrome CSV file: " << filename << "\n";
        return;
    }

    file << "severity,profile,item,reason,location\n";

    for (const ChromeFinding& finding : findings) {
        file << csvEscape(finding.severity) << ","
             << csvEscape(finding.profile) << ","
             << csvEscape(finding.item) << ","
             << csvEscape(finding.reason) << ","
             << csvEscape(finding.location)
             << "\n";
    }

    file.close();
    cout << "Chrome findings CSV saved to: " << filename << "\n";
}

void runChromeSecurityScan() {
    vector<ChromeFinding> findings;
    vector<fs::path> candidates = getChromeUserDataCandidates();
    vector<fs::path> scannedPaths;

    cout << "\nThis scan reads real local Chrome/Chromium profile files.\n";
    cout << "It checks profile Preferences, Local State, and extension manifests.\n";
    cout << "It does not read saved passwords, cookies, or decrypted secret data.\n\n";

    cout << "Auto-detected Chrome/Chromium data locations:\n";
    if (candidates.empty()) {
        cout << "- No candidate paths could be built from environment variables.\n";
    } else {
        for (const fs::path& candidate : candidates) {
            cout << "- " << candidate.string()
                 << (fs::exists(candidate) && fs::is_directory(candidate) ? " [found]" : " [not found]")
                 << "\n";
        }
    }

    cout << "\nPress Enter to scan detected real locations, or paste a Chrome User Data folder path: ";
    cin.ignore(10000, '\n');

    string manualPath;
    getline(cin, manualPath);
    manualPath = cleanPathInput(manualPath);

    if (!manualPath.empty()) {
        addChromeCandidatePath(candidates, manualPath);
    }

    for (const fs::path& candidate : candidates) {
        if (fs::exists(candidate) && fs::is_directory(candidate)) {
            scannedPaths.push_back(candidate);
            scanChromeUserDataDirectory(candidate, findings);
        }
    }

    cout << "\n";

    if (scannedPaths.empty()) {
        cout << "No Chrome/Chromium user data folder found automatically.\n";
        cout << "On Windows it is usually: %LOCALAPPDATA%\\Google\\Chrome\\User Data\n";
        cout << "You can copy that folder path from File Explorer and paste it when option 3 asks for it.\n";
        cout << "On Linux it is usually: ~/.config/google-chrome\n";
        cout << "On macOS it is usually: ~/Library/Application Support/Google/Chrome\n";
        return;
    }

    cout << "Scanned Chrome/Chromium data paths:\n";
    for (const fs::path& path : scannedPaths) {
        cout << "- " << path.string() << "\n";
    }
    cout << "\n";

    printChromeFindings(findings, cout);

    ofstream reportFile("chrome_security_report.txt");
    if (reportFile.is_open()) {
        reportFile << "Scanned Chrome/Chromium data paths:\n";
        for (const fs::path& path : scannedPaths) {
            reportFile << "- " << path.string() << "\n";
        }
        reportFile << "\n";
        printChromeFindings(findings, reportFile);
        reportFile.close();
        cout << "\nChrome security report saved to: chrome_security_report.txt\n";
    } else {
        cout << "\nError: Could not save chrome_security_report.txt\n";
    }

    exportChromeFindingsCsv(findings, "chrome_findings.csv");
}

void saveSampleLogs(const string& filename) {
    ofstream file(filename);

    if (!file.is_open()) {
        cout << "Error: Could not create sample log file.\n";
        return;
    }

    file << "2026-05-20 10:01:03 192.168.1.8 LOGIN_FAILED admin\n";
    file << "2026-05-20 10:01:09 192.168.1.8 LOGIN_FAILED root\n";
    file << "2026-05-20 10:01:15 192.168.1.8 LOGIN_FAILED test\n";
    file << "2026-05-20 10:02:20 192.168.1.8 LOGIN_SUCCESS admin\n";
    file << "172.16.0.4 - - [20/May/2026:10:08:11 +0300] \"GET /admin HTTP/1.1\" 403 532 \"-\" \"Mozilla/5.0\"\n";
    file << "172.16.0.4 - - [20/May/2026:10:08:14 +0300] \"GET /wp-admin HTTP/1.1\" 404 218 \"-\" \"Mozilla/5.0\"\n";
    file << "172.16.0.4 - - [20/May/2026:10:08:18 +0300] \"GET /.env HTTP/1.1\" 404 214 \"-\" \"Mozilla/5.0\"\n";
    file << "172.16.0.4 - - [20/May/2026:10:08:22 +0300] \"GET /phpmyadmin HTTP/1.1\" 404 220 \"-\" \"Mozilla/5.0\"\n";
    file << "172.16.0.4 - - [20/May/2026:10:08:32 +0300] \"GET /backup.sql HTTP/1.1\" 404 220 \"-\" \"Mozilla/5.0\"\n";
    file << "45.67.89.10 - - [20/May/2026:10:11:30 +0300] \"GET /products?id=1%27%20OR%201=1-- HTTP/1.1\" 500 900 \"-\" \"sqlmap\"\n";
    file << "45.67.89.10 - - [20/May/2026:10:11:38 +0300] \"GET /../../etc/passwd HTTP/1.1\" 400 300 \"-\" \"curl/8.0\"\n";
    file << "May 20 10:20:01 server sshd[1234]: Failed password for invalid user admin from 103.88.12.9 port 54321 ssh2\n";
    file << "May 20 10:20:11 server sshd[1234]: Failed password for invalid user oracle from 103.88.12.9 port 54322 ssh2\n";
    file << "May 20 10:20:24 server sshd[1234]: Failed password for root from 103.88.12.9 port 54323 ssh2\n";
    file << "May 20 10:21:44 server sshd[1235]: Accepted password for root from 103.88.12.9 port 54324 ssh2\n";
    file << "May 20 10:25:01 server sshd[999]: Accepted password for sammy from 10.0.0.5 port 50000 ssh2\n";

    file.close();
    cout << "Sample mixed logs created in: " << filename << "\n";
}

void showSupportedFormats() {
    cout << "\nSupported log formats:\n";
    cout << "1. Custom app logs:\n";
    cout << "   2026-05-20 10:01:03 192.168.1.8 LOGIN_FAILED admin\n";
    cout << "\n2. Apache/Nginx access logs:\n";
    cout << "   45.67.89.10 - - [20/May/2026:10:13:45 +0300] \"GET /admin HTTP/1.1\" 403 532 \"-\" \"Mozilla/5.0\"\n";
    cout << "\n3. Linux auth.log SSH logs:\n";
    cout << "   May 20 10:20:01 server sshd[1234]: Failed password for invalid user admin from 45.67.89.10 port 54321 ssh2\n";
}

void showMenu() {
    cout << "\n=== Cybersecurity Log Analyzer ===\n";
    cout << "1. Create sample mixed log file\n";
    cout << "2. Analyze log file\n";
    cout << "3. Scan local Chrome/Chromium browser profile\n";
    cout << "4. Show supported log formats\n";
    cout << "5. Exit\n";
    cout << "Choose option: ";
}

void runAnalysisWorkflow(const string& filename) {
    vector<LogEntry> logs = loadLogs(filename);

    if (logs.empty()) {
        cout << "No valid supported logs found.\n";
        return;
    }

    map<string, IpStats> results = analyzeLogs(logs);

    cout << "\n";
    generateReport(results, cout);

    cout << "\n";
    generateTimelineView(logs, cout, 30);

    ofstream reportFile("analysis_report.txt");
    if (reportFile.is_open()) {
        generateReport(results, reportFile);
        reportFile << "\n";
        generateTimelineView(logs, reportFile, 1000);
        reportFile.close();
        cout << "\nMain report saved to: analysis_report.txt\n";
    } else {
        cout << "\nError: Could not save main report file.\n";
    }

    exportIpSummaryCsv(results, "ip_summary.csv");
    exportAlertsCsv(results, "alerts.csv");
    exportTimelineCsv(logs, "timeline.csv");
    saveTimelineTxt(logs, "timeline.txt");
}

int main() {
    int choice;

    while (true) {
        showMenu();
        cin >> choice;

        if (cin.fail()) {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "Invalid input. Enter a number.\n";
            continue;
        }

        if (choice == 1) {
            saveSampleLogs("sample_mixed_logs.txt");
        } else if (choice == 2) {
            string filename;
            cout << "Enter log filename: ";
            cin >> filename;
            runAnalysisWorkflow(filename);
        } else if (choice == 3) {
            runChromeSecurityScan();
        } else if (choice == 4) {
            showSupportedFormats();
        } else if (choice == 5) {
            cout << "Exiting analyzer.\n";
            break;
        } else {
            cout << "Invalid option. Try again.\n";
        }
    }

    return 0;
}
