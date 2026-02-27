/*
 * MCP Termux Server v5.0 - Integrated Android Reverse Engineering Edition
 * Full MCP HTTP+SSE server (2024-11-05 / 2025-03-27)
 * Shell (root-aware), SSH, File, SysInfo, Sequential Thinking,
 * Interactive session, stackplz eBPF tracing, paradise_tool memory ops.
 * One binary.
 */
#include "httplib.h"
#include "json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/utsname.h>
using json = nlohmann::json;

/* ══════════ CONSTANTS ══════════ */
static const char* VERSION = "7.0.0";
static const char* PROTO_VER = "2024-11-05";
static const char* TERMUX_PREFIX = "/data/data/com.termux/files/usr";
static const char* TERMUX_HOME = "/data/data/com.termux/files/home";
static const char* TERMUX_TMP = "/data/data/com.termux/files/usr/tmp";
static const char* TERMUX_BASH = "/data/data/com.termux/files/usr/bin/bash";

/* Tool paths - computed relative to binary location */
static std::string g_self_dir;  // set in main()

static std::string get_self_dir() {
    char buf[1024] = {};
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len > 0) {
        buf[len] = 0;
        std::string s(buf);
        auto pos = s.rfind('/');
        return pos != std::string::npos ? s.substr(0, pos) : ".";
    }
    return ".";
}

// Accessor functions (use g_self_dir set at startup)
static std::string stackplz_path() { return g_self_dir + "/stackplz"; }
static std::string paradise_path() { return g_self_dir + "/paradise"; }
static std::string r2_bin()        { return g_self_dir + "/radare2/bin/radare2"; }
static std::string r2_lib()        { return g_self_dir + "/radare2/lib"; }
static std::string r2_prefix()     { return g_self_dir + "/radare2"; }
static std::string rabin2_bin()    { return g_self_dir + "/radare2/bin/rabin2"; }
static std::string rasm2_bin()     { return g_self_dir + "/radare2/bin/rasm2"; }

/* ══════════ LOGGING ══════════ */
static std::mutex g_log_mtx;
enum LogLevel { LOG_DEBUG=0, LOG_INFO=1, LOG_WARN=2, LOG_ERROR=3 };
static LogLevel g_log_level = LOG_INFO;

static void log_msg(LogLevel lv, const char* tag, const std::string& m) {
    if (lv < g_log_level) return;
    static const char* L[] = {"DBG","INF","WRN","ERR"};
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char tb[20];
    std::strftime(tb, sizeof(tb), "%H:%M:%S", std::localtime(&t));
    std::lock_guard<std::mutex> lk(g_log_mtx);
    std::cerr << "[" << tb << "][" << L[lv] << "][" << tag << "] " << m << "\n" << std::flush;
}
#define LOGI(t,m) log_msg(LOG_INFO,t,m)
#define LOGW(t,m) log_msg(LOG_WARN,t,m)
#define LOGE(t,m) log_msg(LOG_ERROR,t,m)
#define LOGD(t,m) log_msg(LOG_DEBUG,t,m)

/* ══════════ CONFIG ══════════ */
struct Config {
    std::string host = "0.0.0.0";
    int port = 65534;
    int timeout_sec = 120;
    size_t max_out = 16 * 1024 * 1024;
    std::string work_dir = TERMUX_HOME;
    std::string ssh_host = "127.0.0.1";
    int ssh_port = 8022;
    std::string ssh_user = "root";
    std::string ssh_pass = "123456";
    std::string ssh_key;
};

/* ══════════ UTILS ══════════ */
static std::string gen_id() {
    static std::mt19937_64 rng{std::random_device{}()};
    std::ostringstream o;
    o << std::hex << std::setfill('0') << std::setw(16) << rng() << std::setw(16) << rng();
    return o.str();
}

static std::string trim(const std::string& s) {
    auto l = s.find_first_not_of(" \t\r\n");
    if (l == std::string::npos) return "";
    return s.substr(l, s.find_last_not_of(" \t\r\n") - l + 1);
}

static std::string b64enc(const std::string& in) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    o.reserve((in.size() + 2) / 3 * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t v = (uint8_t)in[i] << 16;
        if (i + 1 < in.size()) v |= (uint8_t)in[i + 1] << 8;
        if (i + 2 < in.size()) v |= (uint8_t)in[i + 2];
        o += T[(v >> 18) & 63];
        o += T[(v >> 12) & 63];
        o += (i + 1 < in.size()) ? T[(v >> 6) & 63] : '=';
        o += (i + 2 < in.size()) ? T[v & 63] : '=';
    }
    return o;
}

static std::string sq_esc(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '\'') r += "'\\''";
        else r += c;
    }
    return r;
}

static std::string wrap_root_cmd(const std::string& cmd) {
    std::string tmpf = std::string(TERMUX_TMP) + "/_mcp_cmd_" + gen_id().substr(0,8) + ".sh";
    std::string script = "#!/data/data/com.termux/files/usr/bin/bash\n"
                        "export PATH=" + std::string(TERMUX_PREFIX) + "/bin:" +
                        std::string(TERMUX_PREFIX) + "/bin/applets:/sbin:/system/bin:/system/xbin\n"
                        "export HOME=" + std::string(TERMUX_HOME) + "\n"
                        "export TMPDIR=" + std::string(TERMUX_TMP) + "\n"
                        "export PREFIX=" + std::string(TERMUX_PREFIX) + "\n"
                        "export LANG=en_US.UTF-8\n" + cmd + "\n";
    std::ofstream sf(tmpf, std::ios::binary);
    if (sf) {
        sf.write(script.data(), script.size());
        sf.close();
        chmod(tmpf.c_str(), 0755);
    }
    return "su -c '" + tmpf + "'; rm -f '" + tmpf + "'";
}

static std::string find_bash() {
    if (access(TERMUX_BASH, X_OK) == 0) return TERMUX_BASH;
    if (access("/bin/bash", X_OK) == 0) return "/bin/bash";
    return "/bin/sh";
}

/* ══════════ JSON HELPERS ══════════ */
static json mkerr(int c, const std::string& m, json id = nullptr) {
    return {{"jsonrpc","2.0"}, {"id",id}, {"error",{{"code",c},{"message",m}}}};
}
static json mkres(json id, json result) {
    return {{"jsonrpc","2.0"}, {"id",id}, {"result",result}};
}
static json tcontent(const std::string& t) {
    return json::array({{{"type","text"}, {"text",t}}});
}
static json tok(const std::string& t) {
    return {{"content",tcontent(t)}, {"isError",false}};
}
static json terr(const std::string& t) {
    return {{"content",tcontent(t)}, {"isError",true}};
}
static json tjson(const json& j, bool e = false) {
    return {{"content",tcontent(j.dump(2))}, {"isError",e}};
}

/* ══════════ EXEC ENGINE ══════════ */
struct ExecResult {
    std::string out, err;
    int exit_code = -1;
    bool timed_out = false;
    std::string errmsg;
};

static ExecResult exec_cmd(const std::string& cmd, int tsec, size_t maxb,
                           const std::string& cwd = "") {
    ExecResult R;
    if (cmd.empty()) { R.errmsg = "Empty command"; return R; }

    int po[2], pe[2];
    if (pipe(po) || pipe(pe)) {
        R.errmsg = "pipe: " + std::string(strerror(errno));
        return R;
    }

    pid_t pid = fork();
    if (pid < 0) {
        R.errmsg = "fork: " + std::string(strerror(errno));
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        return R;
    }

    if (pid == 0) {
        close(po[0]); close(pe[0]);
        dup2(po[1], STDOUT_FILENO);
        dup2(pe[1], STDERR_FILENO);
        close(po[1]); close(pe[1]);
        if (!cwd.empty()) chdir(cwd.c_str());
        setsid();
        std::string path = std::string(TERMUX_PREFIX) + "/bin:" +
                          std::string(TERMUX_PREFIX) + "/bin/applets:" +
                          "/sbin:/system/bin:/system/xbin";
        setenv("PATH", path.c_str(), 1);
        setenv("HOME", TERMUX_HOME, 1);
        setenv("TMPDIR", TERMUX_TMP, 1);
        setenv("PREFIX", TERMUX_PREFIX, 1);
        setenv("LANG", "en_US.UTF-8", 1);
        std::string bash = find_bash();
        execl(bash.c_str(), "bash", "-c", cmd.c_str(), nullptr);
        _exit(127);
    }

    close(po[1]); close(pe[1]);
    fcntl(po[0], F_SETFL, O_NONBLOCK);
    fcntl(pe[0], F_SETFL, O_NONBLOCK);

    auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(tsec);
    bool o_open = true, e_open = true;

    while (o_open || e_open) {
        auto now = std::chrono::steady_clock::now();
        if (now >= dl) {
            R.timed_out = true;
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            break;
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dl - now).count();

        struct pollfd pf[2];
        int nf = 0;
        if (o_open) pf[nf++] = {po[0], POLLIN | POLLHUP, 0};
        if (e_open) pf[nf++] = {pe[0], POLLIN | POLLHUP, 0};
        poll(pf, nf, (int)std::min(ms, (long long)200));

        char tmp[8192];
        if (o_open) {
            ssize_t n = read(po[0], tmp, sizeof(tmp));
            if (n > 0) {
                if (R.out.size() < maxb)
                    R.out.append(tmp, std::min((size_t)n, maxb - R.out.size()));
            } else if (n == 0) {
                o_open = false;
            }
        }
        if (e_open) {
            ssize_t n = read(pe[0], tmp, sizeof(tmp));
            if (n > 0) {
                if (R.err.size() < maxb)
                    R.err.append(tmp, std::min((size_t)n, maxb - R.err.size()));
            } else if (n == 0) {
                e_open = false;
            }
        }
    }

    close(po[0]); close(pe[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    R.exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (R.timed_out) R.errmsg = "Timed out after " + std::to_string(tsec) + "s";
    return R;
}

static std::string build_ssh(const Config& c, const std::string& cmd) {
    std::string encoded = b64enc(cmd);
    std::string key_part = c.ssh_key.empty() ? "" : " -i " + c.ssh_key;
    return "sshpass -p '" + sq_esc(c.ssh_pass) + "'"
           " ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
           " -o ConnectTimeout=10" + key_part +
           " -p " + std::to_string(c.ssh_port) +
           " " + c.ssh_user + "@" + c.ssh_host +
           " \"$(echo " + encoded + " | base64 -d)\"";
}

/* ══════════ INTERACTIVE SESSION MANAGER ══════════ */
struct InteractiveSession {
    pid_t pid = -1;
    int master_fd = -1;
    std::string id;
    std::string cmd_name;
    std::mutex mtx;
    std::chrono::steady_clock::time_point last_active;
    std::atomic<bool> alive{true};
};

static std::mutex g_sess_mtx;
static std::unordered_map<std::string, std::shared_ptr<InteractiveSession>> g_sessions;

static std::shared_ptr<InteractiveSession> create_session(const std::string& cmd,
                                                           const std::string& cwd) {
    auto s = std::make_shared<InteractiveSession>();
    s->id = gen_id();
    s->cmd_name = cmd;
    s->last_active = std::chrono::steady_clock::now();

    int master;
    pid_t pid = forkpty(&master, nullptr, nullptr, nullptr);
    if (pid < 0) return nullptr;

    if (pid == 0) {
        if (!cwd.empty()) chdir(cwd.c_str());
        setenv("TERM", "xterm-256color", 1);
        setenv("LANG", "en_US.UTF-8", 1);
        std::string path = std::string(TERMUX_PREFIX) + "/bin:" +
                          std::string(TERMUX_PREFIX) + "/bin/applets:" +
                          "/sbin:/system/bin:/system/xbin";
        setenv("PATH", path.c_str(), 1);
        setenv("HOME", TERMUX_HOME, 1);
        std::string bash = find_bash();
        execl(bash.c_str(), "bash", "-c", cmd.c_str(), nullptr);
        _exit(127);
    }

    s->pid = pid;
    s->master_fd = master;
    fcntl(master, F_SETFL, O_NONBLOCK);
    {
        std::lock_guard<std::mutex> lk(g_sess_mtx);
        g_sessions[s->id] = s;
    }
    LOGI("Sess", "Created session " + s->id.substr(0,8) + " cmd=" + cmd.substr(0,60));
    return s;
}

static std::string session_read(std::shared_ptr<InteractiveSession> s, int wait_ms = 500) {
    std::lock_guard<std::mutex> lk(s->mtx);
    s->last_active = std::chrono::steady_clock::now();
    std::string result;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);

    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pf = {s->master_fd, POLLIN, 0};
        int left = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        poll(&pf, 1, std::min(left, 100));

        char tmp[4096];
        ssize_t n = read(s->master_fd, tmp, sizeof(tmp));
        if (n > 0) {
            result.append(tmp, n);
        } else if (n == 0) {
            s->alive = false;
            break;
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                s->alive = false;
                break;
            }
        }
    }
    return result;
}

static bool session_write(std::shared_ptr<InteractiveSession> s, const std::string& input) {
    std::lock_guard<std::mutex> lk(s->mtx);
    s->last_active = std::chrono::steady_clock::now();
    ssize_t n = write(s->master_fd, input.c_str(), input.size());
    return n > 0;
}

static void session_kill(std::shared_ptr<InteractiveSession> s) {
    if (s->pid > 0) {
        kill(s->pid, SIGKILL);
        waitpid(s->pid, nullptr, WNOHANG);
        s->pid = -1;
    }
    if (s->master_fd >= 0) {
        close(s->master_fd);
        s->master_fd = -1;
    }
    s->alive = false;
    LOGI("Sess", "Killed session " + s->id.substr(0,8));
}

/* ══════════ JOB MANAGER ══════════ */
struct Job {
    std::mutex mtx;
    std::condition_variable cv;
    ExecResult result;
    bool done = false;
    std::string cmd_desc;
    std::chrono::system_clock::time_point created = std::chrono::system_clock::now();
};

static std::mutex g_jmtx;
static std::unordered_map<std::string, std::shared_ptr<Job>> g_jobs;
static std::atomic<bool> g_stop{false};

static std::string submit(const std::string& desc, std::function<ExecResult()> fn) {
    auto id = gen_id();
    auto j = std::make_shared<Job>();
    j->cmd_desc = desc;
    {std::lock_guard<std::mutex> lk(g_jmtx); g_jobs[id] = j;}
    std::thread([j, fn = std::move(fn)]() {
        ExecResult r = fn();
        std::lock_guard<std::mutex> lk(j->mtx);
        j->result = std::move(r);
        j->done = true;
        j->cv.notify_all();
    }).detach();
    return id;
}

static std::shared_ptr<Job> get_job(const std::string& id) {
    std::lock_guard<std::mutex> lk(g_jmtx);
    auto it = g_jobs.find(id);
    return it != g_jobs.end() ? it->second : nullptr;
}

static void cleanup_jobs() {
    auto now = std::chrono::system_clock::now();
    std::vector<std::string> dead;
    std::lock_guard<std::mutex> lk(g_jmtx);
    for (auto& kv : g_jobs) {
        std::unique_lock<std::mutex> jl(kv.second->mtx, std::try_to_lock);
        if (!jl.owns_lock()) continue;
        auto age = std::chrono::duration_cast<std::chrono::minutes>(now - kv.second->created).count();
        if (kv.second->done && age > 30) dead.push_back(kv.first);
    }
    for (auto& id : dead) { g_jobs.erase(id); LOGI("Jobs", "Cleaned: " + id.substr(0,8)); }
}

static void cleanup_sessions() {
    auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<std::string, std::shared_ptr<InteractiveSession>>> dead;
    {
        std::lock_guard<std::mutex> lk(g_sess_mtx);
        for (auto& kv : g_sessions) {
            auto age = std::chrono::duration_cast<std::chrono::minutes>(
                now - kv.second->last_active).count();
            if (!kv.second->alive || age > 30)
                dead.push_back({kv.first, kv.second});
        }
        for (auto& p : dead) g_sessions.erase(p.first);
    }
    for (auto& p : dead) {
        std::lock_guard<std::mutex> lk(p.second->mtx);
        session_kill(p.second);
    }
}

/* ══════════ SEQUENTIAL THINKING ══════════ */
struct Thought {
    std::string text;
    int num = 0, total = 0;
    bool is_rev = false;
    int revises = 0;
    bool has_branch = false;
    int branch_from = 0;
    std::string branch_id;
    bool needs_more = false;
};

struct ThinkSess {
    std::vector<Thought> hist;
    std::map<std::string, std::vector<int>> branches;
};

static std::unordered_map<std::string, ThinkSess> g_tsess;
static std::mutex g_tmtx;

static std::string tbox(const Thought& t) {
    std::string hdr;
    if (t.is_rev)
        hdr = "Revision of #" + std::to_string(t.revises);
    else if (t.has_branch)
        hdr = "Branch '" + t.branch_id + "' from #" + std::to_string(t.branch_from);
    else
        hdr = "Thought " + std::to_string(t.num) + "/" + std::to_string(t.total);

    const int W = 60;
    std::string line(W, '-');
    std::ostringstream o;
    o << "\n+" << line << "+\n";
    int pad = std::max(0, (W - (int)hdr.size()) / 2);
    o << "|" << std::string(pad, ' ') << hdr
      << std::string(std::max(0, W - (int)hdr.size() - pad), ' ') << "|\n";
    o << "+" << line << "+\n";

    std::string body = t.text;
    for (size_t pos = 0; pos < body.size();) {
        size_t end = pos + (W - 2);
        if (end >= body.size()) end = body.size();
        else {
            size_t nl = body.find('\n', pos);
            if (nl != std::string::npos && nl < end) end = nl;
            else { size_t sp = body.rfind(' ', end); if (sp > pos) end = sp; }
        }
        std::string ln = body.substr(pos, end - pos);
        o << "| " << ln << std::string(std::max(0, W - 2 - (int)ln.size()), ' ') << "|\n";
        pos = end;
        if (pos < body.size() && (body[pos] == '\n' || body[pos] == ' ')) pos++;
    }
    o << "+" << line << "+\n";
    return o.str();
}

static json do_think(const json& a, const std::string& sid) {
    auto gs = [&](const char* k, const std::string& d = "") -> std::string {
        return a.contains(k) && a[k].is_string() ? a[k].get<std::string>() : d;
    };
    auto gi = [&](const char* k, int d = 0) -> int {
        return a.contains(k) && a[k].is_number() ? a[k].get<int>() : d;
    };
    auto gb = [&](const char* k, bool d = false) -> bool {
        return a.contains(k) && a[k].is_boolean() ? a[k].get<bool>() : d;
    };

    Thought t;
    t.text = gs("thought");
    t.num = gi("thoughtNumber", 1);
    t.total = gi("totalThoughts", 1);
    t.is_rev = gb("isRevision");
    t.revises = gi("revisesThought");
    t.needs_more = gb("needsMoreThoughts");
    t.branch_id = gs("branchId");
    if (a.contains("branchFromThought") && a["branchFromThought"].is_number()) {
        t.has_branch = true;
        t.branch_from = a["branchFromThought"].get<int>();
    }
    if (t.text.empty()) return terr("thought field required");
    if (t.num < 1) t.num = 1;
    if (t.total < t.num) t.total = t.num;

    std::lock_guard<std::mutex> lk(g_tmtx);
    auto& sess = g_tsess[sid];
    if (t.is_rev && t.revises >= 1 && t.revises <= (int)sess.hist.size())
        sess.hist[t.revises - 1] = t;
    else
        sess.hist.push_back(t);
    if (t.has_branch && !t.branch_id.empty())
        sess.branches[t.branch_id].push_back((int)sess.hist.size() - 1);

    std::string box = tbox(t);
    std::cerr << box << std::flush;

    bool nxt = t.needs_more || (t.num < t.total);
    bool next_needed = gb("nextThoughtNeeded", nxt);

    json bj = json::object();
    for (auto& kv : sess.branches) bj[kv.first] = json(kv.second);

    json meta = {
        {"session_id", sid}, {"thoughtNumber", t.num}, {"totalThoughts", t.total},
        {"nextThoughtNeeded", next_needed}, {"thoughtHistoryLength", (int)sess.hist.size()},
        {"branches", bj}
    };

    std::string txt = box + "\nThought " + std::to_string(t.num) + "/" + std::to_string(t.total);
    txt += next_needed ? "\n> Continue thinking..." : "\n> Thinking complete.";
    return {{"content", tcontent(txt)}, {"isError", false}, {"_meta", meta}};
}

/* ══════════ ROOT DETECTION (cached) ══════════ */
static int g_has_root = -1;
static std::mutex g_root_mtx;

static bool check_root() {
    std::lock_guard<std::mutex> lk(g_root_mtx);
    if (g_has_root >= 0) return g_has_root == 1;
    auto r = exec_cmd("su -c 'id' 2>/dev/null", 5, 512);
    g_has_root = (r.exit_code == 0 && r.out.find("uid=0") != std::string::npos) ? 1 : 0;
    LOGI("Root", std::string("Root detection: ") +
         (g_has_root == 1 ? "available" : "unavailable"));
    return g_has_root == 1;
}

/* ══════════ HELPER: run tool with root ══════════ */
static ExecResult run_root_cmd(const std::string& cmd, int timeout, size_t maxout) {
    std::string final_cmd = cmd;
    if (check_root()) {
        final_cmd = wrap_root_cmd(cmd);
    }
    return exec_cmd(final_cmd, timeout, maxout);
}

/* ══════════ TOOL LIST ══════════ */
static json get_tools() {
    return json::array({
      /* ─── Original v4.0 Tools ─── */
      {{"name","shell_exec"},
       {"description",
        "Execute shell command in Termux. Auto-uses root (su) when available. "
        "Commands are passed via base64 to avoid escaping issues. "
        "Can find PID of any Android app: shell_exec({command:\"pidof com.tencent.mobileqq\"}) or "
        "shell_exec({command:\"ps -A | grep tencent\"}). "
        "Set root=false to run as Termux user."},
       {"inputSchema",{{"type","object"},{"required",{"command"}},{"properties",{
         {"command",{{"type","string"},{"description","Shell command (any complexity, no escaping needed)"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout in seconds (max 600)"}}},
         {"workdir",{{"type","string"},{"description","Working directory"}}},
         {"root",{{"type","boolean"},{"default",true},{"description","Use root via su if available"}}}
       }}}}},
      {{"name","shell_exec_async"},
       {"description","Run command in background, returns job_id to poll with job_status."},
       {"inputSchema",{{"type","object"},{"required",{"command"}},{"properties",{
         {"command",{{"type","string"}}},
         {"timeout",{{"type","integer"},{"default",120}}}
       }}}}},
      {{"name","job_status"},
       {"description","Get async job result by job_id."},
       {"inputSchema",{{"type","object"},{"required",{"job_id"}},{"properties",{
         {"job_id",{{"type","string"}}}
       }}}}},
      {{"name","job_list"},
       {"description","List all async jobs with status."},
       {"inputSchema",{{"type","object"},{"properties",json::object()}}}},
      {{"name","ssh_exec"},
       {"description",
        "Execute command via SSH (runs as root). Uses base64 encoding for safe "
        "command transmission. Alternative root channel."},
       {"inputSchema",{{"type","object"},{"required",{"command"}},{"properties",{
         {"command",{{"type","string"}}},
         {"host",{{"type","string"}}},
         {"port",{{"type","integer"}}},
         {"user",{{"type","string"}}},
         {"timeout",{{"type","integer"},{"default",60}}}
       }}}}},
      {{"name","interactive_session"},
       {"description",
        "Manage interactive PTY sessions (python, top, vim, etc). "
        "Actions: start|send|read|kill|list. "
        "start: {action:\"start\", command:\"python3\"} -> returns session_id. "
        "send: {action:\"send\", session_id:\"...\", input:\"print(123)\\n\"}. "
        "read: {action:\"read\", session_id:\"...\", timeout:3000}. "
        "kill: {action:\"kill\", session_id:\"...\"}. "
        "list: {action:\"list\"}."},
       {"inputSchema",{{"type","object"},{"required",{"action"}},{"properties",{
         {"action",{{"type","string"},{"enum",{"start","send","read","kill","list"}}}},
         {"command",{{"type","string"},{"description","Command for start"}}},
         {"session_id",{{"type","string"},{"description","Session ID"}}},
         {"input",{{"type","string"},{"description","Input text (include \\n for enter)"}}},
         {"workdir",{{"type","string"},{"description","Working directory for start"}}},
         {"timeout",{{"type","integer"},{"default",2000},{"description","Read timeout ms"}}}
       }}}}},
      {{"name","file_read"},
       {"description","Read file content. encoding: text or base64."},
       {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
         {"path",{{"type","string"}}},
         {"encoding",{{"type","string"},{"default","text"}}}
       }}}}},
      {{"name","file_write"},
       {"description","Write file. encoding: text or base64. append: bool."},
       {"inputSchema",{{"type","object"},{"required",{"path","content"}},{"properties",{
         {"path",{{"type","string"}}},
         {"content",{{"type","string"}}},
         {"encoding",{{"type","string"},{"default","text"}}},
         {"append",{{"type","boolean"},{"default",false}}}
       }}}}},
      {{"name","file_list"},
       {"description","List directory contents with size and type."},
       {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
         {"path",{{"type","string"}}},
         {"show_hidden",{{"type","boolean"},{"default",false}}}
       }}}}},
      {{"name","file_delete"},
       {"description","Delete file or directory."},
       {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
         {"path",{{"type","string"}}},
         {"recursive",{{"type","boolean"},{"default",false}}}
       }}}}},
      {{"name","sys_info"},
       {"description","System info: OS, CPU, memory, disk, Android props, root status."},
       {"inputSchema",{{"type","object"},{"properties",json::object()}}}},
      {{"name","process_list"},
       {"description","List running processes (uses root when available). Optional filter."},
       {"inputSchema",{{"type","object"},{"properties",{
         {"filter",{{"type","string"},{"description","Filter keyword (grep)"}}}
       }}}}},
      {{"name","sequentialthinking"},
       {"description",
        "Step-by-step thinking with revision and branching.\n"
        "Required: thought, thoughtNumber, totalThoughts, nextThoughtNeeded.\n"
        "Optional: isRevision, revisesThought, branchFromThought, branchId, needsMoreThoughts."},
       {"inputSchema",{{"type","object"},
         {"required",{"thought","thoughtNumber","totalThoughts","nextThoughtNeeded"}},
         {"properties",{
           {"thought",{{"type","string"}}},
           {"thoughtNumber",{{"type","integer"},{"minimum",1}}},
           {"totalThoughts",{{"type","integer"},{"minimum",1}}},
           {"nextThoughtNeeded",{{"type","boolean"}}},
           {"isRevision",{{"type","boolean"}}},
           {"revisesThought",{{"type","integer"}}},
           {"branchFromThought",{{"type","integer"}}},
           {"branchId",{{"type","string"}}},
           {"needsMoreThoughts",{{"type","boolean"}}}
         }}}}},

      /* ─── stackplz: eBPF Tracing (15 tools) ─── */

      /* === trace_syscall === */
      {{"name","trace_syscall"},
       {"description",
        "\xf0\x9f\x94\xac [Syscall Trace] \xe8\xbf\xbd\xe8\xb8\xaa Android \xe5\xba\x94\xe7\x94\xa8\xe7\x9a\x84\xe7\xb3\xbb\xe7\xbb\x9f\xe8\xb0\x83\xe7\x94\xa8\xe3\x80\x82\xe5\x9f\xba\xe4\xba\x8e eBPF\xef\xbc\x8c\xe5\xaf\xb9\xe7\x9b\xae\xe6\xa0\x87\xe8\xbf\x9b\xe7\xa8\x8b\xe5\xbd\xb1\xe5\x93\x8d\xe6\x9e\x81\xe5\xb0\x8f\xe3\x80\x82\n"
        "\xe5\x8a\x9f\xe8\x83\xbd\xef\xbc\x9a\xe7\x9b\x91\xe6\x8e\xa7\xe7\x9b\xae\xe6\xa0\x87 App \xe7\x9a\x84\xe6\x89\x80\xe6\x9c\x89\xe7\xb3\xbb\xe7\xbb\x9f\xe8\xb0\x83\xe7\x94\xa8\xef\xbc\x8c\xe6\x8d\x95\xe8\x8e\xb7\xe5\x8f\x82\xe6\x95\xb0\xe3\x80\x81\xe8\xbf\x94\xe5\x9b\x9e\xe5\x80\xbc\xe3\x80\x81\xe5\xa0\x86\xe6\xa0\x88\xe3\x80\x82\n"
        "\n"
        "COMMON SYSCALLS:\n"
        "  \xe6\x96\x87\xe4\xbb\xb6: openat, read, write, close, fstat, lstat, readlinkat, faccessat, unlinkat\n"
        "  \xe7\xbd\x91\xe7\xbb\x9c: connect, sendto, recvfrom, socket, bind, listen, accept4\n"
        "  \xe8\xbf\x9b\xe7\xa8\x8b: clone, execve, kill, exit_group, wait4, getpid, gettid\n"
        "  \xe5\x86\x85\xe5\xad\x98: mmap, mprotect, munmap, brk, madvise\n"
        "  \xe4\xbf\xa1\xe5\x8f\xb7: rt_sigaction, rt_sigprocmask, rt_sigreturn\n"
        "  \xe5\x85\xb6\xe4\xbb\x96: ioctl, prctl, futex, clock_gettime\n"
        "\n"
        "\xe5\x8f\xaf\xe7\x94\xa8\xe9\x80\x89\xe9\xa1\xb9:\n"
        "  syscall: \xe9\x80\x97\xe5\x8f\xb7\xe5\x88\x86\xe9\x9a\x94\xe7\x9a\x84 syscall \xe5\x90\x8d\xe7\xa7\xb0\xef\xbc\x8c\xe5\xa6\x82 'openat,read,write'\n"
        "  no_syscall: \xe9\xbb\x91\xe5\x90\x8d\xe5\x8d\x95\xef\xbc\x8c\xe6\x8e\x92\xe9\x99\xa4\xe4\xb8\x8d\xe9\x9c\x80\xe8\xa6\x81\xe7\x9a\x84 syscall\xef\xbc\x8c\xe6\x9c\x80\xe5\xa4\x9a" "20\xe4\xb8\xaa\n"
        "  filter: \xe5\x8f\x82\xe6\x95\xb0\xe8\xbf\x87\xe6\xbb\xa4\xe8\xa7\x84\xe5\x88\x99\xef\xbc\x8c\xe5\xa6\x82\xe5\x8f\xaa\xe6\x8d\x95\xe8\x8e\xb7\xe7\x89\xb9\xe5\xae\x9a\xe6\x96\x87\xe4\xbb\xb6\xe8\xb7\xaf\xe5\xbe\x84\n"
        "  stack: \xe8\xbe\x93\xe5\x87\xba\xe5\xa0\x86\xe6\xa0\x88\xe5\x9b\x9e\xe6\xba\xaf\xef\xbc\x88\xe6\x9f\xa5\xe8\xb0\x81\xe8\xb0\x83\xe7\x94\xa8\xe4\xba\x86\xe8\xbf\x99\xe4\xb8\xaa syscall\xef\xbc\x89\n"
        "  regs: \xe8\xbe\x93\xe5\x87\xba\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe4\xbf\xa1\xe6\x81\xaf\n"
        "  json_fmt: JSON\xe6\xa0\xbc\xe5\xbc\x8f\xe8\xbe\x93\xe5\x87\xba\xef\xbc\x8c\xe6\x96\xb9\xe4\xbe\xbf\xe7\xa8\x8b\xe5\xba\x8f\xe8\xa7\xa3\xe6\x9e\x90\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", syscall:\"openat\"}\n"
        "  {name:\"com.game\", syscall:\"openat,read,write\", no_syscall:\"ioctl,futex\"}\n"
        "  {name:\"com.game\", syscall:\"openat\", stack:true, json_fmt:true}\n"
        "  {name:\"com.game\", syscall:\"connect,sendto,recvfrom\", regs:true}"},
       {"inputSchema",{{"type","object"},{"required",{"name","syscall"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name (e.g. com.game.app)"}}},
         {"syscall",{{"type","string"},{"description","Syscall names, comma-separated: 'openat' or 'openat,read,write'"}}},
         {"no_syscall",{{"type","string"},{"description","Syscall blacklist, comma-separated (max 20)"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}},{"description","Arg filter rules (e.g. match specific file path)"}}},
         {"pid",{{"type","string"},{"description","PID whitelist"}}},{"tid",{{"type","string"},{"description","TID whitelist"}}},
         {"tname",{{"type","string"},{"description","Thread name whitelist"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"},{"description","Save log to file path"}}},
         {"json_fmt",{{"type","boolean"},{"default",false},{"description","Output as JSON"}}},
         {"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false},{"description","Enable stack unwinding"}}},
         {"stack_size",{{"type","integer"},{"description","Stack dump bytes (default 8192, max 65528)"}}},
         {"regs",{{"type","boolean"},{"default",false},{"description","Show all registers"}}},
         {"getoff",{{"type","boolean"},{"default",false},{"description","Calculate PC/LR module offset"}}},
         {"buffer",{{"type","integer"},{"description","Perf buffer size in MB (default 8)"}}},
         {"timeout",{{"type","integer"},{"default",60},{"description","Trace duration in seconds"}}}
       }}}}},

      /* === trace_uprobe === */
      {{"name","trace_uprobe"},
       {"description",
        "\xf0\x9f\x8e\xa3 [Uprobe Hook] Hook .so \xe5\xba\x93\xe5\x87\xbd\xe6\x95\xb0\xef\xbc\x8c\xe6\x8d\x95\xe8\x8e\xb7\xe5\x8f\x82\xe6\x95\xb0\xe5\x80\xbc\xe3\x80\x82\xe5\x9f\xba\xe4\xba\x8e eBPF uprobe\xe3\x80\x82\n"
        "\n"
        "POINT SYNTAX: 'symbol+offset[type1,type2,...]'\n"
        "  symbol: \xe5\x87\xbd\xe6\x95\xb0\xe7\xac\xa6\xe5\x8f\xb7\xe5\x90\x8d (e.g. open, strstr, il2cpp_string_new)\n"
        "  +offset: \xe5\x8f\xaf\xe9\x80\x89\xe5\x81\x8f\xe7\xa7\xbb (e.g. +0x0)\n"
        "  [types]: \xe5\x8f\x82\xe6\x95\xb0\xe7\xb1\xbb\xe5\x9e\x8b\xe5\x88\x97\xe8\xa1\xa8\xef\xbc\x8c\xe7\xa9\xba\xe5\x88\x99\xe4\xb8\x8d\xe8\xa7\xa3\xe6\x9e\x90\xe5\x8f\x82\xe6\x95\xb0\n"
        "\n"
        "ARGUMENT TYPES:\n"
        "  str     - \xe5\xad\x97\xe7\xac\xa6\xe4\xb8\xb2\xe6\x8c\x87\xe9\x92\x88\xef\xbc\x8c\xe8\x87\xaa\xe5\x8a\xa8\xe8\xaf\xbb\xe5\x8f\x96\xe5\x86\x85\xe5\xae\xb9 (e.g. \xe6\x96\x87\xe4\xbb\xb6\xe8\xb7\xaf\xe5\xbe\x84\xe3\x80\x81URL)\n"
        "  int     - \xe6\x9c\x89\xe7\xac\xa6\xe5\x8f\xb7\xe6\x95\xb4\xe6\x95\xb0 (fd, flags, etc.)\n"
        "  uint    - \xe6\x97\xa0\xe7\xac\xa6\xe5\x8f\xb7\xe6\x95\xb4\xe6\x95\xb0\n"
        "  uint64  - 64\xe4\xbd\x8d\xe6\x97\xa0\xe7\xac\xa6\xe5\x8f\xb7\xe6\x95\xb4\xe6\x95\xb0 (size_t, \xe5\x9c\xb0\xe5\x9d\x80)\n"
        "  ptr     - \xe6\x8c\x87\xe9\x92\x88\xef\xbc\x8c\xe6\x98\xbe\xe7\xa4\xba\xe5\x8d\x81\xe5\x85\xad\xe8\xbf\x9b\xe5\x88\xb6\xe5\x9c\xb0\xe5\x9d\x80\n"
        "  buf:N   - \xe7\xbc\x93\xe5\x86\xb2\xe5\x8c\xba\xef\xbc\x8c\xe8\xaf\xbb\xe5\x8f\x96N\xe5\xad\x97\xe8\x8a\x82 (e.g. buf:128)\n"
        "  str_arr - \xe5\xad\x97\xe7\xac\xa6\xe4\xb8\xb2\xe6\x95\xb0\xe7\xbb\x84 (char**\xef\xbc\x8c\xe5\xa6\x82 execve \xe7\x9a\x84 argv)\n"
        "\n"
        "\xe6\xb3\xa8\xe6\x84\x8f: str_arr \xe9\x9c\x80\xe8\xa6\x81 maxop>=192\n"
        "\xe6\xb3\xa8\xe6\x84\x8f: \xe9\xbb\x98\xe8\xae\xa4 hook libc.so\xef\xbc\x8c\xe5\x8f\xaf\xe9\x80\x9a\xe8\xbf\x87 lib \xe5\x8f\x82\xe6\x95\xb0\xe6\x8c\x87\xe5\xae\x9a\xe5\x85\xb6\xe4\xbb\x96\xe5\xba\x93\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"strstr+0x0[str,str]\"]}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"write[int,buf:128,int]\"]}\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", point:[\"il2cpp_string_new[str]\"], regs:true}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"execve[str,str_arr,str_arr]\"], maxop:192}"},
       {"inputSchema",{{"type","object"},{"required",{"name","point"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"default","libc.so"},{"description","Library to hook (default libc.so). Can be full path or just name."}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook point specs. Format: 'symbol+offset[type1,type2]'"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}},{"description","Arg value filter rules"}}},
         {"maxop",{{"type","integer"},{"description","Max eBPF ops. Default 64. Use 192+ for str_arr type."}}},
         {"dumpret",{{"type","boolean"},{"default",false},{"description","Also show return address offset"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"stack_size",{{"type","integer"}}},
         {"regs",{{"type","boolean"},{"default",false}}},{"getoff",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_offset === (NEW) */
      {{"name","trace_offset"},
       {"description",
        "\xf0\x9f\x93\x8d [Offset Hook] \xe6\x8c\x89\xe5\x81\x8f\xe7\xa7\xbb\xe5\x9c\xb0\xe5\x9d\x80 Hook .so \xe5\xba\x93\xe5\x87\xbd\xe6\x95\xb0\xe3\x80\x82\xe4\xb8\x8d\xe9\x9c\x80\xe8\xa6\x81\xe7\xac\xa6\xe5\x8f\xb7\xe5\x90\x8d\xef\xbc\x8c\xe9\x80\x82\xe5\x90\x88 stripped \xe7\x9a\x84\xe5\xba\x93\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\xbd\x93\xe4\xbd\xa0\xe7\x9f\xa5\xe9\x81\x93\xe7\x9b\xae\xe6\xa0\x87\xe5\x87\xbd\xe6\x95\xb0\xe7\x9a\x84\xe5\x81\x8f\xe7\xa7\xbb\xe5\x9c\xb0\xe5\x9d\x80\xef\xbc\x88\xe4\xbe\x8b\xe5\xa6\x82\xe4\xbb\x8e IDA/Ghidra/r2 \xe8\x8e\xb7\xe5\x8f\x96\xef\xbc\x89\xef\xbc\x8c\n"
        "\xe4\xbd\x86\xe5\xba\x93\xe6\xb2\xa1\xe6\x9c\x89\xe7\xac\xa6\xe5\x8f\xb7\xe8\xa1\xa8\xef\xbc\x88stripped\xef\xbc\x89\xe6\x97\xb6\xe4\xbd\xbf\xe7\x94\xa8\xe3\x80\x82\n"
        "\xe7\x9b\xb8\xe6\xaf\x94 trace_uprobe \xe6\x9b\xb4\xe7\xae\x80\xe5\x8d\x95\xef\xbc\x8c\xe5\x8f\xaa\xe9\x9c\x80\xe6\x8f\x90\xe4\xbe\x9b\xe5\xba\x93\xe5\x90\x8d + \xe5\x81\x8f\xe7\xa7\xbb + \xe5\x8f\xaf\xe9\x80\x89\xe5\x8f\x82\xe6\x95\xb0\xe7\xb1\xbb\xe5\x9e\x8b\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", offset:\"0x1A3C00\"}\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", offset:\"0x1A3C00\", arg_types:\"str,int\", stack:true}\n"
        "  {name:\"com.game\", lib:\"libUE4.so\", offset:\"0x5F1234\", regs:true, getoff:true}"},
       {"inputSchema",{{"type","object"},{"required",{"name","lib","offset"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"description","Library name (e.g. libil2cpp.so)"}}},
         {"offset",{{"type","string"},{"description","Hex offset in library (e.g. 0x1A3C00)"}}},
         {"arg_types",{{"type","string"},{"description","Optional: comma-separated arg types (e.g. 'str,int,ptr')"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"stack_size",{{"type","integer"}}},
         {"regs",{{"type","boolean"},{"default",false}}},{"getoff",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_register === (NEW) */
      {{"name","trace_register"},
       {"description",
        "\xf0\x9f\x93\x8a [Register Track] Hook \xe5\x87\xbd\xe6\x95\xb0\xe5\xb9\xb6\xe8\xbf\xbd\xe8\xb8\xaa\xe6\x8c\x87\xe5\xae\x9a\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe7\x9a\x84\xe5\x80\xbc + \xe8\xae\xa1\xe7\xae\x97\xe6\xa8\xa1\xe5\x9d\x97\xe5\x81\x8f\xe7\xa7\xbb\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\xbd\x93\xe4\xbd\xa0\xe9\x9c\x80\xe8\xa6\x81\xe7\x9f\xa5\xe9\x81\x93\xe6\x9f\x90\xe4\xb8\xaa\xe9\x97\xb4\xe6\x8e\xa5\xe8\xb7\xb3\xe8\xbd\xac (br x8, blr x9 \xe7\xad\x89) \xe7\x9a\x84\xe5\xae\x9e\xe9\x99\x85\xe7\x9b\xae\xe6\xa0\x87\xe5\x9c\xb0\xe5\x9d\x80\xe6\x97\xb6\xef\xbc\x8c\n"
        "\xe6\x88\x96\xe8\x80\x85\xe9\x9c\x80\xe8\xa6\x81\xe7\x9f\xa5\xe9\x81\x93\xe6\x9f\x90\xe4\xb8\xaa\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe5\x9c\xa8\xe7\x89\xb9\xe5\xae\x9a\xe4\xbd\x8d\xe7\xbd\xae\xe7\x9a\x84\xe5\x80\xbc\xe3\x80\x82\n"
        "\xe4\xbc\x9a\xe8\x87\xaa\xe5\x8a\xa8\xe8\xae\xa1\xe7\xae\x97\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe5\x80\xbc\xe5\xaf\xb9\xe5\xba\x94\xe7\x9a\x84\xe6\xa8\xa1\xe5\x9d\x97\xe5\x81\x8f\xe7\xa7\xbb\xe3\x80\x82\n"
        "\n"
        "REGISTERS: x0-x28, x29(fp), x30(lr), sp, pc\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", offset:\"0x175248\", reg:\"x8\"}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:\"open[str]\", reg:\"x30\"}"},
       {"inputSchema",{{"type","object"},{"required",{"name","reg"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"default","libc.so"},{"description","Library name"}}},
         {"offset",{{"type","string"},{"description","Hex offset (alternative to point)"}}},
         {"point",{{"type","string"},{"description","Hook point spec (alternative to offset)"}}},
         {"reg",{{"type","string"},{"description","Register to track: x0-x28, x29(fp), x30(lr), sp, pc"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_return === (NEW) */
      {{"name","trace_return"},
       {"description",
        "\xe2\x86\xa9\xef\xb8\x8f [Return Offset] Hook \xe5\x87\xbd\xe6\x95\xb0\xe5\xb9\xb6\xe8\x8e\xb7\xe5\x8f\x96\xe8\xbf\x94\xe5\x9b\x9e\xe5\x9c\xb0\xe5\x9d\x80\xe5\x81\x8f\xe7\xa7\xbb\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe7\x9f\xa5\xe9\x81\x93\xe6\x9f\x90\xe4\xb8\xaa\xe5\x87\xbd\xe6\x95\xb0\xe8\xa2\xab\xe8\xb0\x81\xe8\xb0\x83\xe7\x94\xa8\xe4\xba\x86\xef\xbc\x8c\xe5\xb9\xb6\xe8\x8e\xb7\xe5\x8f\x96\xe8\xb0\x83\xe7\x94\xa8\xe8\x80\x85\xe7\x9a\x84\xe7\xb2\xbe\xe7\xa1\xae\xe8\xbf\x94\xe5\x9b\x9e\xe5\x81\x8f\xe7\xa7\xbb\xef\xbc\x88\xe5\x8d\xb3 BL/BLR \xe4\xb8\x8b\xe4\xb8\x80\xe6\x9d\xa1\xe6\x8c\x87\xe4\xbb\xa4\xef\xbc\x89\xe3\x80\x82\n"
        "\xe7\xbb\x93\xe5\x90\x88 --stack \xe5\x8f\xaf\xe4\xbb\xa5\xe7\x9c\x8b\xe5\x88\xb0\xe5\xae\x8c\xe6\x95\xb4\xe8\xb0\x83\xe7\x94\xa8\xe9\x93\xbe\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:\"open[str]\"}\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", offset:\"0x1A3C00\", stack:true}"},
       {"inputSchema",{{"type","object"},{"required",{"name"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"default","libc.so"},{"description","Library name"}}},
         {"offset",{{"type","string"},{"description","Hex offset (alternative to point)"}}},
         {"point",{{"type","string"},{"description","Hook point spec with types (alternative to offset)"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},
         {"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_hexdump === (NEW) */
      {{"name","trace_hexdump"},
       {"description",
        "\xf0\x9f\x94\xa2 [Hex Buffer Trace] Hook \xe5\x87\xbd\xe6\x95\xb0\xe5\xb9\xb6\xe4\xbb\xa5 hex dump \xe6\xa0\xbc\xe5\xbc\x8f\xe8\xbe\x93\xe5\x87\xba\xe7\xbc\x93\xe5\x86\xb2\xe5\x8c\xba\xe5\x86\x85\xe5\xae\xb9\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\xbd\x93\xe4\xbd\xa0\xe9\x9c\x80\xe8\xa6\x81\xe6\x9f\xa5\xe7\x9c\x8b\xe5\x87\xbd\xe6\x95\xb0\xe5\x8f\x82\xe6\x95\xb0\xe4\xb8\xad\xe7\x9a\x84\xe4\xba\x8c\xe8\xbf\x9b\xe5\x88\xb6\xe6\x95\xb0\xe6\x8d\xae\xef\xbc\x88\xe5\xa6\x82\xe5\x8a\xa0\xe5\xaf\x86\xe6\x95\xb0\xe6\x8d\xae\xe3\x80\x81\xe5\x8d\x8f\xe8\xae\xae\xe5\x8c\x85\xe3\x80\x81key\xe7\xad\x89\xef\xbc\x89\xe6\x97\xb6\xe4\xbd\xbf\xe7\x94\xa8\xe3\x80\x82\n"
        "\xe7\xb1\xbb\xe4\xbc\xbc frida hexdump\xef\xbc\x8c\xe4\xbd\x86\xe5\x9f\xba\xe4\xba\x8e eBPF\xef\xbc\x8c\xe4\xb8\x8d\xe5\xae\xb9\xe6\x98\x93\xe8\xa2\xab\xe6\xa3\x80\xe6\xb5\x8b\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"write[int,buf:256,int]\"]}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"send[int,buf:512,int,int]\"]}\n"
        "  {name:\"com.game\", lib:\"libssl.so\", point:[\"SSL_write+0x0[ptr,buf:256,int]\"]}"},
       {"inputSchema",{{"type","object"},{"required",{"name","point"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"default","libc.so"},{"description","Library name"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook points with buf:N type for hex output"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}},{"description","Arg filter rules"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_config === */
      {{"name","trace_config"},
       {"description",
        "\xf0\x9f\x93\x84 [Config Hook] \xe4\xbd\xbf\xe7\x94\xa8 JSON \xe9\x85\x8d\xe7\xbd\xae\xe6\x96\x87\xe4\xbb\xb6\xe8\xbf\x9b\xe8\xa1\x8c\xe5\xa4\x8d\xe6\x9d\x82\xe7\x9a\x84\xe5\xa4\x9a\xe7\x82\xb9\xe6\x89\xb9\xe9\x87\x8f hook\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\x90\x8c\xe6\x97\xb6 hook \xe5\xa4\x9a\xe4\xb8\xaa\xe5\xba\x93\xe7\x9a\x84\xe5\xa4\x9a\xe4\xb8\xaa\xe5\x87\xbd\xe6\x95\xb0\xef\xbc\x8c\xe6\xaf\x8f\xe4\xb8\xaa\xe5\x87\xbd\xe6\x95\xb0\xe5\x8d\x95\xe7\x8b\xac\xe9\x85\x8d\xe7\xbd\xae\xe6\x98\xaf\xe5\x90\xa6\xe8\xbe\x93\xe5\x87\xba\xe5\xa0\x86\xe6\xa0\x88\xe5\x92\x8c\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe3\x80\x82\n"
        "\n"
        "CONFIG FORMAT (JSON):\n"
        "{\n"
        "  \"library_dirs\": [\"/apex/com.android.runtime/lib64\"],\n"
        "  \"libs\": [\n"
        "    {\n"
        "      \"library\": \"bionic/libc.so\",\n"
        "      \"disable\": false,\n"
        "      \"configs\": [\n"
        "        {\"stack\": true, \"regs\": true, \"symbols\": [\"open\"], \"offsets\": []},\n"
        "        {\"stack\": false, \"regs\": true, \"symbols\": [\"read\",\"write\"], \"offsets\": []}\n"
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "\n"
        "\xe5\x86\x85\xe7\xbd\xae syscall \xe9\x85\x8d\xe7\xbd\xae: <self_dir>/user/config/config_syscall_aarch64.json\n"
        "\n"
        "Example: {name:\"com.game\", config:[\"/path/to/config.json\"]}"},
       {"inputSchema",{{"type","object"},{"required",{"name","config"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"config",{{"type","array"},{"items",{{"type","string"}}},{"description","One or more JSON config file paths"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"out",{{"type","string"}}},{"json_fmt",{{"type","boolean"},{"default",false}}},
         {"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === hw_breakpoint === */
      {{"name","hw_breakpoint"},
       {"description",
        "\xf0\x9f\x8e\xaf [HW Breakpoint] \xe8\xae\xbe\xe7\xbd\xae ARM64 \xe7\xa1\xac\xe4\xbb\xb6\xe6\x96\xad\xe7\x82\xb9\xef\xbc\x8c\xe6\x8d\x95\xe8\x8e\xb7\xe5\x86\x85\xe5\xad\x98\xe8\xaf\xbb\xe5\x86\x99\xe6\x88\x96\xe4\xbb\xa3\xe7\xa0\x81\xe6\x89\xa7\xe8\xa1\x8c\xe4\xba\x8b\xe4\xbb\xb6\xe3\x80\x82\n"
        "\n"
        "BREAKPOINT TYPES:\n"
        "  x  - \xe6\x89\xa7\xe8\xa1\x8c\xe6\x96\xad\xe7\x82\xb9: \xe5\xbd\x93 CPU \xe6\x89\xa7\xe8\xa1\x8c\xe5\x88\xb0\xe8\xaf\xa5\xe5\x9c\xb0\xe5\x9d\x80\xe6\x97\xb6\xe8\xa7\xa6\xe5\x8f\x91\n"
        "  w  - \xe5\x86\x99\xe6\x96\xad\xe7\x82\xb9: \xe5\xbd\x93\xe6\x95\xb0\xe6\x8d\xae\xe8\xa2\xab\xe5\x86\x99\xe5\x85\xa5\xe8\xaf\xa5\xe5\x9c\xb0\xe5\x9d\x80\xe6\x97\xb6\xe8\xa7\xa6\xe5\x8f\x91 (\xe5\xb8\xb8\xe7\x94\xa8\xe4\xba\x8e\xe6\x89\xbe\xe5\x86\x99\xe5\x85\xa5\xe8\x80\x85)\n"
        "  r  - \xe8\xaf\xbb\xe6\x96\xad\xe7\x82\xb9: \xe5\xbd\x93\xe6\x95\xb0\xe6\x8d\xae\xe8\xa2\xab\xe8\xaf\xbb\xe5\x8f\x96\xe6\x97\xb6\xe8\xa7\xa6\xe5\x8f\x91\n"
        "  rw - \xe8\xaf\xbb\xe5\x86\x99\xe6\x96\xad\xe7\x82\xb9: \xe8\xaf\xbb\xe6\x88\x96\xe5\x86\x99\xe9\x83\xbd\xe8\xa7\xa6\xe5\x8f\x91\n"
        "\n"
        "BRK FORMAT: '0xOFFSET:TYPE'\n"
        "  0x1234:w   - \xe5\x9c\xa8\xe5\x81\x8f\xe7\xa7\xbb 0x1234 \xe5\xa4\x84\xe8\xae\xbe\xe7\xbd\xae\xe5\x86\x99\xe6\x96\xad\xe7\x82\xb9\n"
        "  0x5678:x   - \xe5\x9c\xa8\xe5\x81\x8f\xe7\xa7\xbb 0x5678 \xe5\xa4\x84\xe8\xae\xbe\xe7\xbd\xae\xe6\x89\xa7\xe8\xa1\x8c\xe6\x96\xad\xe7\x82\xb9\n"
        "\n"
        "brk_lib: \xe6\x8c\x87\xe5\xae\x9a\xe5\x81\x8f\xe7\xa7\xbb\xe5\x9f\xba\xe4\xba\x8e\xe5\x93\xaa\xe4\xb8\xaa\xe6\xa8\xa1\xe5\x9d\x97\n"
        "brk_len: \xe6\x96\xad\xe7\x82\xb9\xe9\x95\xbf\xe5\xba\xa6 1-8 \xe5\xad\x97\xe8\x8a\x82 (\xe9\xbb\x98\xe8\xae\xa4 4)\n"
        "\xe2\x9a\xa0\xef\xb8\x8f \xe9\x98\xbb\xe5\xa1\x9e\xe6\x93\x8d\xe4\xbd\x9c\xef\xbc\x81\xe4\xbc\x9a\xe7\xad\x89\xe5\xbe\x85\xe7\x9b\xb4\xe5\x88\xb0\xe6\x96\xad\xe7\x82\xb9\xe5\x91\xbd\xe4\xb8\xad\xe6\x88\x96\xe8\xb6\x85\xe6\x97\xb6\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", brk:\"0x1234:w\", brk_lib:\"libil2cpp.so\", regs:true}\n"
        "  {name:\"com.game\", brk:\"0x5678:x\", brk_lib:\"libgame.so\", stack:true}\n"
        "  {name:\"com.game\", brk:\"0xABCD:rw\", brk_lib:\"libil2cpp.so\", regs:true, getoff:true}"},
       {"inputSchema",{{"type","object"},{"required",{"name","brk"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"brk",{{"type","string"},{"description","'0xOFFSET:TYPE' where TYPE is x/r/w/rw"}}},
         {"brk_lib",{{"type","string"},{"description","Module name for offset base (e.g. libil2cpp.so)"}}},
         {"brk_len",{{"type","integer"},{"description","Breakpoint byte length 1-8 (default 4)"}}},
         {"brk_pid",{{"type","integer"}}},{"pid",{{"type","string"}}},
         {"regs",{{"type","boolean"},{"default",true},{"description","Show registers on break (default true)"}}},
         {"getoff",{{"type","boolean"},{"default",false},{"description","Calculate PC/LR module offset"}}},
         {"stack",{{"type","boolean"},{"default",false},{"description","Show stack trace"}}},
         {"stack_size",{{"type","integer"}}},
         {"showpc",{{"type","boolean"},{"default",false},{"description","Show raw PC register value"}}},
         {"out",{{"type","string"}}},{"json_fmt",{{"type","boolean"},{"default",false}}},
         {"debug",{{"type","boolean"},{"default",false}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_signal === */
      {{"name","trace_signal"},
       {"description",
        "\xe2\x9a\xa1 [Signal Inject] Hook \xe5\x87\xbd\xe6\x95\xb0\xe5\xb9\xb6\xe5\x9c\xa8\xe5\x91\xbd\xe4\xb8\xad\xe6\x97\xb6\xe5\x8f\x91\xe9\x80\x81\xe4\xbf\xa1\xe5\x8f\xb7\xef\xbc\x8c\xe7\x94\xa8\xe4\xba\x8e\xe5\x86\xbb\xe7\xbb\x93/\xe5\x81\x9c\xe6\xad\xa2\xe7\x9b\xae\xe6\xa0\x87\xe3\x80\x82\n"
        "\n"
        "SIGNALS:\n"
        "  SIGSTOP - \xe6\x9a\x82\xe5\x81\x9c\xe8\xbf\x9b\xe7\xa8\x8b\xef\xbc\x88\xe5\x8f\xaf\xe7\x94\xa8 auto_resume \xe8\x87\xaa\xe5\x8a\xa8\xe6\x81\xa2\xe5\xa4\x8d\xef\xbc\x89\n"
        "  SIGABRT - \xe4\xb8\xad\xe6\xad\xa2\xe8\xbf\x9b\xe7\xa8\x8b\xef\xbc\x88\xe7\x94\x9f\xe6\x88\x90 tombstone\xef\xbc\x89\n"
        "  SIGTRAP - \xe8\xa7\xa6\xe5\x8f\x91\xe8\xb0\x83\xe8\xaf\x95\xe5\x99\xa8\xe6\x96\xad\xe7\x82\xb9\n"
        "\n"
        "signal vs tkill:\n"
        "  signal: \xe5\x8f\x91\xe9\x80\x81\xe7\xbb\x99\xe6\x95\xb4\xe4\xb8\xaa\xe8\xbf\x9b\xe7\xa8\x8b\n"
        "  tkill: \xe5\x8f\x91\xe9\x80\x81\xe7\xbb\x99\xe7\x89\xb9\xe5\xae\x9a\xe7\xba\xbf\xe7\xa8\x8b\xef\xbc\x88\xe9\x85\x8d\xe5\x90\x88 tname \xe4\xbd\xbf\xe7\x94\xa8\xef\xbc\x89\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", point:[\"open[str]\"], signal:\"SIGSTOP\", auto_resume:true}\n"
        "  {name:\"com.game\", lib:\"libil2cpp.so\", point:[\"func+0x0[]\"], tkill:\"SIGSTOP\", tname:\"main\"}\n"
        "  {name:\"com.game\", point:[\"connect[int,ptr,int]\"], signal:\"SIGTRAP\"}"},
       {"inputSchema",{{"type","object"},{"required",{"name","point"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"lib",{{"type","string"},{"default","libc.so"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook point specs"}}},
         {"signal",{{"type","string"},{"description","Signal to entire process: SIGSTOP/SIGABRT/SIGTRAP"}}},
         {"tkill",{{"type","string"},{"description","Signal to specific thread"}}},
         {"auto_resume",{{"type","boolean"},{"default",false},{"description","Auto resume after SIGSTOP"}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"out",{{"type","string"}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_log === (NEW) */
      {{"name","trace_log"},
       {"description",
        "\xf0\x9f\x93\x9d [Background Trace] \xe5\x90\x8e\xe5\x8f\xb0\xe8\xbf\xbd\xe8\xb8\xaa\xef\xbc\x8c\xe4\xbb\x85\xe8\xbe\x93\xe5\x87\xba\xe5\x88\xb0\xe6\x96\x87\xe4\xbb\xb6\xef\xbc\x8c\xe4\xb8\x8d\xe5\x8d\xa0\xe7\x94\xa8\xe7\xbb\x88\xe7\xab\xaf\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe9\x95\xbf\xe6\x97\xb6\xe9\x97\xb4\xe8\xbf\xbd\xe8\xb8\xaa\xe6\x94\xb6\xe9\x9b\x86\xe6\x95\xb0\xe6\x8d\xae\xef\xbc\x8c\xe5\xa6\x82\xe7\x9b\x91\xe6\x8e\xa7\xe5\xba\x94\xe7\x94\xa8\xe6\x96\x87\xe4\xbb\xb6\xe8\xae\xbf\xe9\x97\xae\xe3\x80\x81\xe7\xbd\x91\xe7\xbb\x9c\xe8\xbf\x9e\xe6\x8e\xa5\xe7\xad\x89\xe3\x80\x82\n"
        "\xe4\xbd\xbf\xe7\x94\xa8 --quiet + --out \xe6\xa8\xa1\xe5\xbc\x8f\xef\xbc\x8c\xe4\xb8\x8d\xe8\xbe\x93\xe5\x87\xba\xe5\x88\xb0\xe7\xbb\x88\xe7\xab\xaf\xef\xbc\x8c\xe4\xbb\x85\xe5\x86\x99\xe6\x96\x87\xe4\xbb\xb6\xe3\x80\x82\n"
        "\xe8\xbf\xbd\xe8\xb8\xaa\xe7\xbb\x93\xe6\x9d\x9f\xe5\x90\x8e\xe5\x8f\xaf\xe7\x94\xa8 file_read \xe8\xaf\xbb\xe5\x8f\x96\xe6\x97\xa5\xe5\xbf\x97\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", syscall:\"openat\", log_file:\"/sdcard/trace.log\", timeout:300}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"open[str]\"], log_file:\"/sdcard/open.log\"}\n"
        "  {name:\"com.game\", syscall:\"connect,sendto\", log_file:\"/sdcard/net.log\", json_fmt:true}"},
       {"inputSchema",{{"type","object"},{"required",{"name","log_file"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"syscall",{{"type","string"},{"description","Syscall names (alternative to point)"}}},
         {"lib",{{"type","string"},{"description","Library name (used with point)"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook points (alternative to syscall)"}}},
         {"log_file",{{"type","string"},{"description","Output log file path (e.g. /sdcard/trace.log)"}}},
         {"no_syscall",{{"type","string"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",300}}}
       }}}}},

      /* === trace_thread === (NEW) */
      {{"name","trace_thread"},
       {"description",
        "\xf0\x9f\xa7\xb5 [Thread Trace] \xe6\x8c\x89\xe7\xba\xbf\xe7\xa8\x8b\xe5\x90\x8d\xe6\x88\x96 TID \xe8\xbf\x87\xe6\xbb\xa4\xe8\xbf\xbd\xe8\xb8\xaa\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\x8f\xaa\xe5\x85\xb3\xe6\xb3\xa8\xe7\x89\xb9\xe5\xae\x9a\xe7\xba\xbf\xe7\xa8\x8b\xe7\x9a\x84\xe8\xa1\x8c\xe4\xb8\xba\xef\xbc\x8c\xe5\xa6\x82\xe6\xb8\xb8\xe6\x88\x8f\xe4\xb8\xbb\xe7\xba\xbf\xe7\xa8\x8b\xe3\x80\x81\xe7\xbd\x91\xe7\xbb\x9c\xe7\xba\xbf\xe7\xa8\x8b\xe3\x80\x81\xe6\xb8\xb2\xe6\x9f\x93\xe7\xba\xbf\xe7\xa8\x8b\xe7\xad\x89\xe3\x80\x82\n"
        "\xe6\x94\xaf\xe6\x8c\x81\xe7\x99\xbd\xe5\x90\x8d\xe5\x8d\x95 (tname/tid) \xe5\x92\x8c\xe9\xbb\x91\xe5\x90\x8d\xe5\x8d\x95 (no_tname/no_tid)\xe3\x80\x82\n"
        "\n"
        "\xe5\xb8\xb8\xe8\xa7\x81\xe7\xba\xbf\xe7\xa8\x8b\xe5\x90\x8d:\n"
        "  main - \xe4\xb8\xbb\xe7\xba\xbf\xe7\xa8\x8b\n"
        "  UnityMain / UnityGfx - Unity \xe6\xb8\xb8\xe6\x88\x8f\xe7\xba\xbf\xe7\xa8\x8b\n"
        "  GameThread / RenderThread - UE4 \xe7\xba\xbf\xe7\xa8\x8b\n"
        "  OkHttp / okio - \xe7\xbd\x91\xe7\xbb\x9c\xe7\xba\xbf\xe7\xa8\x8b\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", tname:\"main\", syscall:\"openat\"}\n"
        "  {name:\"com.game\", tname:\"UnityMain\", lib:\"libil2cpp.so\", point:[\"il2cpp_string_new[str]\"]}\n"
        "  {name:\"com.game\", tid:\"12345\", syscall:\"read,write\", stack:true}\n"
        "  {name:\"com.game\", no_tname:\"FinalizerDaemon,ReferenceQueueDaemon\", syscall:\"openat\"}"},
       {"inputSchema",{{"type","object"},{"required",{"name"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"tname",{{"type","string"},{"description","Thread name whitelist (e.g. 'main' or 'UnityMain')"}}},
         {"tid",{{"type","string"},{"description","TID whitelist"}}},
         {"no_tname",{{"type","string"},{"description","Thread name blacklist"}}},
         {"no_tid",{{"type","string"},{"description","TID blacklist"}}},
         {"syscall",{{"type","string"},{"description","Syscall names to trace"}}},
         {"lib",{{"type","string"},{"description","Library name for uprobe"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook point specs"}}},
         {"no_syscall",{{"type","string"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}}}},
         {"pid",{{"type","string"}}},{"no_pid",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === trace_uid === (NEW) */
      {{"name","trace_uid"},
       {"description",
        "\xf0\x9f\x91\xa4 [UID Trace] \xe6\x8c\x89 UID \xe8\xbf\xbd\xe8\xb8\xaa\xef\xbc\x8c\xe4\xb8\x8d\xe9\x9c\x80\xe8\xa6\x81\xe5\x8c\x85\xe5\x90\x8d\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe8\xbf\xbd\xe8\xb8\xaa\xe7\xb3\xbb\xe7\xbb\x9f\xe8\xbf\x9b\xe7\xa8\x8b\xe6\x88\x96\xe4\xb8\x8d\xe7\x9f\xa5\xe9\x81\x93\xe5\x8c\x85\xe5\x90\x8d\xe7\x9a\x84\xe8\xbf\x9b\xe7\xa8\x8b\xe3\x80\x82\n"
        "\xe6\xaf\x8f\xe4\xb8\xaa Android \xe5\xba\x94\xe7\x94\xa8\xe9\x83\xbd\xe6\x9c\x89\xe5\x94\xaf\xe4\xb8\x80\xe7\x9a\x84 UID\xef\xbc\x8c\xe5\x8f\xaf\xe9\x80\x9a\xe8\xbf\x87 'stat -c %u /data/data/com.app' \xe8\x8e\xb7\xe5\x8f\x96\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {uid:\"10245\", syscall:\"openat\", stack:true}\n"
        "  {uid:\"10245\", lib:\"libc.so\", point:[\"open[str]\"]}\n"
        "  {uid:\"1000\", syscall:\"connect,sendto\", regs:true}"},
       {"inputSchema",{{"type","object"},{"required",{"uid"}},{"properties",{
         {"uid",{{"type","string"},{"description","Target UID (e.g. 10245). Get via: stat -c %u /data/data/com.app"}}},
         {"syscall",{{"type","string"},{"description","Syscall names to trace"}}},
         {"lib",{{"type","string"},{"description","Library name for uprobe"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}},{"description","Hook point specs"}}},
         {"no_syscall",{{"type","string"}}},
         {"filter",{{"type","array"},{"items",{{"type","string"}}}}},
         {"pid",{{"type","string"}}},{"tid",{{"type","string"}}},{"tname",{{"type","string"}}},
         {"no_pid",{{"type","string"}}},{"no_tid",{{"type","string"}}},{"no_tname",{{"type","string"}}},
         {"out",{{"type","string"}}},
         {"json_fmt",{{"type","boolean"},{"default",false}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"stack",{{"type","boolean"},{"default",false}}},{"regs",{{"type","boolean"},{"default",false}}},
         {"buffer",{{"type","integer"}}},{"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === perf_dump === */
      {{"name","perf_dump"},
       {"description",
        "\xf0\x9f\x92\xbe [Perf Dump] \xe5\xb0\x86\xe5\x8e\x9f\xe5\xa7\x8b eBPF perf \xe4\xba\x8b\xe4\xbb\xb6\xe4\xbf\x9d\xe5\xad\x98\xe5\x88\xb0\xe6\x96\x87\xe4\xbb\xb6\xef\xbc\x8c\xe5\x8f\xaf\xe7\xa8\x8d\xe5\x90\x8e\xe7\x94\xa8 perf_parse \xe8\xa7\xa3\xe6\x9e\x90\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\x85\x88\xe5\xbf\xab\xe9\x80\x9f\xe8\xae\xb0\xe5\xbd\x95\xe5\x8e\x9f\xe5\xa7\x8b\xe6\x95\xb0\xe6\x8d\xae\xef\xbc\x8c\xe7\xa8\x8d\xe5\x90\x8e\xe6\x85\xa2\xe6\x85\xa2\xe5\x88\x86\xe6\x9e\x90\xe3\x80\x82\xe9\x80\x82\xe5\x90\x88\xe9\xab\x98\xe9\xa2\x91\xe4\xba\x8b\xe4\xbb\xb6\xe5\x9c\xba\xe6\x99\xaf\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {name:\"com.game\", syscall:\"openat\", dump_file:\"/sdcard/trace.perf\"}\n"
        "  {name:\"com.game\", lib:\"libc.so\", point:[\"write[int,buf:64,int]\"], dump_file:\"/sdcard/write.perf\"}"},
       {"inputSchema",{{"type","object"},{"required",{"name","dump_file"}},{"properties",{
         {"name",{{"type","string"},{"description","Target package name"}}},
         {"dump_file",{{"type","string"},{"description","Output perf file path"}}},
         {"syscall",{{"type","string"}}},{"lib",{{"type","string"}}},
         {"point",{{"type","array"},{"items",{{"type","string"}}}}},
         {"pid",{{"type","string"}}},{"debug",{{"type","boolean"},{"default",false}}},
         {"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* === perf_parse === */
      {{"name","perf_parse"},
       {"description",
        "\xf0\x9f\x93\x8a [Perf Parse] \xe8\xa7\xa3\xe6\x9e\x90\xe4\xb9\x8b\xe5\x89\x8d\xe4\xbf\x9d\xe5\xad\x98\xe7\x9a\x84 perf \xe6\x95\xb0\xe6\x8d\xae\xe6\x96\x87\xe4\xbb\xb6\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\x85\x88\xe7\x94\xa8 perf_dump \xe5\xbd\x95\xe5\x88\xb6\xef\xbc\x8c\xe5\x86\x8d\xe7\x94\xa8 perf_parse \xe8\xa7\xa3\xe6\x9e\x90\xe6\x88\x90\xe5\x8f\xaf\xe8\xaf\xbb\xe6\xa0\xbc\xe5\xbc\x8f\xe6\x88\x96 JSON\xe3\x80\x82\n"
        "\n"
        "Examples:\n"
        "  {parse_file:\"/sdcard/trace.perf\"}\n"
        "  {parse_file:\"/sdcard/trace.perf\", json_fmt:true}"},
       {"inputSchema",{{"type","object"},{"required",{"parse_file"}},{"properties",{
         {"parse_file",{{"type","string"},{"description","Perf data file to parse"}}},
         {"json_fmt",{{"type","boolean"},{"default",false},{"description","Output as JSON"}}},
         {"timeout",{{"type","integer"},{"default",30}}}
       }}}}},

      /* === stackplz_raw === */
      {{"name","stackplz_raw"},
       {"description",
        "\xf0\x9f\x94\xa7 [Raw stackplz] \xe7\x9b\xb4\xe6\x8e\xa5\xe6\x89\xa7\xe8\xa1\x8c stackplz \xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c\xef\xbc\x88\xe9\x80\x83\xe7\x94\x9f\xe8\x88\xb1\xef\xbc\x89\xe3\x80\x82\n"
        "\n"
        "\xe7\x94\xa8\xe9\x80\x94: \xe5\xbd\x93\xe5\x85\xb6\xe4\xbb\x96\xe5\xb7\xa5\xe5\x85\xb7\xe6\x97\xa0\xe6\xb3\x95\xe6\xbb\xa1\xe8\xb6\xb3\xe9\x9c\x80\xe6\xb1\x82\xe6\x97\xb6\xef\xbc\x8c\xe7\x9b\xb4\xe6\x8e\xa5\xe4\xbc\xa0\xe9\x80\x92 stackplz \xe5\x8f\x82\xe6\x95\xb0\xe3\x80\x82\n"
        "\n"
        "ALL FLAGS:\n"
        "  --name PKG    \xe7\x9b\xae\xe6\xa0\x87\xe5\x8c\x85\xe5\x90\x8d\n"
        "  --uid UID     \xe7\x9b\xae\xe6\xa0\x87 UID\n"
        "  --pid PID     PID \xe7\x99\xbd\xe5\x90\x8d\xe5\x8d\x95\n"
        "  --tid TID     TID \xe7\x99\xbd\xe5\x90\x8d\xe5\x8d\x95\n"
        "  --tname NAME  \xe7\xba\xbf\xe7\xa8\x8b\xe5\x90\x8d\xe7\x99\xbd\xe5\x90\x8d\xe5\x8d\x95\n"
        "  --syscall SYS syscall \xe8\xbf\xbd\xe8\xb8\xaa\n"
        "  --lib LIB     \xe7\x9b\xae\xe6\xa0\x87\xe5\xba\x93\n"
        "  --point SPEC  uprobe hook \xe7\x82\xb9\n"
        "  --config JSON \xe9\x85\x8d\xe7\xbd\xae\xe6\x96\x87\xe4\xbb\xb6\n"
        "  --brk ADDR    \xe7\xa1\xac\xe4\xbb\xb6\xe6\x96\xad\xe7\x82\xb9\n"
        "  --brk-lib LIB \xe6\x96\xad\xe7\x82\xb9\xe5\x9f\xba\xe5\x9d\x80\xe6\xa8\xa1\xe5\x9d\x97\n"
        "  --stack       \xe5\xa0\x86\xe6\xa0\x88\xe5\x9b\x9e\xe6\xba\xaf\n"
        "  --regs        \xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe4\xbf\xa1\xe6\x81\xaf\n"
        "  --getoff      \xe8\xae\xa1\xe7\xae\x97 PC/LR \xe5\x81\x8f\xe7\xa7\xbb\n"
        "  --reg REG     \xe8\xbf\xbd\xe8\xb8\xaa\xe7\x89\xb9\xe5\xae\x9a\xe5\xaf\x84\xe5\xad\x98\xe5\x99\xa8\xe5\x81\x8f\xe7\xa7\xbb\n"
        "  --json        JSON \xe8\xbe\x93\xe5\x87\xba\n"
        "  --out FILE    \xe8\xbe\x93\xe5\x87\xba\xe5\x88\xb0\xe6\x96\x87\xe4\xbb\xb6\n"
        "  --quiet       \xe4\xb8\x8d\xe8\xbe\x93\xe5\x87\xba\xe5\x88\xb0\xe7\xbb\x88\xe7\xab\xaf\n"
        "  --dump FILE   \xe4\xbf\x9d\xe5\xad\x98 perf \xe6\x95\xb0\xe6\x8d\xae\n"
        "  --parse FILE  \xe8\xa7\xa3\xe6\x9e\x90 perf \xe6\x95\xb0\xe6\x8d\xae\n"
        "  --dumpret     \xe8\xbe\x93\xe5\x87\xba\xe8\xbf\x94\xe5\x9b\x9e\xe5\x81\x8f\xe7\xa7\xbb\n"
        "  --dumphex     hex dump \xe7\xbc\x93\xe5\x86\xb2\xe5\x8c\xba\n"
        "  --kill SIG    \xe5\x8f\x91\xe9\x80\x81\xe4\xbf\xa1\xe5\x8f\xb7\n"
        "  --tkill SIG   \xe5\x8f\x91\xe9\x80\x81\xe7\xba\xbf\xe7\xa8\x8b\xe4\xbf\xa1\xe5\x8f\xb7\n"
        "  --auto        SIGSTOP \xe8\x87\xaa\xe5\x8a\xa8\xe6\x81\xa2\xe5\xa4\x8d\n"
        "  --maxop N     eBPF \xe6\x93\x8d\xe4\xbd\x9c\xe6\x95\xb0\xe4\xb8\x8a\xe9\x99\x90\n"
        "  --buffer N    perf \xe7\xbc\x93\xe5\x86\xb2 MB\n"
        "  --filter RULE \xe5\x8f\x82\xe6\x95\xb0\xe8\xbf\x87\xe6\xbb\xa4\n"
        "  --showpc      \xe6\x98\xbe\xe7\xa4\xba\xe5\x8e\x9f\xe5\xa7\x8b PC\n"
        "  --showtime    \xe6\x98\xbe\xe7\xa4\xba\xe5\x90\xaf\xe5\x8a\xa8\xe6\x97\xb6\xe9\x97\xb4\n"
        "  --showuid     \xe6\x98\xbe\xe7\xa4\xba UID\n"
        "  --debug       \xe8\xb0\x83\xe8\xaf\x95\xe6\xa8\xa1\xe5\xbc\x8f\n"
        "\n"
        "Example: {args:\"--name com.game --syscall openat --json --stack\"}"},
       {"inputSchema",{{"type","object"},{"required",{"args"}},{"properties",{
         {"args",{{"type","string"},{"description","Complete stackplz command-line arguments"}}},
         {"timeout",{{"type","integer"},{"default",60}}}
       }}}}},

      /* ─── Memory Tools (paradise_tool_v5) ─── */
      {{"name","mem_maps"},
       {"description",
        "📋 [Memory Maps] Show target process memory maps via Paradise driver.\n"
        "Filters: --lib (only .so), --heap (heap/dalvik), --rw (readable+writable).\n"
        "Example: {pkg:\"com.game.app\", filter:\"--lib\"}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"filter",{{"type","string"},{"enum",{"--lib","--heap","--rw"}},{"description","Region filter"}}},
         {"timeout",{{"type","integer"},{"default",30}}}
       }}}}},

      {{"name","mem_module"},
       {"description",
        "📦 [Module Base] Get module base address in target process.\n"
        "Example: {pkg:\"com.game.app\", module:\"libil2cpp.so\"} -> 0x7abc000000"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","module"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"module",{{"type","string"},{"description","Module name, e.g. libil2cpp.so"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},
      {{"name","mem_offset"},
       {"description",
        "🧮 [Offset Calc] Calculate absolute address = module_base + offset.\n"
        "Example: {pkg:\"com.game\", module:\"libil2cpp.so\", offset:\"0x1234\"}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","module","offset"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"module",{{"type","string"},{"description","Module name"}}},
         {"offset",{{"type","string"},{"description","Hex offset e.g. 0x1234"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_read"},
       {"description",
        "👁️ [Memory Read] Read typed values from target process memory.\n"
        "Types: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 str.\n"
        "Addr can be absolute (0xABCD) or module-relative (libgame.so+0x1234).\n"
        "Use --gg for GG union search format output.\n"
        "Examples:\n"
        "  {pkg:\"com.game\", addr:\"0x12345678\", type:\"f32\"}\n"
        "  {pkg:\"com.game\", addr:\"libil2cpp.so+0x1234\", type:\"u32\", count:10}\n"
        "  {pkg:\"com.game\", addr:\"0x12345678\", type:\"i32\", count:5, gg_mode:true}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr","type"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Address: 0xABCD or libxxx.so+0xOFFSET"}}},
         {"type",{{"type","string"},{"enum",{"u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","str"}},
            {"description","Value type"}}},
         {"count",{{"type","integer"},{"default",1},{"description","Number of values to read"}}},
         {"gg_mode",{{"type","boolean"},{"default",false},{"description","Output in GG union search format"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_write"},
       {"description",
        "✏️ [Memory Write] Write typed values to target process memory. Supports batch.\n"
        "Types: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 str.\n"
        "Addr can be absolute or module-relative. Auto-verifies after write.\n"
        "Examples:\n"
        "  {pkg:\"com.game\", addr:\"0x12345678\", type:\"f32\", values:[\"999.0\"]}\n"
        "  {pkg:\"com.game\", addr:\"libil2cpp.so+0x100\", type:\"u32\", values:[\"1\",\"2\",\"3\"]}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr","type","values"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Address: 0xABCD or libxxx.so+0xOFFSET"}}},
         {"type",{{"type","string"},{"enum",{"u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","str"}}}},
         {"values",{{"type","array"},{"items",{{"type","string"}}},{"description","Values to write (batch)"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_asm_write"},
       {"description",
        "🔧 [ASM Write] Assemble ARM64 instructions and write to target process memory.\n"
        "Uses Keystone assembler + Capstone verifier. Multiple instructions separated by ';'.\n"
        "Examples:\n"
        "  {pkg:\"com.game\", addr:\"libil2cpp.so+0xcfc\", asm_text:\"ret\"}\n"
        "  {pkg:\"com.game\", addr:\"0x12345678\", asm_text:\"mov x0, #1; ret\"}\n"
        "  {pkg:\"com.game\", addr:\"0x12345678\", asm_text:\"nop; nop; nop; nop\"}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr","asm_text"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Address: 0xABCD or libxxx.so+0xOFFSET"}}},
         {"asm_text",{{"type","string"},{"description","ARM64 assembly text, multiple instructions separated by ';'"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_scan"},
       {"description",
        "🔍 [Memory Scan] Scan target process memory for a value or value range.\n"
        "Types: u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 str.\n"
        "Scan modes: exact value or range (min~max).\n"
        "Filters: --only-lib, --only-heap, --only-module <name>, --range <start> <end>.\n"
        "Examples:\n"
        "  {pkg:\"com.game\", type:\"i32\", value:\"999\"}\n"
        "  {pkg:\"com.game\", type:\"f32\", value:\"100.0\", scan_filter:\"--only-heap\", limit:500}\n"
        "  {pkg:\"com.game\", type:\"i32\", min:\"1\", max:\"1000\", scan_filter:\"--only-lib\"}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","type"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"type",{{"type","string"},{"enum",{"u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","str"}}}},
         {"value",{{"type","string"},{"description","Exact value to search (for exact scan)"}}},
         {"min",{{"type","string"},{"description","Minimum value (for range scan)"}}},
         {"max",{{"type","string"},{"description","Maximum value (for range scan)"}}},
         {"scan_filter",{{"type","string"},{"description","Filter: --only-lib, --only-heap, --only-module <name>"}}},
         {"range_start",{{"type","string"},{"description","Custom scan range start address"}}},
         {"range_end",{{"type","string"},{"description","Custom scan range end address"}}},
         {"limit",{{"type","integer"},{"default",2000},{"description","Max results (default 2000, max 100000)"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout (scans can be slow)"}}}
       }}}}},

      {{"name","mem_disasm"},
       {"description",
        "📜 [Disassemble] Disassemble ARM64 instructions at address using Capstone.\n"
        "Shows module offset for each instruction. Max 1024 instructions.\n"
        "Example: {pkg:\"com.game\", addr:\"libil2cpp.so+0x1234\", count:32}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Address: 0xABCD or libxxx.so+0xOFFSET"}}},
         {"count",{{"type","integer"},{"default",16},{"description","Number of instructions (default 16, max 1024)"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_ptr"},
       {"description",
        "🔗 [Pointer Chain] Follow a pointer chain and read the final value.\n"
        "Resolves base -> dereference + offset -> dereference + offset -> ... -> final read.\n"
        "If no type given, shows u64/i32/f32 of final address.\n"
        "Examples:\n"
        "  {pkg:\"com.game\", base:\"libil2cpp.so+0x1234\", offsets:[\"0x20\",\"0x48\",\"0x10\"], type:\"f32\"}\n"
        "  {pkg:\"com.game\", base:\"0x7abc000000\", offsets:[\"0x100\",\"0x0\",\"0x320\"]}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","base","offsets"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"base",{{"type","string"},{"description","Base address or module+offset"}}},
         {"offsets",{{"type","array"},{"items",{{"type","string"}}},{"description","Offset chain, e.g. ['0x20','0x48','0x10']"}}},
         {"type",{{"type","string"},{"enum",{"u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","str"}},
            {"description","Type to read at final address (optional)"}}},
         {"timeout",{{"type","integer"},{"default",15}}}
       }}}}},

      {{"name","mem_dump"},
       {"description",
        "💾 [Memory Dump] Dump memory region to binary file.\n"
        "Max 512MB. Zero-fills unreadable regions.\n"
        "Example: {pkg:\"com.game\", addr:\"libil2cpp.so+0x0\", size:\"0x100000\", file:\"/sdcard/dump.bin\"}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr","size","file"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Start address"}}},
         {"size",{{"type","string"},{"description","Size in bytes (hex or decimal)"}}},
         {"file",{{"type","string"},{"description","Output file path"}}},
         {"timeout",{{"type","integer"},{"default",120}}}
       }}}}},

      {{"name","mem_hexdump"},
       {"description",
        "🔢 [Hex Dump] Display memory as hex+ASCII table.\n"
        "Example: {pkg:\"com.game\", addr:\"0x12345678\", size:\"0x100\", cols:16}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr","size"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Start address"}}},
         {"size",{{"type","string"},{"description","Size in bytes (hex or decimal, max 64MB)"}}},
         {"cols",{{"type","integer"},{"default",16},{"description","Columns per row (1-64)"}}},
         {"timeout",{{"type","integer"},{"default",30}}}
       }}}}},

      {{"name","mem_brk"},
       {"description",
        "🎯 [HW Breakpoint] Set hardware breakpoint on target address via stackplz.\n"
        "Types: x=execute, r=read, w=write, rw=read+write.\n"
        "Auto-resolves module-relative addresses.\n"
        "⚠️ This is a blocking operation - runs until hit or timeout.\n"
        "Example: {pkg:\"com.game\", addr:\"libil2cpp.so+0x1234\", type:\"w\", count:1}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Address: 0xABCD or libxxx.so+0xOFFSET"}}},
         {"type",{{"type","string"},{"default","x"},{"enum",{"x","r","w","rw"}},{"description","Breakpoint type"}}},
         {"count",{{"type","integer"},{"description","Max hit count before auto-stop"}}},
         {"timeout",{{"type","integer"},{"default",60},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","mem_chain_trace"},
       {"description",
        "🧬 [Chain Trace] Automatic pointer chain tracer using stackplz write-breakpoints.\n"
        "Sets write-breakpoint on target address, captures registers+PC on write,\n"
        "disassembles the store instruction to find base register, then recurses up.\n"
        "Stops when reaching a static (.so) base address.\n"
        "⚠️ Long-running operation. Game must actively write to the target address.\n"
        "Output: Complete pointer chain in GG/CE format.\n"
        "Example: {pkg:\"com.game\", addr:\"0x7abc123456\", depth:8, timeout_per_brk:30}"},
       {"inputSchema",{{"type","object"},{"required",{"pkg","addr"}},{"properties",{
         {"pkg",{{"type","string"},{"description","Target package name"}}},
         {"addr",{{"type","string"},{"description","Target dynamic address to trace"}}},
         {"depth",{{"type","integer"},{"default",8},{"description","Max recursion depth (default 8)"}}},
         {"timeout_per_brk",{{"type","integer"},{"default",30},{"description","Seconds to wait per breakpoint level"}}},
         {"timeout",{{"type","integer"},{"default",300},{"description","Total timeout in seconds (default 300)"}}}
       }}}}},

      /* ─── Radare2 Static Analysis Tools ─── */
      {{"name","r2_info"},
       {"description",
        "\xf0\x9f\x94\x8d [Binary Info] Get comprehensive binary file information.\n"
        "Returns: architecture (ARM/x86/MIPS), bits (32/64), OS, compiler, security features (NX/canary/PIC/RELRO), "
        "file type (ELF/PE/DEX/Mach-O), language, endianness, entry point.\n"
        "Use this FIRST on any unknown binary to determine analysis strategy.\n"
        "Example: {file:\"/sdcard/libgame.so\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_strings"},
       {"description",
        "\xf0\x9f\x93\x9d [Strings] Extract strings from binary.\n"
        "Modes:\n"
        "  'data' (default): Only data section strings (iz) - fast, relevant strings\n"
        "  'all': All strings including code section (izz) - slow but thorough\n"
        "  'raw': Raw strings from entire file (izzz) - slowest, catches everything\n"
        "Filter: grep pattern to narrow results (e.g. 'http' 'password' 'key' 'encrypt')\n"
        "min_len: minimum string length (default 5)\n"
        "Example: {file:\"/sdcard/libgame.so\", mode:\"data\", filter:\"encrypt\", min_len:8}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"mode",{{"type","string"},{"default","data"},{"description","Search mode: data/all/raw"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"min_len",{{"type","integer"},{"default",5},{"description","Minimum string length"}}},
         {"limit",{{"type","integer"},{"default",500},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_imports"},
       {"description",
        "\xf0\x9f\x93\xa5 [Imports] List imported functions/symbols.\n"
        "Shows external functions the binary depends on (libc, JNI, OpenSSL, etc).\n"
        "Essential for understanding binary capabilities: crypto (AES/RSA), network (connect/send), "
        "file I/O (open/read/write), dangerous ops (system/exec/fork).\n"
        "Filter: grep to narrow (e.g. 'ssl' 'crypt' 'jni')\n"
        "Example: {file:\"/sdcard/libgame.so\", filter:\"crypt\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"limit",{{"type","integer"},{"default",500},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_exports"},
       {"description",
        "\xf0\x9f\x93\xa4 [Exports] List exported functions/symbols.\n"
        "Shows functions the binary provides to others. For .so libraries, these are the public API.\n"
        "For Android: look for JNI_OnLoad and Java_* exports.\n"
        "For games: look for il2cpp_*, mono_* exports.\n"
        "Filter: grep to narrow (e.g. 'Java_' 'JNI' 'il2cpp')\n"
        "Example: {file:\"/sdcard/libil2cpp.so\", filter:\"Java_\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"limit",{{"type","integer"},{"default",500},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_symbols"},
       {"description",
        "\xf0\x9f\x8f\xb7 [Symbols] List all symbols (functions + objects).\n"
        "Combines imports and exports. Shows symbol type, address, size, binding (LOCAL/GLOBAL/WEAK).\n"
        "Use for stripped binary analysis or to find hidden functions.\n"
        "Example: {file:\"/sdcard/libgame.so\", filter:\"init\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"limit",{{"type","integer"},{"default",500},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_sections"},
       {"description",
        "\xf0\x9f\x93\x8a [Sections] List binary sections/segments with permissions.\n"
        "Shows .text (code), .data (writable data), .rodata (read-only), .bss (uninitialized), "
        ".plt/.got (dynamic linking), .init_array (constructors).\n"
        "Useful for: identifying packed/encrypted sections (high entropy), finding writable code (RWX), "
        "understanding memory layout.\n"
        "Example: {file:\"/sdcard/libgame.so\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_functions"},
       {"description",
        "\xf0\x9f\x93\x8b [Functions] List analyzed functions.\n"
        "Requires analysis first (auto-runs 'aa' basic analysis).\n"
        "analyze: analysis level - 'basic' (aa, fast), 'full' (aaa, slow but thorough)\n"
        "Shows: address, size, name for each function.\n"
        "Filter: grep pattern (e.g. 'main' 'init' 'encrypt' 'check')\n"
        "\xe2\x9a\xa0 For large files (>5MB), use 'basic' analysis + filter to avoid timeout.\n"
        "Example: {file:\"/sdcard/libgame.so\", analyze:\"basic\", filter:\"JNI\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"analyze",{{"type","string"},{"default","basic"},{"description","Analysis level: basic (aa) or full (aaa)"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"limit",{{"type","integer"},{"default",500},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_disasm"},
       {"description",
        "\xf0\x9f\x93\x9c [Disassemble] Disassemble instructions at address.\n"
        "addr: hex address or function name (e.g. '0x1234', 'main', 'sym.encrypt')\n"
        "count: number of instructions (default 32)\n"
        "analyze: run analysis first to resolve symbols (default basic)\n"
        "Shows: address, hex bytes, mnemonic, operands, comments.\n"
        "Example: {file:\"/sdcard/libgame.so\", addr:\"0x1234\", count:64}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Address or symbol name (e.g. 0x1234 or main)"}}},
         {"count",{{"type","integer"},{"default",32},{"description","Number of instructions"}}},
         {"analyze",{{"type","string"},{"default","basic"},{"description","Analysis level: none/basic/full"}}},
         {"timeout",{{"type","integer"},{"default",60},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_decompile"},
       {"description",
        "\xf0\x9f\x94\x8d [Decompile] Decompile function to pseudo-C code.\n"
        "Uses r2's pdc (pseudo-decompiler) to convert assembly to readable C-like code.\n"
        "addr: function address or name\n"
        "analyze: run analysis first (recommended 'basic' or 'full')\n"
        "\xe2\x9a\xa0 Quality depends on analysis level. Use 'full' for complex functions.\n"
        "Example: {file:\"/sdcard/libgame.so\", addr:\"main\", analyze:\"full\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Function address or name"}}},
         {"analyze",{{"type","string"},{"default","basic"},{"description","Analysis level: none/basic/full"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_xrefs"},
       {"description",
        "\xf0\x9f\x94\x97 [Cross References] Find who calls/references an address.\n"
        "direction:\n"
        "  'to' (axt): Who references this address? (e.g. who calls this function?)\n"
        "  'from' (axf): What does this address reference? (e.g. what does this function call?)\n"
        "Requires analysis. Essential for tracing call chains and data flow.\n"
        "Example: {file:\"/sdcard/libgame.so\", addr:\"sym.encrypt\", direction:\"to\", analyze:\"full\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Target address or symbol"}}},
         {"direction",{{"type","string"},{"default","to"},{"description","Direction: to (axt) or from (axf)"}}},
         {"analyze",{{"type","string"},{"default","full"},{"description","Analysis level (full recommended for xrefs)"}}},
         {"limit",{{"type","integer"},{"default",100},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_search"},
       {"description",
        "\xf0\x9f\x94\x8e [Search] Search for bytes, strings, or patterns in binary.\n"
        "search_type:\n"
        "  'string': Search for UTF-8 string (e.g. 'password')\n"
        "  'hex': Search for hex bytes (e.g. 'deadbeef' or '7f454c46')\n"
        "  'asm': Search for assembly pattern (e.g. 'mov x0, x1')\n"
        "  'crypto': Scan for crypto constants (AES S-box, RSA, SHA)\n"
        "Shows address and context for each match.\n"
        "Example: {file:\"/sdcard/libgame.so\", search_type:\"hex\", pattern:\"7f454c46\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","search_type","pattern"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"search_type",{{"type","string"},{"description","Type: string/hex/asm/crypto"}}},
         {"pattern",{{"type","string"},{"description","Search pattern"}}},
         {"limit",{{"type","integer"},{"default",100},{"description","Max results"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_hexdump"},
       {"description",
        "\xf0\x9f\x94\xa2 [Hex Dump] Display hex+ASCII dump at address.\n"
        "addr: start address (hex)\n"
        "size: bytes to dump (default 256, max 4096)\n"
        "Shows classic hex dump with ASCII sidebar.\n"
        "Example: {file:\"/sdcard/libgame.so\", addr:\"0x1000\", size:512}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Start address (hex)"}}},
         {"size",{{"type","integer"},{"default",256},{"description","Bytes to dump (max 4096)"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_entropy"},
       {"description",
        "\xf0\x9f\x93\x88 [Entropy] Calculate entropy of binary sections.\n"
        "High entropy (>7.0) indicates encryption or compression (packed/protected binary).\n"
        "Normal code: ~5.5-6.5, Encrypted: >7.0, Compressed: >7.5\n"
        "Useful for: detecting packers (UPX, Themida), encrypted sections, embedded data.\n"
        "Example: {file:\"/sdcard/libgame.so\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_cmd"},
       {"description",
        "\xe2\x9a\x99 [Raw Command] Execute arbitrary radare2 commands on a binary.\n"
        "This is the escape hatch for any r2 command not covered by other tools.\n"
        "Commands are passed to: r2 -q -e bin.cache=true -c \"<commands>\" <file>\n"
        "analyze: optional analysis before commands (none/basic/full)\n"
        "Common commands:\n"
        "  iI - binary info\n"
        "  afl - list functions\n"
        "  pdf @ addr - disassemble function\n"
        "  pdc @ addr - decompile function\n"
        "  axt @ addr - xrefs to\n"
        "  /c pattern - search code pattern\n"
        "  iS - sections\n"
        "  ii - imports\n"
        "  ie - entry points\n"
        "  afn newname @ addr - rename function\n"
        "  Multiple commands separated by ';'\n"
        "Example: {file:\"/sdcard/lib.so\", commands:\"aa; afl~encrypt\", analyze:\"none\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","commands"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"commands",{{"type","string"},{"description","R2 commands (semicolon separated)"}}},
         {"analyze",{{"type","string"},{"default","none"},{"description","Analysis level: none/basic/full"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout in seconds"}}}
       }}}}},

      {{"name","r2_rabin"},
       {"description",
        "\xf0\x9f\x93\xa6 [rabin2] Run rabin2 binary analysis tool directly.\n"
        "rabin2 extracts info without opening r2 - much faster for quick checks.\n"
        "Common flags:\n"
        "  -I  binary info (arch, bits, os)\n"
        "  -i  imports\n"
        "  -E  exports\n"
        "  -s  symbols\n"
        "  -S  sections\n"
        "  -l  libraries (linked .so)\n"
        "  -z  strings from data sections\n"
        "  -zz strings from entire binary\n"
        "  -H  header fields\n"
        "  -e  entrypoints\n"
        "  -M  main address\n"
        "  -g  everything (combine all above)\n"
        "Multiple flags can be combined: '-Iize'\n"
        "Example: {file:\"/sdcard/libgame.so\", flags:\"-Ii\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","flags"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"flags",{{"type","string"},{"description","rabin2 flags (e.g. '-I', '-iz', '-E')"}}},
         {"filter",{{"type","string"},{"description","Grep filter pattern"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout in seconds"}}}
       }}}}},


      /* ─── r2 extra tools ─── */
      {{"name","r2_asm"},
       {"description",
        "\xf0\x9f\x94\xa7 [ASM] Assemble/Disassemble single ARM64 instructions using rasm2.\n"
        "direction:\n"
        "  'asm' (default): Assembly text -> hex bytes (e.g. 'ret' -> 'c0035fd6')\n"
        "  'disasm': Hex bytes -> assembly text (e.g. 'c0035fd6' -> 'ret')\n"
        "arch: architecture (default arm, also: x86, mips)\n"
        "bits: register size (default 64, also: 32, 16)\n"
        "Examples:\n"
        "  {code:\"ret\", direction:\"asm\"}\n"
        "  {code:\"c0035fd6\", direction:\"disasm\"}\n"
        "  {code:\"mov x0, #1; ret\", direction:\"asm\"}"},
       {"inputSchema",{{"type","object"},{"required",{"code"}},{"properties",{
         {"code",{{"type","string"},{"description","Assembly text or hex bytes"}}},
         {"direction",{{"type","string"},{"default","asm"},{"description","asm or disasm"}}},
         {"arch",{{"type","string"},{"default","arm"},{"description","Architecture"}}},
         {"bits",{{"type","integer"},{"default",64},{"description","Bits: 16/32/64"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}},

      {{"name","r2_diff"},
       {"description",
        "\xf0\x9f\x94\x80 [Diff] Compare two binary files using radiff2.\n"
        "Finds code differences between versions of the same library.\n"
        "mode:\n"
        "  'bytes' (default): Byte-level diff\n"
        "  'code': Code diff with disassembly (-c)\n"
        "  'graph': Graph diff (-g main)\n"
        "Example: {file1:\"/sdcard/old.so\", file2:\"/sdcard/new.so\", mode:\"code\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file1","file2"}},{"properties",{
         {"file1",{{"type","string"},{"description","First binary file"}}},
         {"file2",{{"type","string"},{"description","Second binary file"}}},
         {"mode",{{"type","string"},{"default","bytes"},{"description","Diff mode: bytes/code/graph"}}},
         {"timeout",{{"type","integer"},{"default",60},{"description","Timeout"}}}
       }}}}},

      {{"name","r2_hash"},
       {"description",
        "\xf0\x9f\x94\x91 [Hash] Calculate file hash using rahash2.\n"
        "Supported algorithms: md5, sha1, sha256, sha512, crc32, entropy, all\n"
        "Can hash specific byte range with addr+size.\n"
        "Example: {file:\"/sdcard/lib.so\", algo:\"md5,sha256\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to file"}}},
         {"algo",{{"type","string"},{"default","md5,sha256"},{"description","Hash algorithms (comma-separated)"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout"}}}
       }}}}},

      /* ─── Android / Game RE Tools ─── */
      {{"name","find_jni_methods"},
       {"description",
        "\xf0\x9f\x94\x8d [JNI Methods] List all JNI interface functions in a native library.\n"
        "Finds: JNI_OnLoad, JNI_OnUnload, Java_* static registrations,\n"
        "and dynamic registrations via RegisterNatives.\n"
        "Essential for Android native reverse engineering.\n"
        "Example: {file:\"/sdcard/libnative.so\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to .so library"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","apply_hex_patch"},
       {"description",
        "\xf0\x9f\x94\xa8 [Hex Patch] Apply binary patch to a file at specified offset.\n"
        "Writes hex bytes directly to file. Creates backup (.bak) first.\n"
        "Use r2_disasm to find the offset, then patch.\n"
        "Examples:\n"
        "  {file:\"/sdcard/lib.so\", offset:\"0x1234\", hex:\"c0035fd6\"} (patch to 'ret')\n"
        "  {file:\"/sdcard/lib.so\", offset:\"0x1234\", hex:\"1f2003d5\"} (patch to 'nop')"},
       {"inputSchema",{{"type","object"},{"required",{"file","offset","hex"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"offset",{{"type","string"},{"description","Hex offset (e.g. 0x1234)"}}},
         {"hex",{{"type","string"},{"description","Hex bytes to write (e.g. c0035fd6)"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}},

      {{"name","scan_crypto_signatures"},
       {"description",
        "\xf0\x9f\x94\x90 [Crypto Scan] Scan binary for cryptographic algorithm signatures.\n"
        "Detects: AES S-box, RSA constants, SHA constants, DES tables,\n"
        "Base64 tables, RC4 patterns, and other crypto signatures.\n"
        "Also searches for crypto-related strings (key, encrypt, decrypt, aes, rsa).\n"
        "Example: {file:\"/sdcard/libgame.so\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","batch_decrypt_strings"},
       {"description",
        "\xf0\x9f\x94\x93 [Decrypt Strings] Attempt to decrypt/decode obfuscated strings in binary.\n"
        "Tries common deobfuscation: XOR with single/multi byte keys, Base64, ROT13,\n"
        "Caesar cipher, reversed strings. Outputs decoded candidates.\n"
        "enc_type: auto (try all), xor, base64, rot13\n"
        "xor_range: key range for XOR bruteforce (default 1-255)\n"
        "Example: {file:\"/sdcard/lib.so\", enc_type:\"auto\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"enc_type",{{"type","string"},{"default","auto"},{"description","Encryption type: auto/xor/base64/rot13"}}},
         {"addr",{{"type","string"},{"description","Specific address to decode (optional)"}}},
         {"size",{{"type","integer"},{"default",256},{"description","Bytes to analyze"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","add_knowledge_note"},
       {"description",
        "\xf0\x9f\x93\x9d [Knowledge Note] Save or query persistent analysis notes.\n"
        "Stores important findings (addresses, function purposes, pointer chains) to disk.\n"
        "action:\n"
        "  'add': Save a new note (requires content)\n"
        "  'list': List all notes (optional tag filter)\n"
        "  'search': Full-text search in notes\n"
        "  'delete': Delete note by id\n"
        "Notes persist across sessions in <self_dir>/notes/\n"
        "Example: {action:\"add\", tag:\"jqys\", content:\"doBlock at libil2cpp.so+0x1A3C00\"}"},
       {"inputSchema",{{"type","object"},{"required",{"action"}},{"properties",{
         {"action",{{"type","string"},{"description","add/list/search/delete"}}},
         {"content",{{"type","string"},{"description","Note content (for add)"}}},
         {"tag",{{"type","string"},{"description","Tag/category (for add/list)"}}},
         {"query",{{"type","string"},{"description","Search query (for search)"}}},
         {"id",{{"type","string"},{"description","Note ID (for delete)"}}}
       }}}}},

      {{"name","simulate_execution"},
       {"description",
        "\xf0\x9f\xa7\xaa [ESIL Simulate] Emulate ARM64 code execution in r2's ESIL sandbox.\n"
        "Useful for: resolving dynamic values, understanding obfuscated code,\n"
        "tracing register values through complex logic.\n"
        "steps: number of instructions to emulate (default 32)\n"
        "show_regs: output register state after execution\n"
        "Example: {file:\"/sdcard/lib.so\", addr:\"0x1234\", steps:20, show_regs:true}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Start address for emulation"}}},
         {"steps",{{"type","integer"},{"default",32},{"description","Number of steps to emulate"}}},
         {"show_regs",{{"type","boolean"},{"default",true},{"description","Show registers after execution"}}},
         {"analyze",{{"type","string"},{"default","basic"},{"description","Analysis level: none/basic/full"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","rename_function"},
       {"description",
        "\xf0\x9f\x8f\xb7\xef\xb8\x8f [Rename] Rename function at address in r2 project.\n"
        "Useful for annotating discovered functions during analysis.\n"
        "The rename is applied in-session (use r2_cmd for persistent project save).\n"
        "Example: {file:\"/sdcard/lib.so\", addr:\"0x1234\", new_name:\"decrypt_config\"}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr","new_name"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Function address"}}},
         {"new_name",{{"type","string"},{"description","New function name"}}},
         {"analyze",{{"type","string"},{"default","basic"},{"description","Analysis level"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","symbolic_deobfuscate"},
       {"description",
        "\xf0\x9f\xa7\xa9 [Symbolic Exec] Analyze control flow obfuscation using r2 ESIL.\n"
        "Traces all possible execution paths from an address to find:\n"
        "- Opaque predicates (always-true/false branches)\n"
        "- Flattened control flow dispatcher variables\n"
        "- Dead code elimination candidates\n"
        "Output: simplified control flow with resolved branches.\n"
        "Example: {file:\"/sdcard/lib.so\", addr:\"0x1234\", depth:50}"},
       {"inputSchema",{{"type","object"},{"required",{"file","addr"}},{"properties",{
         {"file",{{"type","string"},{"description","Path to binary file"}}},
         {"addr",{{"type","string"},{"description","Start address"}}},
         {"depth",{{"type","integer"},{"default",50},{"description","Max analysis depth (instructions)"}}},
         {"analyze",{{"type","string"},{"default","full"},{"description","Analysis level"}}},
         {"timeout",{{"type","integer"},{"default",120},{"description","Timeout"}}}
       }}}}},

      /* ─── Android System / Utility Tools ─── */
      {{"name","read_logcat"},
       {"description",
        "\xf0\x9f\x93\x9d [Logcat] Read Android system log.\n"
        "Supports filtering by tag, priority, package, and line count.\n"
        "priority: V(verbose) D(debug) I(info) W(warn) E(error) F(fatal)\n"
        "Examples:\n"
        "  {lines:50}  -- last 50 lines\n"
        "  {tag:\"ActivityManager\", priority:\"I\"}\n"
        "  {pkg:\"com.game.app\", lines:100}\n"
        "  {grep:\"crash|exception\", priority:\"E\"}"},
       {"inputSchema",{{"type","object"},{"properties",{
         {"lines",{{"type","integer"},{"default",50},{"description","Number of recent lines"}}},
         {"tag",{{"type","string"},{"description","Filter by log tag"}}},
         {"priority",{{"type","string"},{"default","D"},{"description","Min priority: V/D/I/W/E/F"}}},
         {"pkg",{{"type","string"},{"description","Filter by package name (uses --pid)"}}},
         {"grep",{{"type","string"},{"description","Grep filter pattern"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}},

      {{"name","sqlite_query"},
       {"description",
        "\xf0\x9f\x97\x84 [SQLite] Execute SQL query on a database file.\n"
        "Uses Python sqlite3 module. Supports SELECT, .tables, .schema.\n"
        "Common Android databases:\n"
        "  /data/data/<pkg>/databases/*.db\n"
        "  /data/data/<pkg>/shared_prefs/ (XML, not DB)\n"
        "Examples:\n"
        "  {db:\"/data/data/com.app/databases/data.db\", sql:\"SELECT * FROM users LIMIT 10\"}\n"
        "  {db:\"/data/data/com.app/databases/data.db\", sql:\".tables\"}\n"
        "  {db:\"/data/data/com.app/databases/data.db\", sql:\".schema users\"}"},
       {"inputSchema",{{"type","object"},{"required",{"db","sql"}},{"properties",{
         {"db",{{"type","string"},{"description","Path to .db file"}}},
         {"sql",{{"type","string"},{"description","SQL query or .tables/.schema"}}},
         {"limit",{{"type","integer"},{"default",100},{"description","Max rows"}}},
         {"timeout",{{"type","integer"},{"default",15},{"description","Timeout"}}}
       }}}}},

      {{"name","termux_save_script"},
       {"description",
        "\xf0\x9f\x92\xbe [Save Script] Save code to file with correct permissions.\n"
        "Sets executable permission and Termux user ownership.\n"
        "Useful for saving analysis scripts, automation tools, etc.\n"
        "Example: {path:\"/sdcard/scan.py\", content:\"#!/usr/bin/env python3\\nprint('hello')\\n\", executable:true}"},
       {"inputSchema",{{"type","object"},{"required",{"path","content"}},{"properties",{
         {"path",{{"type","string"},{"description","Output file path"}}},
         {"content",{{"type","string"},{"description","File content"}}},
         {"executable",{{"type","boolean"},{"default",false},{"description","Make executable (chmod +x)"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}},

      {{"name","termux_command"},
       {"description",
        "\xf0\x9f\x92\xbb [Termux Cmd] Run command as Termux user (not root).\n"
        "Has access to Python, pip, node, gcc, etc.\n"
        "Useful as AI sandbox for running analysis scripts.\n"
        "Example: {command:\"python3 -c \\\"print(123)\\\"\"}"}, 
       {"inputSchema",{{"type","object"},{"required",{"command"}},{"properties",{
         {"command",{{"type","string"},{"description","Command to run in Termux env"}}},
         {"timeout",{{"type","integer"},{"default",30},{"description","Timeout"}}}
       }}}}},

      {{"name","os_list_dir"},
       {"description",
        "\xf0\x9f\x93\x81 [List Dir] List directory contents with root access.\n"
        "Shows: permissions, owner, size, date, name. Supports hidden files.\n"
        "Can access /data/data/<pkg>/ and other root-only directories.\n"
        "Example: {path:\"/data/data/com.game.app/files/\"}"},
       {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
         {"path",{{"type","string"},{"description","Directory path"}}},
         {"show_hidden",{{"type","boolean"},{"default",false},{"description","Show hidden files"}}},
         {"recursive",{{"type","boolean"},{"default",false},{"description","Recursive listing"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}},

      {{"name","os_read_file"},
       {"description",
        "\xf0\x9f\x93\x84 [Read File] Read file content with root access.\n"
        "Can read any file on the system including protected app data.\n"
        "mode: text (default), hex (hexdump), base64\n"
        "Example: {path:\"/data/data/com.game.app/shared_prefs/config.xml\"}"},
       {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
         {"path",{{"type","string"},{"description","File path"}}},
         {"mode",{{"type","string"},{"default","text"},{"description","Output mode: text/hex/base64"}}},
         {"lines",{{"type","integer"},{"description","Limit output lines"}}},
         {"timeout",{{"type","integer"},{"default",10},{"description","Timeout"}}}
       }}}}}
    });
}

/* ══════════ TOOL EXECUTOR ══════════ */
static json run_tool(const std::string& nm, const json& a, const Config& cfg,
                     const std::string& sid) {
    // --- shell_exec ---
    if (nm == "shell_exec") {
        std::string cmd = a.value("command", "");
        if (cmd.empty()) return terr("command required");
        int to = std::min(a.value("timeout", cfg.timeout_sec), 600);
        std::string cwd = a.value("workdir", cfg.work_dir);
        bool use_root = a.value("root", true);
        std::string final_cmd = cmd;
        if (use_root && check_root()) {
            final_cmd = wrap_root_cmd(cmd);
            LOGI("Tool", "shell_exec(root/b64): " + cmd.substr(0, 120));
        } else {
            LOGI("Tool", "shell_exec: " + cmd.substr(0, 120));
        }
        auto r = exec_cmd(final_cmd, to, cfg.max_out, cwd);
        json j = {{"exit_code", r.exit_code}, {"stdout", r.out},
                  {"stderr", r.err}, {"timed_out", r.timed_out}};
        if (!r.errmsg.empty()) j["error"] = r.errmsg;
        return tjson(j);
    }

    // --- shell_exec_async ---
    if (nm == "shell_exec_async") {
        std::string cmd = a.value("command", "");
        if (cmd.empty()) return terr("command required");
        int to = std::min(a.value("timeout", cfg.timeout_sec), 600);
        bool use_root = a.value("root", true);
        std::string final_cmd = cmd;
        if (use_root && check_root()) {
            final_cmd = wrap_root_cmd(cmd);
        }
        Config cc = cfg;
        cc.timeout_sec = to;
        std::string fc = final_cmd;
        std::string jid = submit(cmd.substr(0, 60),
            [fc, cc]() { return exec_cmd(fc, cc.timeout_sec, cc.max_out, cc.work_dir); });
        return tok("Job started.\njob_id: " + jid + "\nUse job_status to poll.");
    }

    // --- job_status ---
    if (nm == "job_status") {
        std::string jid = a.value("job_id", "");
        if (jid.empty()) return terr("job_id required");
        auto j = get_job(jid);
        if (!j) return terr("Job not found: " + jid);
        std::lock_guard<std::mutex> lk(j->mtx);
        json r = {{"job_id", jid}, {"done", j->done}, {"description", j->cmd_desc},
                  {"exit_code", j->result.exit_code}, {"stdout", j->result.out},
                  {"stderr", j->result.err}, {"timed_out", j->result.timed_out},
                  {"error", j->result.errmsg}};
        return tjson(r);
    }

    // --- job_list ---
    if (nm == "job_list") {
        json jobs = json::array();
        std::lock_guard<std::mutex> lk(g_jmtx);
        for (auto& kv : g_jobs) {
            std::unique_lock<std::mutex> jl(kv.second->mtx, std::try_to_lock);
            if (jl.owns_lock())
                jobs.push_back({{"job_id", kv.first}, {"done", kv.second->done},
                               {"description", kv.second->cmd_desc},
                               {"exit_code", kv.second->result.exit_code}});
        }
        return tjson({{"count", (int)jobs.size()}, {"jobs", jobs}});
    }

    // --- ssh_exec ---
    if (nm == "ssh_exec") {
        std::string cmd = a.value("command", "");
        if (cmd.empty()) return terr("command required");
        Config sc = cfg;
        if (a.contains("host") && a["host"].is_string()) sc.ssh_host = a["host"];
        if (a.contains("port") && a["port"].is_number()) sc.ssh_port = a["port"];
        if (a.contains("user") && a["user"].is_string()) sc.ssh_user = a["user"];
        int to = a.value("timeout", 60);
        LOGI("Tool", "ssh_exec: " + cmd.substr(0, 120));
        auto r = exec_cmd(build_ssh(sc, cmd), to, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"stdout", r.out},
                  {"stderr", r.err}, {"timed_out", r.timed_out}};
        if (!r.errmsg.empty()) j["error"] = r.errmsg;
        return tjson(j);
    }

    // --- interactive_session ---
    if (nm == "interactive_session") {
        std::string action = a.value("action", "");

        if (action == "start") {
            std::string cmd = a.value("command", "bash");
            std::string cwd = a.value("workdir", cfg.work_dir);
            auto s = create_session(cmd, cwd);
            if (!s) return terr("Failed to create PTY session");
            std::string initial = session_read(s, 1000);
            return tjson({{"session_id", s->id}, {"status", "started"},
                         {"command", cmd}, {"initial_output", initial}});
        }

        if (action == "send") {
            std::string sess_id = a.value("session_id", "");
            std::string input = a.value("input", "");
            int tmo = a.value("timeout", 2000);
            if (sess_id.empty()) return terr("session_id required");
            std::shared_ptr<InteractiveSession> s;
            {
                std::lock_guard<std::mutex> lk(g_sess_mtx);
                auto it = g_sessions.find(sess_id);
                if (it != g_sessions.end()) s = it->second;
            }
            if (!s || !s->alive) return terr("Session not found or dead: " + sess_id);
            session_write(s, input);
            std::string out = session_read(s, tmo);
            return tjson({{"session_id", sess_id}, {"alive", (bool)s->alive}, {"output", out}});
        }

        if (action == "read") {
            std::string sess_id = a.value("session_id", "");
            int tmo = a.value("timeout", 2000);
            if (sess_id.empty()) return terr("session_id required");
            std::shared_ptr<InteractiveSession> s;
            {
                std::lock_guard<std::mutex> lk(g_sess_mtx);
                auto it = g_sessions.find(sess_id);
                if (it != g_sessions.end()) s = it->second;
            }
            if (!s || !s->alive) return terr("Session not found or dead: " + sess_id);
            std::string out = session_read(s, tmo);
            return tjson({{"session_id", sess_id}, {"alive", (bool)s->alive}, {"output", out}});
        }

        if (action == "kill") {
            std::string sess_id = a.value("session_id", "");
            if (sess_id.empty()) return terr("session_id required");
            std::shared_ptr<InteractiveSession> s;
            {
                std::lock_guard<std::mutex> lk(g_sess_mtx);
                auto it = g_sessions.find(sess_id);
                if (it != g_sessions.end()) {
                    s = it->second;
                    g_sessions.erase(it);
                }
            }
            if (!s) return terr("Session not found: " + sess_id);
            {
                std::lock_guard<std::mutex> lk(s->mtx);
                session_kill(s);
            }
            return tok("Session killed: " + sess_id);
        }

        if (action == "list") {
            json arr = json::array();
            std::lock_guard<std::mutex> lk(g_sess_mtx);
            for (auto& kv : g_sessions)
                arr.push_back({{"session_id", kv.first},
                              {"command", kv.second->cmd_name},
                              {"alive", (bool)kv.second->alive}});
            return tjson({{"count", (int)arr.size()}, {"sessions", arr}});
        }

        return terr("Unknown action: " + action + ". Use: start|send|read|kill|list");
    }

    // --- file_read ---
    if (nm == "file_read") {
        std::string path = a.value("path", "");
        if (path.empty()) return terr("path required");
        std::string enc = a.value("encoding", "text");
        std::ifstream f(path, std::ios::binary);
        if (!f) return terr("Cannot open: " + path + " (" + strerror(errno) + ")");
        std::string c((std::istreambuf_iterator<char>(f)), {});
        return tok(enc == "base64" ? b64enc(c) : c);
    }

    // --- file_write ---
    if (nm == "file_write") {
        std::string path = a.value("path", "");
        std::string content = a.value("content", "");
        if (path.empty()) return terr("path required");
        bool app = a.value("append", false);
        auto mode = std::ios::binary | (app ? std::ios::app : std::ios::trunc);
        std::ofstream f(path, mode);
        if (!f) return terr("Cannot write: " + path + " (" + strerror(errno) + ")");
        f.write(content.data(), content.size());
        return tok("Written " + std::to_string(content.size()) + " bytes to " + path);
    }

    // --- file_list ---
    if (nm == "file_list") {
        std::string path = a.value("path", cfg.work_dir);
        bool sh = a.value("show_hidden", false);
        DIR* d = opendir(path.c_str());
        if (!d) return terr("Cannot open dir: " + path + " (" + strerror(errno) + ")");
        json entries = json::array();
        struct dirent* de;
        while ((de = readdir(d)) != nullptr) {
            std::string n = de->d_name;
            if (!sh && !n.empty() && n[0] == '.') continue;
            if (n == "." || n == "..") continue;
            struct stat st{};
            stat((path + "/" + n).c_str(), &st);
            entries.push_back({{"name", n},
                              {"type", S_ISDIR(st.st_mode) ? "dir" : "file"},
                              {"size", (long long)st.st_size}});
        }
        closedir(d);
        std::sort(entries.begin(), entries.end(),
            [](const json& x, const json& y) {
                return x["name"].get<std::string>() < y["name"].get<std::string>();
            });
        return tjson({{"path", path}, {"count", (int)entries.size()}, {"entries", entries}});
    }

    // --- file_delete ---
    if (nm == "file_delete") {
        std::string path = a.value("path", "");
        if (path.empty()) return terr("path required");
        static const std::vector<std::string> forbidden = {"/","/data","/system","/vendor","/sdcard"};
        for (auto& fp : forbidden)
            if (path == fp) return terr("Refusing to delete: " + path);
        bool rec = a.value("recursive", false);
        std::string flag = rec ? "-rf" : "-f";
        std::string rm_cmd = "rm " + flag + " '" + sq_esc(path) + "'";
        auto r = exec_cmd(rm_cmd, 30, 65536);
        if (r.exit_code != 0) return terr("Delete failed: " + r.err);
        return tok("Deleted: " + path);
    }

    // --- sys_info ---
    if (nm == "sys_info") {
        auto run = [&](const std::string& c) {
            auto r = exec_cmd(c, 10, 65536);
            return trim(r.out + r.err);
        };
        json info = {
            {"version", VERSION},
            {"uname", run("uname -a")},
            {"uptime", run("uptime")},
            {"cpu", run("nproc && cat /proc/cpuinfo | grep -m2 'model name'")},
            {"memory", run("free -h 2>/dev/null || cat /proc/meminfo | head -4")},
            {"disk", run("df -h /data 2>/dev/null | tail -1")},
            {"android_model", run("getprop ro.product.model 2>/dev/null")},
            {"android_version", run("getprop ro.build.version.release 2>/dev/null")},
            {"hostname", run("hostname")},
            {"whoami", run("whoami")},
            {"root_available", check_root()},
            {"termux_prefix", TERMUX_PREFIX},
            {"stackplz_available", access(stackplz_path().c_str(), X_OK) == 0},
            {"paradise_available", access(paradise_path().c_str(), X_OK) == 0}
        };
        return tjson(info);
    }

    // --- process_list ---
    if (nm == "process_list") {
        std::string filter = a.value("filter", "");
        std::string cmd;
        if (check_root())
            cmd = wrap_root_cmd("ps -A 2>/dev/null || ps aux 2>/dev/null || ps");
        else
            cmd = "ps -ef 2>/dev/null || ps aux 2>/dev/null || ps";
        if (!filter.empty()) {
            std::string safe_filter;
            for (char c : filter) {
                if (std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ':')
                    safe_filter += c;
            }
            if (!safe_filter.empty())
                cmd += " | grep -i '" + safe_filter + "'";
        }
        auto r = exec_cmd(cmd, 15, 512 * 1024);
        return tok(r.out + r.err);
    }

    // --- sequentialthinking ---
    if (nm == "sequentialthinking") return do_think(a, sid);

    /* ═══════════════════════════════════════════
     *  stackplz: eBPF Tracing Tool
     * ═══════════════════════════════════════════ */
    /* ═══════════════════════════════════════════
     *  stackplz Tools (8 tools)
     * ═══════════════════════════════════════════ */

    // Helper: build common stackplz flags
    auto build_splz_common = [&](const json& args) -> std::string {
        std::string cmd = "";
        std::string name = args.value("name", "");
        if (!name.empty()) cmd += " --name '" + sq_esc(name) + "'";
        if (args.contains("pid") && args["pid"].is_string()) cmd += " --pid " + args["pid"].get<std::string>();
        if (args.contains("tid") && args["tid"].is_string()) cmd += " --tid " + args["tid"].get<std::string>();
        if (args.contains("tname") && args["tname"].is_string()) cmd += " --tname '" + sq_esc(args["tname"]) + "'";
        if (args.contains("uid") && args["uid"].is_string()) cmd += " --uid " + args["uid"].get<std::string>();
        if (args.contains("no_pid") && args["no_pid"].is_string()) cmd += " --no-pid " + args["no_pid"].get<std::string>();
        if (args.contains("no_tid") && args["no_tid"].is_string()) cmd += " --no-tid " + args["no_tid"].get<std::string>();
        if (args.contains("no_tname") && args["no_tname"].is_string()) cmd += " --no-tname '" + sq_esc(args["no_tname"]) + "'";
        if (args.contains("out") && args["out"].is_string()) cmd += " -o '" + sq_esc(args["out"]) + "'";
        if (args.value("json_fmt", false)) cmd += " --json";
        if (args.value("debug", false)) cmd += " --debug";
        if (args.value("quiet", false)) cmd += " --quiet";
        if (args.value("stack", false)) cmd += " --stack";
        if (args.contains("stack_size") && args["stack_size"].is_number()) cmd += " --stack-size " + std::to_string(args["stack_size"].get<int>());
        if (args.value("regs", false)) cmd += " --regs";
        if (args.value("getoff", false)) cmd += " --getoff";
        if (args.value("showpc", false)) cmd += " --showpc";
        if (args.value("showtime", false)) cmd += " --showtime";
        if (args.value("showuid", false)) cmd += " --showuid";
        if (args.value("dumphex", false)) cmd += " --dumphex";
        if (args.value("color", false)) cmd += " --color";
        if (args.contains("buffer") && args["buffer"].is_number()) cmd += " --buffer " + std::to_string(args["buffer"].get<int>());
        return cmd;
    };

    auto run_splz = [&](const std::string& cmd, int timeout) -> json {
        std::string full = "cd '" + g_self_dir + "' && timeout " + std::to_string(timeout) + " " + stackplz_path() + " " + cmd + " 2>&1";
        LOGI("Tool", "stackplz: " + cmd.substr(0, 200));
        auto r = run_root_cmd(full, timeout + 5, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out + r.err},
                  {"command", cmd}, {"timed_out", r.timed_out}};
        return tjson(j);
    };

    // run_splz_file: redirect output to file (workaround for stackplz -o path bug)
    auto run_splz_file = [&](const std::string& cmd, const std::string& outfile, int timeout) -> json {
        // Use shell redirect instead of stackplz -o (which joins cwd+path even for absolute paths)
        std::string full = "cd '" + g_self_dir + "' && timeout " + std::to_string(timeout) + " " + stackplz_path() + " " + cmd + " > '" + sq_esc(outfile) + "' 2>&1";
        LOGI("Tool", "stackplz_file: " + cmd.substr(0, 200) + " -> " + outfile);
        auto r = run_root_cmd(full, timeout + 5, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out + r.err},
                  {"command", cmd}, {"output_file", outfile}, {"timed_out", r.timed_out}};
        return tjson(j);
    };

    // ── trace_syscall ──
    if (nm == "trace_syscall") {
        std::string name = a.value("name", "");
        std::string syscall = a.value("syscall", "");
        if (name.empty() || syscall.empty()) return terr("name and syscall required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        cmd += " --syscall '" + sq_esc(syscall) + "'";
        if (a.contains("no_syscall") && a["no_syscall"].is_string()) cmd += " --no-syscall '" + sq_esc(a["no_syscall"]) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        return run_splz(cmd, to);
    }

    // ── trace_uprobe ──
    if (nm == "trace_uprobe") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        if (!a.contains("point") || !a["point"].is_array() || a["point"].empty()) return terr("point array required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        if (a.contains("maxop") && a["maxop"].is_number()) cmd += " --maxop " + std::to_string(a["maxop"].get<int>());
        if (a.value("dumpret", false)) cmd += " --dumpret";
        return run_splz(cmd, to);
    }

    // ── trace_config ──
    if (nm == "trace_config") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        if (!a.contains("config") || !a["config"].is_array()) return terr("config array required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        for (auto& c : a["config"]) if (c.is_string()) cmd += " --config '" + sq_esc(c.get<std::string>()) + "'";
        return run_splz(cmd, to);
    }

    // ── hw_breakpoint ──
    if (nm == "hw_breakpoint") {
        std::string name = a.value("name", "");
        std::string brk = a.value("brk", "");
        if (name.empty() || brk.empty()) return terr("name and brk required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        cmd += " --brk " + brk;
        if (a.contains("brk_lib") && a["brk_lib"].is_string()) {
            cmd += " --brk-lib '" + sq_esc(a["brk_lib"]) + "'";
            // stackplz requires --pid when using --brk-lib; auto-resolve from package name
            if (!a.contains("pid") || !a["pid"].is_string()) {
                auto pid_r = run_root_cmd("pidof '" + sq_esc(name) + "' 2>/dev/null | tr ' ' '\n' | head -1", 5, 128);
                std::string auto_pid = pid_r.out;
                auto_pid.erase(auto_pid.find_last_not_of(" \t\r\n") + 1); // trim
                if (!auto_pid.empty()) {
                    cmd += " --pid " + auto_pid;
                    LOGI("Tool", "hw_breakpoint: auto-resolved PID=" + auto_pid + " for " + name);
                }
            }
        }
        if (a.contains("brk_len") && a["brk_len"].is_number()) cmd += " --brk-len " + std::to_string(a["brk_len"].get<int>());
        if (a.contains("brk_pid") && a["brk_pid"].is_number()) cmd += " --brk-pid " + std::to_string(a["brk_pid"].get<int>());
        return run_splz(cmd, to);
    }

    // ── trace_signal ──
    if (nm == "trace_signal") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        if (!a.contains("point") || !a["point"].is_array()) return terr("point required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("signal") && a["signal"].is_string()) cmd += " --kill " + a["signal"].get<std::string>();
        if (a.contains("tkill") && a["tkill"].is_string()) cmd += " --tkill " + a["tkill"].get<std::string>();
        if (a.value("auto_resume", false)) cmd += " --auto";
        return run_splz(cmd, to);
    }

    // ── perf_dump ──
    if (nm == "perf_dump") {
        std::string name = a.value("name", "");
        std::string dump_file = a.value("dump_file", "");
        if (name.empty() || dump_file.empty()) return terr("name and dump_file required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        // Workaround: stackplz --dump joins cwd+path even for absolute paths
        // Solution: use just the basename, then move the file to the real destination
        std::string dump_basename = "_perf_dump_" + dump_file.substr(dump_file.rfind('/') + 1);
        cmd += " --dump '" + sq_esc(dump_basename) + "'";
        if (a.contains("syscall") && a["syscall"].is_string()) cmd += " --syscall '" + sq_esc(a["syscall"]) + "'";
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        if (a.contains("point") && a["point"].is_array())
            for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        auto result = run_splz(cmd, to);
        // Move dump file from tools dir to actual destination
        std::string mv_cmd = "mv '" + g_self_dir + "/" + sq_esc(dump_basename) + "' '" + sq_esc(dump_file) + "' 2>/dev/null";
        run_root_cmd(mv_cmd, 10, 1024);
        return result;
    }

    // ── perf_parse ──
    if (nm == "perf_parse") {
        std::string parse_file = a.value("parse_file", "");
        if (parse_file.empty()) return terr("parse_file required");
        int to = std::min(a.value("timeout", 30), 300);
        std::string cmd = "";
        // Workaround: stackplz --parse may also have cwd path join issue
        // Copy parse file to tools dir first, then parse
        std::string parse_basename = "_perf_parse_" + parse_file.substr(parse_file.rfind('/') + 1);
        std::string cp_cmd = "cp '" + sq_esc(parse_file) + "' '/data/adb/mcp_re/tools/" + sq_esc(parse_basename) + "' 2>/dev/null";
        run_root_cmd(cp_cmd, 30, 1024);
        cmd += " --parse '" + sq_esc(parse_basename) + "'";
        if (a.value("json_fmt", false)) cmd += " --json";
        return run_splz(cmd, to);
    }

    // ── stackplz_raw ──
    if (nm == "stackplz_raw") {
        std::string args = a.value("args", "");
        if (args.empty()) return terr("args required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = args;
        return run_splz(cmd, to);
    }
    // ── trace_offset ── (NEW)
    if (nm == "trace_offset") {
        std::string name = a.value("name", "");
        std::string lib = a.value("lib", "");
        std::string offset = a.value("offset", "");
        if (name.empty() || lib.empty() || offset.empty()) return terr("name, lib and offset required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        cmd += " --lib '" + sq_esc(lib) + "'";
        std::string point_spec = "+" + offset;
        if (a.contains("arg_types") && a["arg_types"].is_string()) {
            point_spec += "[" + a["arg_types"].get<std::string>() + "]";
        }
        cmd += " --point '" + sq_esc(point_spec) + "'";
        return run_splz(cmd, to);
    }

    // ── trace_register ── (NEW)
    if (nm == "trace_register") {
        std::string name = a.value("name", "");
        std::string reg = a.value("reg", "");
        if (name.empty() || reg.empty()) return terr("name and reg required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        std::string lib = a.value("lib", "libc.so");
        cmd += " --lib '" + sq_esc(lib) + "'";
        if (a.contains("offset") && a["offset"].is_string()) {
            cmd += " --point '+" + a["offset"].get<std::string>() + "'";
        } else if (a.contains("point") && a["point"].is_string()) {
            cmd += " --point '" + sq_esc(a["point"].get<std::string>()) + "'";
        } else {
            return terr("offset or point required");
        }
        cmd += " --regs --reg " + reg;
        return run_splz(cmd, to);
    }

    // ── trace_return ── (NEW)
    if (nm == "trace_return") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        std::string lib = a.value("lib", "libc.so");
        cmd += " --lib '" + sq_esc(lib) + "'";
        if (a.contains("offset") && a["offset"].is_string()) {
            cmd += " --point '+" + a["offset"].get<std::string>() + "'";
        } else if (a.contains("point") && a["point"].is_string()) {
            cmd += " --point '" + sq_esc(a["point"].get<std::string>()) + "'";
        } else {
            return terr("offset or point required");
        }
        cmd += " --dumpret";
        return run_splz(cmd, to);
    }

    // ── trace_hexdump ── (NEW)
    if (nm == "trace_hexdump") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        if (!a.contains("point") || !a["point"].is_array() || a["point"].empty()) return terr("point array required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        cmd += " --dumphex";
        return run_splz(cmd, to);
    }

    // ── trace_log ── (NEW)
    if (nm == "trace_log") {
        std::string name = a.value("name", "");
        std::string log_file = a.value("log_file", "");
        if (name.empty() || log_file.empty()) return terr("name and log_file required");
        int to = std::min(a.value("timeout", 300), 600);
        std::string cmd = build_splz_common(a);
        // Add syscall or point
        if (a.contains("syscall") && a["syscall"].is_string()) {
            cmd += " --syscall '" + sq_esc(a["syscall"]) + "'";
            if (a.contains("no_syscall") && a["no_syscall"].is_string())
                cmd += " --no-syscall '" + sq_esc(a["no_syscall"]) + "'";
        }
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        if (a.contains("point") && a["point"].is_array())
            for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        // Use shell redirect (stackplz -o has cwd path join bug)
        cmd += " --quiet";
        return run_splz_file(cmd, log_file, to);
    }

    // ── trace_thread ── (NEW)
    if (nm == "trace_thread") {
        std::string name = a.value("name", "");
        if (name.empty()) return terr("name required");
        bool has_syscall = a.contains("syscall") && a["syscall"].is_string();
        bool has_point = a.contains("point") && a["point"].is_array();
        if (!has_syscall && !has_point) return terr("syscall or point required");
        int to = std::min(a.value("timeout", 60), 600);
        std::string cmd = build_splz_common(a);
        if (has_syscall) {
            cmd += " --syscall '" + sq_esc(a["syscall"]) + "'";
            if (a.contains("no_syscall") && a["no_syscall"].is_string())
                cmd += " --no-syscall '" + sq_esc(a["no_syscall"]) + "'";
        }
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        if (has_point)
            for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        return run_splz(cmd, to);
    }

    // ── trace_uid ── (NEW)
    if (nm == "trace_uid") {
        std::string uid = a.value("uid", "");
        if (uid.empty()) return terr("uid required");
        int to = std::min(a.value("timeout", 60), 600);
        // Build command manually since build_splz_common uses --name
        std::string cmd = "";
        cmd += " --uid " + uid;
        if (a.contains("pid") && a["pid"].is_string()) cmd += " --pid " + a["pid"].get<std::string>();
        if (a.contains("tid") && a["tid"].is_string()) cmd += " --tid " + a["tid"].get<std::string>();
        if (a.contains("tname") && a["tname"].is_string()) cmd += " --tname '" + sq_esc(a["tname"]) + "'";
        if (a.contains("no_pid") && a["no_pid"].is_string()) cmd += " --no-pid " + a["no_pid"].get<std::string>();
        if (a.contains("no_tid") && a["no_tid"].is_string()) cmd += " --no-tid " + a["no_tid"].get<std::string>();
        if (a.contains("no_tname") && a["no_tname"].is_string()) cmd += " --no-tname '" + sq_esc(a["no_tname"]) + "'";
        if (a.contains("out") && a["out"].is_string()) cmd += " -o '" + sq_esc(a["out"]) + "'";
        if (a.value("json_fmt", false)) cmd += " --json";
        if (a.value("debug", false)) cmd += " --debug";
        if (a.value("stack", false)) cmd += " --stack";
        if (a.value("regs", false)) cmd += " --regs";
        if (a.contains("buffer") && a["buffer"].is_number()) cmd += " --buffer " + std::to_string(a["buffer"].get<int>());
        // syscall or uprobe
        if (a.contains("syscall") && a["syscall"].is_string()) {
            cmd += " --syscall '" + sq_esc(a["syscall"]) + "'";
            if (a.contains("no_syscall") && a["no_syscall"].is_string())
                cmd += " --no-syscall '" + sq_esc(a["no_syscall"]) + "'";
        }
        if (a.contains("lib") && a["lib"].is_string()) cmd += " --lib '" + sq_esc(a["lib"]) + "'";
        if (a.contains("point") && a["point"].is_array())
            for (auto& p : a["point"]) if (p.is_string()) cmd += " --point '" + sq_esc(p.get<std::string>()) + "'";
        if (a.contains("filter") && a["filter"].is_array())
            for (auto& f : a["filter"]) if (f.is_string()) cmd += " --filter '" + sq_esc(f.get<std::string>()) + "'";
        return run_splz(cmd, to);
    }


    /* ═══════════════════════════════════════════
     *  Paradise Memory Tools
     * ═══════════════════════════════════════════ */

    // Helper lambda to run paradise_tool command
    auto run_paradise = [&](const std::string& pkg, const std::string& subcmd, int timeout) -> json {
        std::string cmd = "cd '" + g_self_dir + "' && " + paradise_path() + " -p '" + sq_esc(pkg) + "' " + subcmd + " 2>&1";
        LOGI("Tool", "paradise: " + subcmd.substr(0, 120));
        auto r = run_root_cmd(cmd, timeout, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}};
        if (!r.errmsg.empty()) j["error"] = r.errmsg;
        return tjson(j);
    };

    // --- mem_maps ---
    if (nm == "mem_maps") {
        std::string pkg = a.value("pkg", "");
        if (pkg.empty()) return terr("pkg required");
        std::string subcmd = "info";
        if (a.contains("filter") && a["filter"].is_string()) subcmd += " " + a["filter"].get<std::string>();
        return run_paradise(pkg, subcmd, a.value("timeout", 30));
    }

    // --- mem_module ---
    if (nm == "mem_module") {
        std::string pkg = a.value("pkg", "");
        std::string mod = a.value("module", "");
        if (pkg.empty() || mod.empty()) return terr("pkg and module required");
        return run_paradise(pkg, "module '" + sq_esc(mod) + "'", a.value("timeout", 15));
    }

    // --- mem_offset ---
    if (nm == "mem_offset") {
        std::string pkg = a.value("pkg", "");
        std::string mod = a.value("module", "");
        std::string off = a.value("offset", "");
        if (pkg.empty() || mod.empty() || off.empty()) return terr("pkg, module, offset required");
        return run_paradise(pkg, "offset '" + sq_esc(mod) + "' " + off, a.value("timeout", 15));
    }


    // --- mem_read ---
    if (nm == "mem_read") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        std::string type = a.value("type", "");
        if (pkg.empty() || addr.empty() || type.empty()) return terr("pkg, addr, type required");
        int count = a.value("count", 1);
        bool gg = a.value("gg_mode", false);
        std::string subcmd = "read " + addr + " " + type;
        if (count > 1) subcmd += " " + std::to_string(count);
        if (gg) subcmd += " --gg";
        return run_paradise(pkg, subcmd, a.value("timeout", 15));
    }

    // --- mem_write ---
    if (nm == "mem_write") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        std::string type = a.value("type", "");
        if (pkg.empty() || addr.empty() || type.empty()) return terr("pkg, addr, type required");
        if (!a.contains("values") || !a["values"].is_array() || a["values"].empty())
            return terr("values array required");
        std::string subcmd = "write " + addr + " " + type;
        for (auto& v : a["values"]) {
            if (v.is_string()) subcmd += " '" + sq_esc(v.get<std::string>()) + "'";
            else if (v.is_number()) subcmd += " " + std::to_string(v.get<double>());
        }
        return run_paradise(pkg, subcmd, a.value("timeout", 15));
    }

    // --- mem_asm_write ---
    if (nm == "mem_asm_write") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        std::string asm_text = a.value("asm_text", "");
        if (pkg.empty() || addr.empty() || asm_text.empty()) return terr("pkg, addr, asm_text required");
        std::string subcmd = "asm_write " + addr + " '" + sq_esc(asm_text) + "'";
        return run_paradise(pkg, subcmd, a.value("timeout", 15));
    }

    // --- mem_scan ---
    if (nm == "mem_scan") {
        std::string pkg = a.value("pkg", "");
        std::string type = a.value("type", "");
        if (pkg.empty() || type.empty()) return terr("pkg, type required");

        std::string subcmd;
        bool is_range = a.contains("min") && a.contains("max");

        if (is_range) {
            subcmd = "scan_range " + type + " " + a["min"].get<std::string>() + " " + a["max"].get<std::string>();
        } else {
            std::string value = a.value("value", "");
            if (value.empty()) return terr("value required for exact scan (or min+max for range)");
            subcmd = "scan " + type + " " + value;
        }

        // Filters
        if (a.contains("scan_filter") && a["scan_filter"].is_string()) {
            std::string sf = a["scan_filter"].get<std::string>();
            subcmd += " " + sf;
        }
        if (a.contains("range_start") && a.contains("range_end")) {
            subcmd += " --range " + a["range_start"].get<std::string>() + " " + a["range_end"].get<std::string>();
        }
        if (a.contains("limit") && a["limit"].is_number()) {
            subcmd += " --limit " + std::to_string(a["limit"].get<int>());
        }

        return run_paradise(pkg, subcmd, a.value("timeout", 120));
    }

    // --- mem_scan_range ---
    if (nm == "mem_scan_range") {
        std::string pkg = a.value("pkg", "");
        std::string type = a.value("type", "");
        std::string mn = a.value("min", "");
        std::string mx = a.value("max", "");
        if (pkg.empty() || type.empty() || mn.empty() || mx.empty()) return terr("pkg, type, min, max required");
        std::string subcmd = "scan_range " + type + " " + mn + " " + mx;
        if (a.contains("scan_filter") && a["scan_filter"].is_string()) subcmd += " " + a["scan_filter"].get<std::string>();
        if (a.contains("range_start") && a.contains("range_end"))
            subcmd += " --range " + a["range_start"].get<std::string>() + " " + a["range_end"].get<std::string>();
        if (a.contains("limit") && a["limit"].is_number()) subcmd += " --limit " + std::to_string(a["limit"].get<int>());
        return run_paradise(pkg, subcmd, a.value("timeout", 120));
    }


    // --- mem_disasm ---
    if (nm == "mem_disasm") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        if (pkg.empty() || addr.empty()) return terr("pkg, addr required");
        int count = a.value("count", 16);
        std::string subcmd = "disasm " + addr + " " + std::to_string(count);
        return run_paradise(pkg, subcmd, a.value("timeout", 15));
    }

    // --- mem_ptr ---
    if (nm == "mem_ptr") {
        std::string pkg = a.value("pkg", "");
        std::string base = a.value("base", "");
        if (pkg.empty() || base.empty()) return terr("pkg, base required");
        if (!a.contains("offsets") || !a["offsets"].is_array() || a["offsets"].empty())
            return terr("offsets array required");

        std::string subcmd = "ptr " + base;
        for (auto& off : a["offsets"]) {
            if (off.is_string()) subcmd += " " + off.get<std::string>();
        }
        if (a.contains("type") && a["type"].is_string()) subcmd += " " + a["type"].get<std::string>();
        return run_paradise(pkg, subcmd, a.value("timeout", 15));
    }

    // --- mem_dump ---
    if (nm == "mem_dump") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        std::string size = a.value("size", "");
        std::string file = a.value("file", "");
        if (pkg.empty() || addr.empty() || size.empty() || file.empty())
            return terr("pkg, addr, size, file required");
        std::string subcmd = "dump " + addr + " " + size + " '" + sq_esc(file) + "'";
        return run_paradise(pkg, subcmd, a.value("timeout", 120));
    }

    // --- mem_hexdump ---
    if (nm == "mem_hexdump") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        std::string size = a.value("size", "");
        if (pkg.empty() || addr.empty() || size.empty()) return terr("pkg, addr, size required");
        int cols = a.value("cols", 16);
        std::string subcmd = "hexdump " + addr + " " + size + " " + std::to_string(cols);
        return run_paradise(pkg, subcmd, a.value("timeout", 30));
    }

    // --- mem_brk ---
    if (nm == "mem_brk") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        if (pkg.empty() || addr.empty()) return terr("pkg, addr required");
        std::string type = a.value("type", "x");
        int to = std::min(a.value("timeout", 60), 600);

        std::string subcmd = "brk " + addr + " " + type;

        return run_paradise(pkg, subcmd, to);
    }

    // --- mem_chain_trace ---
    if (nm == "mem_chain_trace") {
        std::string pkg = a.value("pkg", "");
        std::string addr = a.value("addr", "");
        if (pkg.empty() || addr.empty()) return terr("pkg, addr required");
        int depth = a.value("depth", 8);
        int timeout_brk = a.value("timeout_per_brk", 30);
        int to = std::min(a.value("timeout", 300), 600);

        std::string subcmd = "chain_trace " + addr +
                             " --depth " + std::to_string(depth) +
                             " --timeout " + std::to_string(timeout_brk);
        return run_paradise(pkg, subcmd, to);
    }



    /* ═══════════════════════════════════════════
     *  Radare2 Static Analysis Tools
     * ═══════════════════════════════════════════ */

    // Helper: run r2 command
    auto run_r2 = [&](const std::string& file, const std::string& commands,
                      const std::string& analyze, int timeout) -> json {
        std::string r2 = r2_bin();
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string ana_cmd;
        if (analyze == "basic") ana_cmd = "aa;";
        else if (analyze == "full") ana_cmd = "aaa;";
        // else none
        std::string full = env + " " + r2 + " -q -e bin.cache=true -e scr.color=0 -c '"
            + ana_cmd + commands + "' '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        LOGI("Tool", "r2: " + commands.substr(0, 150));
        auto r = run_root_cmd(full, timeout, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out},
                  {"timed_out", r.timed_out}};
        if (!r.errmsg.empty()) j["error"] = r.errmsg;
        return tjson(j);
    };

    // Helper: run rabin2
    auto run_rabin2 = [&](const std::string& file, const std::string& flags, int timeout) -> json {
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin() + " " + flags + " '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        LOGI("Tool", "rabin2: " + flags);
        auto r = run_root_cmd(full, timeout, cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out},
                  {"timed_out", r.timed_out}};
        if (!r.errmsg.empty()) j["error"] = r.errmsg;
        return tjson(j);
    };

    // --- r2_info ---
    if (nm == "r2_info") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        return run_r2(file, "iI", "none", a.value("timeout", 15));
    }

    // --- r2_strings ---
    if (nm == "r2_strings") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string mode = a.value("mode", "data");
        int min_len = a.value("min_len", 5);
        int limit = a.value("limit", 500);
        std::string filter = a.value("filter", "");
        std::string cmd_str;
        if (mode == "all") cmd_str = "izz";
        else if (mode == "raw") cmd_str = "izzz";
        else cmd_str = "iz";
        // Apply min_len config
        std::string prefix = "e bin.str.min=" + std::to_string(min_len) + ";";
        std::string suffix = "";
        if (!filter.empty()) suffix += "~" + filter;
        suffix += "~:..";  // limit with head equivalent
        // Use rabin2 for speed (no need to open r2)
        std::string r2 = r2_bin();
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string full;
        if (mode == "data") {
            full = env + " " + rabin2_bin() + " -z -n " + std::to_string(min_len) + " '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        } else if (mode == "all") {
            full = env + " " + rabin2_bin() + " -zz -n " + std::to_string(min_len) + " '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        } else {
            full = env + " " + rabin2_bin() + " -zzz -n " + std::to_string(min_len) + " '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        }
        if (!filter.empty()) full += " | grep -i '" + sq_esc(filter) + "'";
        full += " | head -" + std::to_string(limit);
        LOGI("Tool", "r2_strings: mode=" + mode + " filter=" + filter);
        auto r = run_root_cmd(full, a.value("timeout", 30), cfg.max_out);
        json j = {{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}};
        return tjson(j);
    }

    // --- r2_imports ---
    if (nm == "r2_imports") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string filter = a.value("filter", "");
        int limit = a.value("limit", 500);
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin() + " -i '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        if (!filter.empty()) full += " | grep -i '" + sq_esc(filter) + "'";
        full += " | head -" + std::to_string(limit);
        auto r = run_root_cmd(full, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_exports ---
    if (nm == "r2_exports") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string filter = a.value("filter", "");
        int limit = a.value("limit", 500);
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin() + " -E '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        if (!filter.empty()) full += " | grep -i '" + sq_esc(filter) + "'";
        full += " | head -" + std::to_string(limit);
        auto r = run_root_cmd(full, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_symbols ---
    if (nm == "r2_symbols") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string filter = a.value("filter", "");
        int limit = a.value("limit", 500);
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin() + " -s '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        if (!filter.empty()) full += " | grep -i '" + sq_esc(filter) + "'";
        full += " | head -" + std::to_string(limit);
        auto r = run_root_cmd(full, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_sections ---
    if (nm == "r2_sections") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        return run_r2(file, "iS", "none", a.value("timeout", 15));
    }

    // --- r2_functions ---
    if (nm == "r2_functions") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string analyze = a.value("analyze", "basic");
        std::string filter = a.value("filter", "");
        int limit = a.value("limit", 500);
        std::string cmd = "afl";
        if (!filter.empty()) cmd += "~" + filter;
        // Build with limit
        std::string r2b = r2_bin();
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string ana_cmd;
        if (analyze == "full") ana_cmd = "aaa;";
        else ana_cmd = "aa;";
        std::string full = env + " " + r2b + " -q -e bin.cache=true -e scr.color=0 -c '"
            + ana_cmd + cmd + "' '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:' | head -" + std::to_string(limit);
        LOGI("Tool", "r2_functions: analyze=" + analyze + " filter=" + filter);
        auto r = run_root_cmd(full, a.value("timeout", 120), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_disasm ---
    if (nm == "r2_disasm") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        int count = std::min(a.value("count", 32), 1024);
        std::string analyze = a.value("analyze", "basic");
        std::string cmd = "s " + addr + "; pd " + std::to_string(count);
        return run_r2(file, cmd, analyze, a.value("timeout", 60));
    }

    // --- r2_decompile ---
    if (nm == "r2_decompile") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        std::string analyze = a.value("analyze", "basic");
        std::string cmd = "s " + addr + "; pdc";
        return run_r2(file, cmd, analyze, a.value("timeout", 120));
    }

    // --- r2_xrefs ---
    if (nm == "r2_xrefs") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        std::string direction = a.value("direction", "to");
        std::string analyze = a.value("analyze", "full");
        int limit = a.value("limit", 100);
        std::string cmd;
        if (direction == "from")
            cmd = "s " + addr + "; axf";
        else
            cmd = "s " + addr + "; axt";
        std::string r2b = r2_bin();
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string ana_cmd;
        if (analyze == "full") ana_cmd = "aaa;";
        else if (analyze == "basic") ana_cmd = "aa;";
        std::string full = env + " " + r2b + " -q -e bin.cache=true -e scr.color=0 -c '"
            + ana_cmd + cmd + "' '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:' | head -" + std::to_string(limit);
        auto r = run_root_cmd(full, a.value("timeout", 120), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_search ---
    if (nm == "r2_search") {
        std::string file = a.value("file", "");
        std::string search_type = a.value("search_type", "");
        std::string pattern = a.value("pattern", "");
        if (file.empty() || search_type.empty() || pattern.empty()) return terr("file, search_type, pattern required");
        int limit = a.value("limit", 100);
        std::string cmd;
        if (search_type == "string") cmd = "/ " + pattern;
        else if (search_type == "hex") cmd = "/x " + pattern;
        else if (search_type == "asm") cmd = "/c " + pattern;
        else if (search_type == "crypto") cmd = "/ca";  // crypto analysis
        else return terr("Invalid search_type. Use: string/hex/asm/crypto");
        std::string r2b = r2_bin();
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string full = env + " " + r2b + " -q -e bin.cache=true -e scr.color=0 -c '"
            + cmd + "' '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:' | head -" + std::to_string(limit);
        auto r = run_root_cmd(full, a.value("timeout", 30), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_hexdump ---
    if (nm == "r2_hexdump") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        int size = std::min(a.value("size", 256), 4096);
        std::string cmd = "s " + addr + "; px " + std::to_string(size);
        return run_r2(file, cmd, "none", a.value("timeout", 15));
    }

    // --- r2_entropy ---
    if (nm == "r2_entropy") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        // Use rahash2 for accurate entropy + r2 section entropy
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin().substr(0, rabin2_bin().size()-6) + "rahash2 -a entropy '" + sq_esc(file) + "' 2>&1";
        full += " && echo '---section entropy---' && ";
        full += env + " " + r2_bin() + " -q -e scr.color=0 -e bin.cache=true -c 'p=e 50' '" + sq_esc(file) + "' 2>&1 | grep -v WARN";
        auto r = run_root_cmd(full, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_cmd ---
    if (nm == "r2_cmd") {
        std::string file = a.value("file", "");
        std::string commands = a.value("commands", "");
        if (file.empty() || commands.empty()) return terr("file and commands required");
        std::string analyze = a.value("analyze", "none");
        return run_r2(file, commands, analyze, a.value("timeout", 120));
    }

    // --- r2_rabin ---
    if (nm == "r2_rabin") {
        std::string file = a.value("file", "");
        std::string flags = a.value("flags", "");
        if (file.empty() || flags.empty()) return terr("file and flags required");
        std::string filter = a.value("filter", "");
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string full = env + " " + rabin2_bin() + " " + flags + " '" + sq_esc(file) + "' 2>&1 | grep -v '^WARN:'";
        if (!filter.empty()) full += " | grep -i '" + sq_esc(filter) + "'";
        auto r = run_root_cmd(full, a.value("timeout", 30), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }



    /* ═══════════════════════════════════════════
     *  R2 Extra Tools (asm, diff, hash)
     * ═══════════════════════════════════════════ */

    // --- r2_asm ---
    if (nm == "r2_asm") {
        std::string c = a.value("code", "");
        if (c.empty()) return terr("code required");
        std::string dir = a.value("direction", "asm");
        std::string arch = a.value("arch", "arm");
        int bits = a.value("bits", 64);
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string rasm = g_self_dir + "/radare2/bin/rasm2";
        std::string full;
        if (dir == "disasm")
            full = env + " " + rasm + " -a " + arch + " -b " + std::to_string(bits) + " -d '" + sq_esc(c) + "' 2>&1";
        else
            full = env + " " + rasm + " -a " + arch + " -b " + std::to_string(bits) + " '" + sq_esc(c) + "' 2>&1";
        auto r = run_root_cmd(full, a.value("timeout", 10), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_diff ---
    if (nm == "r2_diff") {
        std::string f1 = a.value("file1", ""), f2 = a.value("file2", "");
        if (f1.empty() || f2.empty()) return terr("file1 and file2 required");
        std::string mode = a.value("mode", "bytes");
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string rdiff = g_self_dir + "/radare2/bin/radiff2";
        std::string flags = "";
        if (mode == "code") flags = "-c";
        else if (mode == "graph") flags = "-g main";
        std::string full = env + " " + rdiff + " " + flags + " '" + sq_esc(f1) + "' '" + sq_esc(f2) + "' 2>&1";
        auto r = run_root_cmd(full, a.value("timeout", 60), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- r2_hash ---
    if (nm == "r2_hash") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string algo = a.value("algo", "md5,sha256");
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "'";
        std::string rhash = g_self_dir + "/radare2/bin/rahash2";
        std::string full = env + " " + rhash + " -a " + algo + " '" + sq_esc(file) + "' 2>&1";
        auto r = run_root_cmd(full, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    /* ═══════════════════════════════════════════
     *  Android / Game RE Tools
     * ═══════════════════════════════════════════ */

    // --- find_jni_methods ---
    if (nm == "find_jni_methods") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        // 1) Find Java_* exports  2) Find JNI_OnLoad  3) Find RegisterNatives xrefs
        std::string full = "echo '=== JNI Static Exports ===' && " +
            env + " " + rabin2_bin() + " -E '" + sq_esc(file) + "' 2>/dev/null | grep -E 'Java_|JNI_OnLoad|JNI_OnUnload' && " +
            "echo '\n=== Dynamic Registration (RegisterNatives references) ===' && " +
            env + " " + r2_bin() + " -q -e bin.cache=true -e scr.color=0 -c 'aa;axt @ sym.imp.RegisterNatives 2>/dev/null; axt @ sym.imp._ZN7_JNIEnv15RegisterNativesEP7_jclassPK15JNINativeMethodi 2>/dev/null' '" + sq_esc(file) + "' 2>&1 | grep -v WARN";
        auto r = run_root_cmd(full, a.value("timeout", 30), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- apply_hex_patch ---
    if (nm == "apply_hex_patch") {
        std::string file = a.value("file", "");
        std::string offset = a.value("offset", "");
        std::string hex = a.value("hex", "");
        if (file.empty() || offset.empty() || hex.empty()) return terr("file, offset, hex required");
        // Python one-liner to patch binary
        std::string py = "python3 -c \"\nimport sys,shutil,os\nf='" + sq_esc(file) + "'\noff=" + offset + "\nhx='" + sq_esc(hex) + "'\ndata=bytes.fromhex(hx)\nif not os.path.exists(f+'.bak'): shutil.copy2(f,f+'.bak')\nwith open(f,'r+b') as fp:\n  fp.seek(off)\n  old=fp.read(len(data))\n  fp.seek(off)\n  fp.write(data)\nprint(f'Patched {len(data)} bytes at 0x{off:x}')\nprint(f'Old: {old.hex()}')\nprint(f'New: {data.hex()}')\nprint(f'Backup: {f}.bak')\n\"";
        auto r = run_root_cmd(py, a.value("timeout", 10), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- scan_crypto_signatures ---
    if (nm == "scan_crypto_signatures") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string env = "LD_LIBRARY_PATH='" + r2_lib() + "' R2_PREFIX='" + r2_prefix() + "'";
        std::string full = "echo '=== Crypto Constants Scan ===' && " +
            env + " " + r2_bin() + " -q -e bin.cache=true -e scr.color=0 -c '/ca' '" + sq_esc(file) + "' 2>&1 | grep -v WARN && " +
            "echo '\n=== Crypto-related Imports ===' && " +
            env + " " + rabin2_bin() + " -i '" + sq_esc(file) + "' 2>/dev/null | grep -iE 'crypt|aes|rsa|sha|md5|hmac|ssl|tls|cipher|encrypt|decrypt|hash|sign|verify|pkcs|x509|evp_|bio_' && " +
            "echo '\n=== Crypto-related Strings ===' && " +
            env + " " + rabin2_bin() + " -z '" + sq_esc(file) + "' 2>/dev/null | grep -iE 'crypt|aes|rsa|sha|md5|key|encrypt|decrypt|cipher|certificate|-----BEGIN' | head -50";
        auto r = run_root_cmd(full, a.value("timeout", 30), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- batch_decrypt_strings ---
    if (nm == "batch_decrypt_strings") {
        std::string file = a.value("file", "");
        if (file.empty()) return terr("file required");
        std::string enc = a.value("enc_type", "auto");
        std::string addr = a.value("addr", "");
        int size = a.value("size", 256);
        // Use Python for the decryption logic
        std::string py = "python3 -c \"\nimport base64,sys\nf='" + sq_esc(file) + "'\nenc='" + sq_esc(enc) + "'\n"
            "with open(f,'rb') as fp:\n"
            "  " + (addr.empty() ? "# Scan .rodata for obfuscated strings\n  fp.seek(0)\n  data=fp.read()" :
                     "fp.seek(" + addr + ")\n  data=fp.read(" + std::to_string(size) + ")") + "\n"
            "results=[]\n"
            "# XOR brute\n"
            "if enc in('auto','xor'):\n"
            "  for key in range(1,256):\n"
            "    dec=bytes(b^key for b in data[:64])\n"
            "    try:\n"
            "      s=dec.decode('utf-8',errors='strict')\n"
            "      if sum(32<=c<127 for c in dec)>len(dec)*0.7 and len(s.strip())>4:\n"
            "        results.append(f'XOR key=0x{key:02x}: {s.strip()[:80]}')\n"
            "    except: pass\n"
            "# Base64\n"
            "if enc in('auto','base64'):\n"
            "  import re\n"
            "  for m in re.finditer(rb'[A-Za-z0-9+/]{8,}={0,2}',data):\n"
            "    try:\n"
            "      d=base64.b64decode(m.group())\n"
            "      if all(32<=c<127 for c in d) and len(d)>3:\n"
            "        results.append(f'Base64 @0x{m.start():x}: {d.decode()[:80]}')\n"
            "    except: pass\n"
            "print(f'Found {len(results)} candidates:')\n"
            "for r in results[:100]: print(r)\n"
            "\"";
        auto r = run_root_cmd(py, a.value("timeout", 30), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- add_knowledge_note ---
    if (nm == "add_knowledge_note") {
        std::string action = a.value("action", "");
        if (action.empty()) return terr("action required (add/list/search/delete)");
        std::string notes_dir = g_self_dir + "/notes";
        std::string py = "python3 -c \"\nimport json,os,time,glob\nND='" + sq_esc(notes_dir) + "'\nos.makedirs(ND,exist_ok=True)\n"
            "action='" + sq_esc(action) + "'\n";
        if (action == "add") {
            std::string content = a.value("content", "");
            std::string tag = a.value("tag", "general");
            if (content.empty()) return terr("content required for add");
            py += "nid=str(int(time.time()*1000))\n"
                "note={'id':nid,'tag':'" + sq_esc(tag) + "','content':'" + sq_esc(content) + "','time':time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                "with open(os.path.join(ND,nid+'.json'),'w') as f: json.dump(note,f,ensure_ascii=False)\n"
                "print(f'Note saved: id={nid} tag={note[\"tag\"]}')\n";
        } else if (action == "list") {
            std::string tag = a.value("tag", "");
            py += "notes=[]\n"
                "for f in sorted(glob.glob(os.path.join(ND,'*.json'))):\n"
                "  with open(f) as fp: n=json.load(fp)\n"
                "  " + (tag.empty() ? "notes.append(n)" : "if n.get('tag')=='" + sq_esc(tag) + "': notes.append(n)") + "\n"
                "print(f'Total: {len(notes)} notes')\n"
                "for n in notes: print(n.get(\'id\',\'-\')+\'|\'+ n.get(\'tag\',\'-\')+\'|\'+ n.get(\'time\',\'-\')+\'|\'+ str(n.get(\'content\',\'\'))[:100])\n";
        } else if (action == "search") {
            std::string query = a.value("query", "");
            py += "q='" + sq_esc(query) + "'.lower()\nmatches=[]\n"
                "for f in glob.glob(os.path.join(ND,'*.json')):\n"
                "  with open(f) as fp: n=json.load(fp)\n"
                "  if q in n.get('content','').lower() or q in n.get('tag','').lower(): matches.append(n)\n"
                "print(f'Found: {len(matches)} matches')\n"
                "for n in matches: print(n.get(\'id\',\'-\')+\'|\'+ n.get(\'tag\',\'-\')+\'|\'+ n.get(\'time\',\'-\')+\'|\'+ str(n.get(\'content\',\'\'))[:100])\n";
        } else if (action == "delete") {
            std::string nid = a.value("id", "");
            py += "fp=os.path.join(ND,'" + sq_esc(nid) + ".json')\n"
                "if os.path.exists(fp): os.remove(fp); print('Deleted: " + sq_esc(nid) + "')\n"
                "else: print('Not found: " + sq_esc(nid) + "')\n";
        }
        py += "\"";
        auto r = run_root_cmd(py, 10, cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- simulate_execution ---
    if (nm == "simulate_execution") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        int steps = std::min(a.value("steps", 32), 500);
        bool regs = a.value("show_regs", true);
        std::string analyze = a.value("analyze", "basic");
        std::string cmd = "s " + addr + "; aei; aeim; aer PC=" + addr + ";";
        cmd += " " + std::to_string(steps) + " aes;";
        if (regs) cmd += " aer;";
        cmd += " pd 5 @ PC";
        return run_r2(file, cmd, analyze, a.value("timeout", 30));
    }

    // --- rename_function ---
    if (nm == "rename_function") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        std::string name = a.value("new_name", "");
        if (file.empty() || addr.empty() || name.empty()) return terr("file, addr, new_name required");
        std::string analyze = a.value("analyze", "basic");
        std::string cmd = "afn " + name + " @ " + addr + "; pdf @ " + addr;
        return run_r2(file, cmd, analyze, a.value("timeout", 30));
    }

    // --- symbolic_deobfuscate ---
    if (nm == "symbolic_deobfuscate") {
        std::string file = a.value("file", "");
        std::string addr = a.value("addr", "");
        if (file.empty() || addr.empty()) return terr("file and addr required");
        int depth = std::min(a.value("depth", 50), 500);
        std::string analyze = a.value("analyze", "full");
        // Use r2 ESIL + graph analysis to deobfuscate
        std::string cmd =
            "s " + addr + "; af; "
            "echo === Function graph ===; agf; "
            "echo === Basic blocks ===; afb; "
            "echo === ESIL trace (" + std::to_string(depth) + " steps) ===; "
            "aei; aeim; aer PC=" + addr + "; " + std::to_string(depth) + " aes; aer PC; "
            "echo === Conditional branches ===; pdf~je,jne,jb,ja,jg,jl,cbz,cbnz,tbz,tbnz,b.eq,b.ne,b.gt,b.lt,b.ge,b.le";
        return run_r2(file, cmd, analyze, a.value("timeout", 120));
    }

    /* ═══════════════════════════════════════════
     *  Android System / Utility Tools
     * ═══════════════════════════════════════════ */

    // --- read_logcat ---
    if (nm == "read_logcat") {
        int lines = a.value("lines", 50);
        std::string tag = a.value("tag", "");
        std::string pri = a.value("priority", "D");
        std::string pkg = a.value("pkg", "");
        std::string grep = a.value("grep", "");
        std::string cmd = "logcat -d -t " + std::to_string(lines);
        if (!tag.empty()) cmd += " -s '" + sq_esc(tag) + ":" + pri + "'";
        else cmd += " '*:" + pri + "'";
        if (!pkg.empty()) {
            // Get PID of package first
            cmd = "PID=$(pidof '" + sq_esc(pkg) + "' 2>/dev/null | awk '{print $1}'); "
                "if [ -n \"$PID\" ]; then logcat -d -t " + std::to_string(lines) + " --pid=$PID '*:" + pri + "'; "
                "else echo 'Package not running: " + sq_esc(pkg) + "'; fi";
        }
        if (!grep.empty()) cmd += " | grep -iE '" + sq_esc(grep) + "'";
        auto r = run_root_cmd(cmd, a.value("timeout", 10), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- sqlite_query ---
    if (nm == "sqlite_query") {
        std::string db = a.value("db", "");
        std::string sql = a.value("sql", "");
        if (db.empty() || sql.empty()) return terr("db and sql required");
        int limit = a.value("limit", 100);
        // Use Python's sqlite3 module
        std::string py;
        if (sql == ".tables") {
            py = "python3 -c \"\nimport sqlite3\nconn=sqlite3.connect('" + sq_esc(db) + "')\nc=conn.cursor()\nc.execute(\"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name\")\nfor r in c.fetchall(): print(r[0])\nconn.close()\n\"";
        } else if (sql.substr(0,7) == ".schema") {
            std::string tbl = sql.size() > 8 ? sql.substr(8) : "%";
            py = "python3 -c \"\nimport sqlite3\nconn=sqlite3.connect('" + sq_esc(db) + "')\nc=conn.cursor()\nc.execute(\"SELECT sql FROM sqlite_master WHERE name LIKE '" + sq_esc(tbl) + "'\")\nfor r in c.fetchall():\n  if r[0]: print(r[0]+';')\nconn.close()\n\"";
        } else {
            py = "python3 -c \"\nimport sqlite3,json\nconn=sqlite3.connect('" + sq_esc(db) + "')\nconn.row_factory=sqlite3.Row\nc=conn.cursor()\nc.execute('" + sq_esc(sql) + "')\n"
                "rows=c.fetchmany(" + std::to_string(limit) + ")\n"
                "if c.description:\n  cols=[d[0] for d in c.description]\n  print('|'.join(cols))\n  print('-'*60)\n  for r in rows: print('|'.join(str(r[c]) for c in cols))\n"
                "  print(f'\\n({len(rows)} rows)')\n"
                "else:\n  print(f'OK, {c.rowcount} rows affected')\n"
                "conn.close()\n\"";
        }
        auto r = run_root_cmd(py, a.value("timeout", 15), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- termux_save_script ---
    if (nm == "termux_save_script") {
        std::string path = a.value("path", "");
        std::string content = a.value("content", "");
        if (path.empty() || content.empty()) return terr("path and content required");
        bool exec = a.value("executable", false);
        // Write via Python to handle escaping properly
        std::string py = "python3 -c \"\nwith open('" + sq_esc(path) + "','w') as f: f.write( + content + )\nprint('Written: " + sq_esc(path) + "')\n\"";
        auto r = run_root_cmd(py, a.value("timeout", 10), cfg.max_out);
        if (exec) {
            run_root_cmd("chmod 755 '" + sq_esc(path) + "'", 5, 256);
        }
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- termux_command ---
    if (nm == "termux_command") {
        std::string command = a.value("command", "");
        if (command.empty()) return terr("command required");
        int timeout = std::min(a.value("timeout", 30), 300);
        // Run as Termux user
        std::string uid = "10520";  // Termux UID
        std::string full = "su " + uid + " -c 'export HOME=/data/data/com.termux/files/home "
            "PREFIX=/data/data/com.termux/files/usr "
            "PATH=/data/data/com.termux/files/usr/bin:$PATH "
            "LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib "
            "TMPDIR=/data/data/com.termux/files/home/.tmp; "
            "mkdir -p $TMPDIR; " + sq_esc(command) + "' 2>&1";
        auto r = run_root_cmd(full, timeout, cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out + r.err}, {"timed_out", r.timed_out}});
    }

    // --- os_list_dir ---
    if (nm == "os_list_dir") {
        std::string path = a.value("path", "");
        if (path.empty()) return terr("path required");
        bool hidden = a.value("show_hidden", false);
        bool recursive = a.value("recursive", false);
        std::string flags = "-l";
        if (hidden) flags += "a";
        if (recursive) flags += "R";
        std::string cmd = "ls " + flags + " '" + sq_esc(path) + "' 2>&1";
        auto r = run_root_cmd(cmd, a.value("timeout", 10), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }

    // --- os_read_file ---
    if (nm == "os_read_file") {
        std::string path = a.value("path", "");
        if (path.empty()) return terr("path required");
        std::string mode = a.value("mode", "text");
        std::string cmd;
        if (mode == "hex") cmd = "xxd '" + sq_esc(path) + "' 2>&1";
        else if (mode == "base64") cmd = "base64 '" + sq_esc(path) + "' 2>&1";
        else cmd = "cat '" + sq_esc(path) + "' 2>&1";
        if (a.contains("lines") && a["lines"].is_number())
            cmd += " | head -" + std::to_string(a["lines"].get<int>());
        auto r = run_root_cmd(cmd, a.value("timeout", 10), cfg.max_out);
        return tjson({{"exit_code", r.exit_code}, {"output", r.out}, {"timed_out", r.timed_out}});
    }


    return terr("Unknown tool: " + nm);
}

/* ══════════ MCP JSON-RPC ROUTER ══════════ */
static json handle_rpc(const json& req, const Config& cfg, const std::string& sid) {
    if (!req.is_object())
        return mkerr(-32600, "Invalid Request");
    if (!req.contains("method") || !req["method"].is_string())
        return mkerr(-32600, "Invalid Request", req.value("id", json(nullptr)));

    auto id = req.value("id", json(nullptr));
    auto method = req["method"].get<std::string>();
    auto params = req.contains("params") ? req["params"] : json::object();
    LOGI("RPC", method);

    if (method == "ping")
        return mkres(id, json::object());

    if (method == "initialize")
        return mkres(id, {
            {"protocolVersion", PROTO_VER},
            {"serverInfo", {{"name", "MCP Termux Server v5.1 (RE Edition)"}, {"version", VERSION}}},
            {"capabilities", {
                {"tools", {{"listChanged", false}}},
                {"resources", json::object()},
                {"prompts", json::object()}
            }}
        });

    if (method == "notifications/initialized")
        return json(nullptr);

    if (method == "tools/list")
        return mkres(id, {{"tools", get_tools()}});

    if (method == "tools/call") {
        std::string nm;
        json args = json::object();
        if (params.contains("name") && params["name"].is_string())
            nm = params["name"];
        if (params.contains("arguments") && params["arguments"].is_object())
            args = params["arguments"];
        if (nm.empty())
            return mkerr(-32602, "tools/call: missing name", id);
        try {
            return mkres(id, run_tool(nm, args, cfg, sid));
        } catch (const std::exception& e) {
            return mkres(id, terr(std::string("Exception: ") + e.what()));
        }
    }

    if (method == "resources/list")
        return mkres(id, {{"resources", json::array()}});
    if (method == "prompts/list")
        return mkres(id, {{"prompts", json::array()}});
    if (method == "completion/complete")
        return mkres(id, {{"completion", {{"values", json::array()},
                          {"total", 0}, {"hasMore", false}}}});

    return mkerr(-32601, "Method not found: " + method, id);
}

/* ══════════ MAIN ══════════ */
static httplib::Server* g_svr_ptr = nullptr;

int main(int argc, char* argv[]) {
    // ── Init self directory (for relative paths) ──
    g_self_dir = get_self_dir();
    LOGI("Main", "Base directory: " + g_self_dir);

    // ── Auto-create symlink for paradise compatibility ──
    // paradise hardcodes /data/adb/CD/stackplz/stackplz
    {
        struct stat _lst{};
        if (lstat("/data/adb/CD/stackplz/stackplz", &_lst) != 0) {
            std::string sh = "mkdir -p /data/adb/CD/stackplz/preload_libs /data/adb/CD/stackplz/user/config"
                " && ln -sf " + g_self_dir + "/stackplz /data/adb/CD/stackplz/stackplz"
                " && ln -sf " + g_self_dir + "/user/config/config_syscall_aarch64.json /data/adb/CD/stackplz/user/config/config_syscall_aarch64.json"
                " && for f in " + g_self_dir + "/preload_libs/*.so; do ln -sf $f /data/adb/CD/stackplz/preload_libs/$(basename $f); done";
            system(sh.c_str());
            LOGI("Main", "Created paradise compatibility symlinks -> " + g_self_dir);
        }
    }

    // ── Auto-load Paradise kernel module if not loaded ──
    {
        FILE* fp = fopen("/proc/modules", "r");
        bool loaded = false;
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp))
                if (strstr(line, "paradise")) { loaded = true; break; }
            fclose(fp);
        }
        if (!loaded) {
            // Detect kernel version
            struct utsname uts{};
            uname(&uts);
            std::string kver(uts.release);  // e.g. "5.10.210-android12-..."
            std::string major_minor;
            // Extract major.minor (e.g. "5.10", "6.1", "6.6")
            auto dot1 = kver.find('.');
            if (dot1 != std::string::npos) {
                auto dot2 = kver.find('.', dot1+1);
                auto dash = kver.find('-', dot1+1);
                auto end = std::min(dot2, dash);
                major_minor = kver.substr(0, end);
            }
            // Try to find matching .ko in kmodules/
            std::string ko_path = g_self_dir + "/kmodules/" + major_minor + ".ko";
            if (access(ko_path.c_str(), F_OK) == 0) {
                std::string cmd = "insmod '" + ko_path + "' 2>&1";
                FILE* p = popen(cmd.c_str(), "r");
                char buf[256] = {};
                if (p) { fgets(buf, sizeof(buf), p); pclose(p); }
                LOGI("Main", "Auto-insmod " + ko_path + " : " + std::string(buf));
            } else {
                LOGW("Main", "No matching kernel module for " + major_minor + " in kmodules/");
            }
        } else {
            LOGI("Main", "Paradise kernel module already loaded");
        }
    }

    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--host") { if (i+1<argc) cfg.host = argv[++i]; }
        else if (arg == "-p" || arg == "--port") { if (i+1<argc) cfg.port = std::stoi(argv[++i]); }
        else if (arg == "-t" || arg == "--timeout") { if (i+1<argc) cfg.timeout_sec = std::stoi(argv[++i]); }
        else if (arg == "-d" || arg == "--debug") { g_log_level = LOG_DEBUG; }
        else if (arg == "--help") {
            std::cout << "MCP Termux Server v" << VERSION << " - Integrated RE Edition\n"
                      << "Usage: " << argv[0] << " [options]\n"
                      << "  -h, --host HOST     Bind address (default: 0.0.0.0)\n"
                      << "  -p, --port PORT     Port (default: 65534)\n"
                      << "  -t, --timeout SEC   Default timeout (default: 120)\n"
                      << "  -d, --debug         Enable debug logging\n"
                      << "\nIntegrated tools:\n"
                      << "  stackplz (eBPF tracing):   " << stackplz_path() << "\n"
                      << "  paradise_tool (memory):    " << paradise_path() << "\n"
                      << "  radare2 (static analysis): " << r2_bin() << "\n";
            return 0;
        }
        else if (i == 1 && arg[0] != '-') cfg.host = arg;
        else if (i == 2 && arg[0] != '-') cfg.port = std::stoi(arg);
        else if (i == 3 && arg[0] != '-') cfg.timeout_sec = std::stoi(arg);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, [](int) { g_stop = true; if (g_svr_ptr) g_svr_ptr->stop(); });
    signal(SIGTERM, [](int) { g_stop = true; if (g_svr_ptr) g_svr_ptr->stop(); });

    LOGI("Main", "MCP Termux Server v" + std::string(VERSION) + " (RE Edition) starting...");
    LOGI("Main", "Termux prefix: " + std::string(TERMUX_PREFIX));
    LOGI("Main", "stackplz: " + std::string(access(stackplz_path().c_str(), F_OK)==0 ? "found" : "NOT found"));
    LOGI("Main", "paradise: " + std::string(access(paradise_path().c_str(), F_OK)==0 ? "found" : "NOT found"));
    LOGI("Main", "radare2: " + std::string(access(r2_bin().c_str(), F_OK)==0 ? "found" : "NOT found"));

    mkdir(TERMUX_TMP, 0755);
    check_root();

    std::thread([]() {
        while (!g_stop) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            cleanup_jobs();
            cleanup_sessions();
        }
    }).detach();

    httplib::Server svr;
    g_svr_ptr = &svr;

    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        res.set_header("Access-Control-Allow-Headers",
            "Content-Type,Authorization,Accept,Cache-Control,"
            "X-Requested-With,mcp-session-id,Last-Event-ID");
        res.set_header("Access-Control-Expose-Headers", "mcp-session-id,Content-Type");
        res.set_header("Access-Control-Max-Age", "86400");
        if (req.method == "OPTIONS") { res.status = 204; return httplib::Server::HandlerResponse::Handled; }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.set_read_timeout(300, 0);
    svr.set_write_timeout(300, 0);

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json j = {{"status", "ok"}, {"version", VERSION}, {"protocol", PROTO_VER},
                  {"tools", (int)get_tools().size()}, {"root_available", check_root()},
                  {"stackplz", access(stackplz_path().c_str(), X_OK) == 0},
                  {"paradise", access(paradise_path().c_str(), X_OK) == 0},
                  {"radare2", access(r2_bin().c_str(), X_OK) == 0},
                  {"rabin2", access(rabin2_bin().c_str(), X_OK) == 0},
                  {"rasm2", access(rasm2_bin().c_str(), X_OK) == 0}};
        res.set_content(j.dump(), "application/json");
    });

    svr.Get("/mcp", [&cfg](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.has_header("mcp-session-id") ?
            req.get_header_value("mcp-session-id") : gen_id();
        res.set_header("mcp-session-id", sid);
        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");
        json ep = {{"type", "endpoint"},
                   {"uri", "http://127.0.0.1:" + std::to_string(cfg.port) + "/mcp"}};
        LOGI("SSE", "Client session=" + sid.substr(0,8));
        res.set_content("event: endpoint\ndata: " + ep.dump() + "\n\n",
                       "text/event-stream");
    });

    svr.Post("/mcp", [&cfg](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.has_header("mcp-session-id") ?
            req.get_header_value("mcp-session-id") : gen_id();
        res.set_header("mcp-session-id", sid);

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            res.set_content(mkerr(-32700, "Parse error").dump(), "application/json");
            return;
        }

        auto one = [&](const json& r) -> json {
            if (!r.is_object()) return mkerr(-32600, "Invalid Request");
            return handle_rpc(r, cfg, sid);
        };

        if (body.is_array()) {
            json out = json::array();
            for (auto& r : body) {
                auto resp = one(r);
                if (!resp.is_null()) out.push_back(resp);
            }
            if (out.empty()) { res.status = 204; return; }
            res.set_content(out.dump(), "application/json");
        } else {
            auto resp = one(body);
            if (resp.is_null()) { res.status = 204; return; }
            res.set_content(resp.dump(), "application/json");
        }
    });

    svr.Get("/mcp/v1/job", [](const httplib::Request& req, httplib::Response& res) {
        std::string jid = req.get_param_value("job_id");
        if (jid.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"Missing job_id\"}", "application/json");
            return;
        }
        auto j = get_job(jid);
        if (!j) {
            res.status = 404;
            res.set_content("{\"error\":\"Not found\"}", "application/json");
            return;
        }
        std::lock_guard<std::mutex> lk(j->mtx);
        json r = {{"job_id", jid}, {"done", j->done},
                  {"exit_code", j->result.exit_code},
                  {"stdout", j->result.out}, {"stderr", j->result.err},
                  {"error", j->result.errmsg}};
        res.set_content(r.dump(), "application/json");
    });

    LOGI("Main", "Listening on " + cfg.host + ":" + std::to_string(cfg.port));
    LOGI("Main", "Endpoints: POST/GET /mcp, GET /health, GET /mcp/v1/job");
    LOGI("Main", "Total tools: " + std::to_string(get_tools().size()));

    if (!svr.listen(cfg.host.c_str(), cfg.port)) {
        LOGE("Main", "Failed to bind " + cfg.host + ":" + std::to_string(cfg.port));
        return 1;
    }

    LOGI("Main", "Server stopped.");
    return 0;
}
