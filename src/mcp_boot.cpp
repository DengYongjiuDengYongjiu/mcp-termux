/*
 * MCP Bootstrap Server v1.0 — Lightweight management MCP
 * Port: 65533 | No auth (localhost only)
 * Run: MT Manager root exec -> press 1 -> foreground
 * Compile: g++ -std=c++17 -O2 -pthread -o mcp_boot mcp_boot.cpp
 */
#include "httplib.h"
#include "json.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

using json = nlohmann::json;
static const int PORT = 65533;
static const char* VERSION = "1.0.0";
static const char* PROTO_VER = "2024-11-05";

/* ── Helpers ── */
static std::string gen_id() {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> d;
    char buf[32]; snprintf(buf, sizeof(buf), "%016lx", (unsigned long)d(rng));
    return buf;
}

static std::string b64enc(const std::string& in) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; const unsigned char* d = (const unsigned char*)in.c_str(); size_t len = in.size();
    for (size_t i=0; i<len; i+=3) {
        unsigned int n = d[i]<<16; if(i+1<len) n|=d[i+1]<<8; if(i+2<len) n|=d[i+2];
        out+=T[(n>>18)&63]; out+=T[(n>>12)&63];
        out+=(i+1<len)?T[(n>>6)&63]:'='; out+=(i+2<len)?T[n&63]:'=';
    }
    return out;
}

static std::string sq_esc(const std::string& s) {
    std::string r; for (char c : s) { if (c=='\'') r+="'\\''"; else r+=c; } return r;
}

static json mkerr(int code, const std::string& msg, json id = nullptr) {
    return {{"jsonrpc","2.0"},{"id",id},{"error",{{"code",code},{"message",msg}}}};
}
static json mkres(const json& id, const json& result) {
    return {{"jsonrpc","2.0"},{"id",id},{"result",result}};
}

struct ExecResult { std::string out; int exit_code; bool timed_out; };

static ExecResult run_cmd(const std::string& cmd, int timeout) {
    std::string b64 = b64enc(cmd);
    std::string wrapped = "timeout " + std::to_string(timeout) +
        " su -c \"$(echo '" + b64 + "' | base64 -d)\" 2>&1";
    FILE* fp = popen(wrapped.c_str(), "r");
    if (!fp) return {"popen failed", -1, false};
    std::string out; char buf[4096]; size_t maxout = 1024*1024;
    while (fgets(buf, sizeof(buf), fp)) { out += buf; if (out.size() > maxout) break; }
    int rc = pclose(fp);
    return {out, WEXITSTATUS(rc), WEXITSTATUS(rc)==124};
}

/* ── Tool defs ── */
static json get_tools() {
    return json::array({
        {{"name","boot_shell"},
         {"description","Execute shell command with root. For managing main MCP.\nExample: {command:\"pidof mcp\"}"},
         {"inputSchema",{{"type","object"},{"required",{"command"}},{"properties",{
            {"command",{{"type","string"},{"description","Shell command"}}},
            {"timeout",{{"type","integer"},{"default",120},{"description","Timeout seconds"}}}
         }}}}},
        {{"name","boot_read"},
         {"description","Read file with root.\nExample: {path:\"/data/adb/mcp_re_v6/mcp.log\"}"},
         {"inputSchema",{{"type","object"},{"required",{"path"}},{"properties",{
            {"path",{{"type","string"},{"description","File path"}}},
            {"lines",{{"type","integer"},{"description","Last N lines"}}}
         }}}}},
        {{"name","boot_write"},
         {"description","Write file with root.\nExample: {path:\"/tmp/t.txt\", content:\"hello\"}"},
         {"inputSchema",{{"type","object"},{"required",{"path","content"}},{"properties",{
            {"path",{{"type","string"},{"description","File path"}}},
            {"content",{{"type","string"},{"description","Content"}}},
            {"append",{{"type","boolean"},{"default",false}}}
         }}}}},
        {{"name","boot_deploy"},
         {"description","Deploy new MCP binary and restart on port 65534.\nsource: new binary path\ntarget_dir: install dir (default /data/adb/mcp_re_v6)"},
         {"inputSchema",{{"type","object"},{"required",{"source"}},{"properties",{
            {"source",{{"type","string"},{"description","New binary path"}}},
            {"target_dir",{{"type","string"},{"default","/data/adb/mcp_re_v6"},{"description","Install dir"}}}
         }}}}}
    });
}

/* ── Tool handler ── */
static json run_tool(const std::string& nm, const json& a) {
    // Return format: {"content":[{"type":"text","text":"..."}], "isError":false}
    auto terr = [](const std::string& m) -> json {
        return {{"content", json::array({{{"type","text"},{"text",m}}})}, {"isError", true}};
    };
    auto tok = [](const json& j) -> json {
        return {{"content", json::array({{{"type","text"},{"text",j.dump(2)}}})}, {"isError", false}};
    };

    if (nm == "boot_shell") {
        std::string cmd = a.value("command", "");
        if (cmd.empty()) return terr("command required");
        auto r = run_cmd(cmd, std::min(a.value("timeout", 120), 600));
        return tok({{"exit_code", r.exit_code}, {"stdout", r.out}, {"timed_out", r.timed_out}});
    }
    if (nm == "boot_read") {
        std::string path = a.value("path", "");
        if (path.empty()) return terr("path required");
        std::string cmd = "cat '" + sq_esc(path) + "'";
        if (a.contains("lines") && a["lines"].is_number())
            cmd = "tail -" + std::to_string(a["lines"].get<int>()) + " '" + sq_esc(path) + "'";
        auto r = run_cmd(cmd, 10);
        return tok({{"exit_code", r.exit_code}, {"content", r.out}});
    }
    if (nm == "boot_write") {
        std::string path = a.value("path", ""), content = a.value("content", "");
        if (path.empty()) return terr("path required");
        std::string b64 = b64enc(content);
        std::string op = a.value("append", false) ? ">>" : ">";
        auto r = run_cmd("echo '" + b64 + "' | base64 -d " + op + " '" + sq_esc(path) + "' && echo OK", 10);
        return tok({{"exit_code", r.exit_code}, {"output", r.out}, {"bytes", (int)content.size()}});
    }
    if (nm == "boot_deploy") {
        std::string src = a.value("source", ""), dir = a.value("target_dir", "/data/adb/mcp_re_v6");
        if (src.empty()) return terr("source required");
        std::string script =
            "set -e\necho '[1/5] Kill old...'\npkill -9 -f '" + sq_esc(dir) + "/mcp' 2>/dev/null||true\nsleep 1\n"
            "echo '[2/5] Backup...'\n[ -f '" + sq_esc(dir) + "/mcp' ]&&cp '" + sq_esc(dir) + "/mcp' '" + sq_esc(dir) + "/mcp.bak'||true\n"
            "echo '[3/5] Deploy...'\ncp '" + sq_esc(src) + "' '" + sq_esc(dir) + "/mcp'\nchmod 755 '" + sq_esc(dir) + "/mcp'\n"
            "echo '[4/5] Start...'\ncd '" + sq_esc(dir) + "'&&nohup ./mcp -p 65534 </dev/null>./mcp.log 2>&1 &\nsleep 3\n"
            "echo '[5/5] Verify...'\nif pidof mcp>/dev/null 2>&1;then echo \"OK PID=$(pidof mcp)\";head -8 '" + sq_esc(dir) + "/mcp.log';else echo FAIL;tail -10 '" + sq_esc(dir) + "/mcp.log';fi\n";
        auto r = run_cmd(script, 30);
        return tok({{"exit_code", r.exit_code}, {"output", r.out}});
    }
    return terr("Unknown tool: " + nm);
}

/* ── JSON-RPC router (same as v7 main MCP) ── */
static json handle_rpc(const json& req) {
    if (!req.is_object() || !req.contains("method") || !req["method"].is_string())
        return mkerr(-32600, "Invalid Request", req.value("id", json(nullptr)));

    auto id = req.value("id", json(nullptr));
    auto method = req["method"].get<std::string>();
    auto params = req.contains("params") ? req["params"] : json::object();

    if (method == "ping")
        return mkres(id, json::object());
    if (method == "initialize")
        return mkres(id, {
            {"protocolVersion", PROTO_VER},
            {"serverInfo", {{"name","MCP Bootstrap"},{"version",VERSION}}},
            {"capabilities", {{"tools",{{"listChanged",false}}},{"resources",json::object()},{"prompts",json::object()}}}
        });
    if (method == "notifications/initialized")
        return json(nullptr);  // -> 204
    if (method == "tools/list")
        return mkres(id, {{"tools", get_tools()}});
    if (method == "tools/call") {
        std::string nm = params.value("name", "");
        json args = params.contains("arguments") ? params["arguments"] : json::object();
        if (nm.empty()) return mkerr(-32602, "missing tool name", id);
        try { return mkres(id, run_tool(nm, args)); }
        catch (const std::exception& e) { return mkres(id, run_tool("__err", json())); }
    }
    if (method == "resources/list") return mkres(id, {{"resources", json::array()}});
    if (method == "prompts/list") return mkres(id, {{"prompts", json::array()}});
    if (method == "completion/complete")
        return mkres(id, {{"completion",{{"values",json::array()},{"total",0},{"hasMore",false}}}});
    return mkerr(-32601, "Method not found: " + method, id);
}

/* ── HTTP Server ── */
static httplib::Server* g_svr = nullptr;

int main() {
    printf("\n========================================\n");
    printf("  MCP Bootstrap Server v%s\n", VERSION);
    printf("  Port: %d\n", PORT);
    printf("========================================\n");
    printf("  1. Start foreground (default)\n");
    printf("  2. Exit\n");
    printf("========================================\n");
    printf("Choose [1]: ");
    fflush(stdout);

    char ch[16] = "1";
    if (isatty(STDIN_FILENO)) { if (!fgets(ch, sizeof(ch), stdin)) ch[0]='1'; }
    if (atoi(ch) == 2) { printf("Bye.\n"); return 0; }

    signal(SIGINT, [](int) { printf("\n[Boot] Stopping...\n"); if(g_svr) g_svr->stop(); });
    signal(SIGTERM, [](int) { if(g_svr) g_svr->stop(); });
    signal(SIGPIPE, SIG_IGN);

    httplib::Server svr;
    g_svr = &svr;

    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"ok\"}", "application/json");
    });

    // SSE endpoint — identical format to v7
    svr.Get("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.has_header("mcp-session-id") ?
            req.get_header_value("mcp-session-id") : gen_id();
        res.set_header("mcp-session-id", sid);
        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        res.set_header("X-Accel-Buffering", "no");
        json ep = {{"type","endpoint"},{"uri","http://127.0.0.1:65533/mcp"}};
        res.set_content("event: endpoint\ndata: " + ep.dump() + "\n\n", "text/event-stream");
    });

    // POST handler — identical protocol to v7
    svr.Post("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        std::string sid = req.has_header("mcp-session-id") ?
            req.get_header_value("mcp-session-id") : gen_id();
        res.set_header("mcp-session-id", sid);

        json body;
        try { body = json::parse(req.body); } catch (...) {
            res.status = 400;
            res.set_content(mkerr(-32700, "Parse error").dump(), "application/json");
            return;
        }

        auto one = [](const json& r) -> json {
            if (!r.is_object()) return mkerr(-32600, "Invalid Request");
            return handle_rpc(r);
        };

        if (body.is_array()) {
            json out = json::array();
            for (auto& r : body) { auto resp = one(r); if (!resp.is_null()) out.push_back(resp); }
            if (out.empty()) { res.status = 204; return; }
            res.set_content(out.dump(), "application/json");
        } else {
            auto resp = one(body);
            if (resp.is_null()) { res.status = 204; return; }
            res.set_content(resp.dump(), "application/json");
        }
    });

    // DELETE session
    svr.Delete("/mcp", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200; res.set_content("{}", "application/json");
    });

    printf("\n[Boot] Listening 0.0.0.0:%d | Tools: %d | Ctrl+C stop\n\n", PORT, (int)get_tools().size());
    fflush(stdout);

    if (!svr.listen("0.0.0.0", PORT)) {
        fprintf(stderr, "[Boot] FATAL: port %d in use\n", PORT);
        return 1;
    }
    return 0;
}
