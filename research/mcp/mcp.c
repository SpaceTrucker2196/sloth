#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sloth.h"   /* SLOTH_VERSION — serverInfo.version is sloth's own,
                      * not a second number to keep in step. */
#include "json.h"
#include "mcp.h"

#define TEXT_MAX 32768

/* A bounded appender that latches overflow instead of truncating. Every
 * caller checks `over` once at the end rather than at every append,
 * which is the only reason the response builders below read as
 * straight-line code. */
typedef struct { char *buf; size_t cap, len; int over; } sb_t;

static void sb_init(sb_t *s, char *buf, size_t cap) {
    s->buf = buf; s->cap = cap; s->len = 0; s->over = 0;
    if (cap) buf[0] = '\0';
}

static void sb_addf(sb_t *s, const char *fmt, ...) {
    if (s->over || s->len + 1 >= s->cap) { s->over = 1; return; }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->buf + s->len, s->cap - s->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= s->cap - s->len) { s->over = 1; return; }
    s->len += (size_t)n;
}

static void sb_json(sb_t *s, const char *str) {
    if (s->over) return;
    if (json_esc_append(s->buf, s->cap, str) != 0) { s->over = 1; return; }
    s->len = strlen(s->buf);
}

/* ── id echo ──────────────────────────────────────────────────────────
 *
 * JSON-RPC ids may be a string, a number, or null, and the response
 * must carry the request's id back unchanged. Rendering it once here
 * keeps the four response builders from each getting it subtly
 * different. */
static void sb_id(sb_t *s, const json_doc_t *d, int id) {
    if (id < 0 || d->nodes[id].type == JSON_NULL) { sb_addf(s, "null"); return; }
    if (d->nodes[id].type == JSON_STR) { sb_json(s, json_str(d, id)); return; }
    double v = d->nodes[id].num;
    /* Integral ids print as integers, not through %g. Both are valid
     * JSON and agree for small values, but %g switches to exponent form
     * around 1e16 — a client that sent 10000000000000000 and pairs
     * responses by string equality would not recognise "1e+16" as its
     * own id. */
    if (v == (double)(long long)v) sb_addf(s, "%lld", (long long)v);
    else                           sb_addf(s, "%.17g", v);
}

static mcp_result_t finish(sb_t *s) {
    return s->over ? MCP_OVERFLOW : MCP_OK;
}

static mcp_result_t err_resp(sb_t *s, const json_doc_t *d, int id,
                             int code, const char *msg) {
    sb_addf(s, "{\"jsonrpc\":\"2.0\",\"id\":");
    if (d) sb_id(s, d, id); else sb_addf(s, "null");
    sb_addf(s, ",\"error\":{\"code\":%d,\"message\":", code);
    sb_json(s, msg);
    sb_addf(s, "}}");
    return finish(s);
}

/* ── tool result text ─────────────────────────────────────────────── */

static void hits_text(sb_t *t, const rq_hit_t *hits, int n,
                      const char *what) {
    if (n == 0) {
        /* Not an error. An empty corpus and a question with no answer
         * in it are both ordinary states, and reporting them as tool
         * failures would train a client to retry something that will
         * never succeed. */
        sb_addf(t, "No documents in the research corpus match %s.\n", what);
        return;
    }
    sb_addf(t, "%d document%s matching %s.\n", n, n == 1 ? "" : "s", what);
    for (int i = 0; i < n; i++) {
        const rq_hit_t *h = &hits[i];
        sb_addf(t, "\n## %s\n", h->title);
        sb_addf(t, "source: %s\n", h->source_url);
        sb_addf(t, "retrieved: %s\n", h->retrieved);
        if (h->topics[0]) sb_addf(t, "topics: %s\n", h->topics);
        sb_addf(t, "path: %s\n", h->path);
        if (h->snippet[0]) sb_addf(t, "\n%s\n", h->snippet);
    }
}

/* Writes the tool's text into `t`. Returns 1 if the call is an error
 * from the *tool's* point of view — a missing argument — which MCP
 * reports inside a successful result with isError, so the model sees it
 * and can correct itself rather than the transport failing. */
static int run_tool(rq_handle_t *rq, const json_doc_t *d, int args,
                    const char *tool, time_t now, sb_t *t) {
    rq_hit_t hits[RQ_MAX_HITS];
    char     what[RQ_STR * 2];

    if (!rq) {
        sb_addf(t, "The research corpus is unavailable: %s. "
                   "Build it with `make research-index`.\n", rq_open_error());
        return 1;
    }

    if (strcmp(tool, "research_search") == 0) {
        const char *q      = json_str(d, json_obj_get(d, args, "query"));
        const char *filter = json_str(d, json_obj_get(d, args, "filter"));
        int max = (int)json_num(d, json_obj_get(d, args, "max"), RQ_MAX_HITS);
        if (!q || !q[0]) {
            sb_addf(t, "research_search requires a non-empty `query`.\n");
            return 1;
        }
        if (max < 1) max = 1;
        int n = rq_search(rq, q, filter, hits, max);
        if (filter && filter[0])
            snprintf(what, sizeof(what), "\"%.100s\" (filtered to %.100s)",
                     q, filter);
        else
            snprintf(what, sizeof(what), "\"%.100s\"", q);
        hits_text(t, hits, n, what);
        return 0;
    }

    if (strcmp(tool, "research_for_alert") == 0) {
        const char *kind = json_str(d, json_obj_get(d, args, "alert_kind"));
        if (!kind || !kind[0]) {
            sb_addf(t, "research_for_alert requires an `alert_kind`, "
                       "e.g. ALERT_TYPE_EVIL_TWIN.\n");
            return 1;
        }
        int n = rq_for_alert(rq, kind, hits, RQ_MAX_HITS);
        snprintf(what, sizeof(what), "alert kind %.100s", kind);
        hits_text(t, hits, n, what);
        return 0;
    }

    if (strcmp(tool, "research_cite") == 0) {
        const char *topic = json_str(d, json_obj_get(d, args, "topic"));
        if (!topic || !topic[0]) {
            sb_addf(t, "research_cite requires a `topic`.\n");
            return 1;
        }
        char cites[RQ_MAX_HITS][RQ_STR];
        int n = rq_cite(rq, topic, cites, RQ_MAX_HITS);
        if (n == 0) {
            sb_addf(t, "No sources in the research corpus cover topic "
                       "\"%s\".\n", topic);
            return 0;
        }
        sb_addf(t, "%d source%s for topic \"%s\".\n",
                n, n == 1 ? "" : "s", topic);
        for (int i = 0; i < n; i++) sb_addf(t, "- %s\n", cites[i]);
        return 0;
    }

    if (strcmp(tool, "research_recent") == 0) {
        int days = (int)json_num(d, json_obj_get(d, args, "days"), 7);
        if (days < 1) days = 1;
        int n = rq_recent(rq, days, now, hits, RQ_MAX_HITS);
        snprintf(what, sizeof(what), "retrieval within the last %d day%s",
                 days, days == 1 ? "" : "s");
        hits_text(t, hits, n, what);
        return 0;
    }

    /* Unreachable: the caller validates the tool name first, so that an
     * unknown name is a protocol error rather than a tool result. */
    sb_addf(t, "unknown tool\n");
    return 1;
}

static int known_tool(const char *name) {
    return name && (strcmp(name, "research_search")    == 0 ||
                    strcmp(name, "research_for_alert") == 0 ||
                    strcmp(name, "research_cite")      == 0 ||
                    strcmp(name, "research_recent")    == 0);
}

/* The tools/list payload. Written out rather than generated from a
 * table because it is read by a model, and the descriptions are the
 * only thing telling it that for_alert wants an enum name and not a
 * display title — the distinction that cost three bugs on the sloth
 * side of this same query layer. */
static const char *TOOLS_JSON =
"[{\"name\":\"research_search\",\"description\":"
"\"Full-text search over sloth's research corpus (IEEE clauses, CVEs, CERT "
"advisories, MITRE techniques, papers). BM25-ranked.\","
"\"inputSchema\":{\"type\":\"object\",\"properties\":{"
"\"query\":{\"type\":\"string\",\"description\":\"FTS5 query text.\"},"
"\"filter\":{\"type\":\"string\",\"description\":\"Restrict to one topic or "
"alert kind.\"},"
"\"max\":{\"type\":\"integer\",\"description\":\"Maximum hits, default 16.\"}"
"},\"required\":[\"query\"]}},"

"{\"name\":\"research_for_alert\",\"description\":"
"\"Documents backing one sloth alert. Takes the enum name "
"(ALERT_TYPE_BLOCKACK_ATTACK), not the display title shown in the TUI "
"(BLOCKACK_ATK), which is abbreviated to fit the column.\","
"\"inputSchema\":{\"type\":\"object\",\"properties\":{"
"\"alert_kind\":{\"type\":\"string\",\"description\":"
"\"An ALERT_TYPE_* enum name.\"}},\"required\":[\"alert_kind\"]}},"

"{\"name\":\"research_cite\",\"description\":"
"\"Canonical source URLs for a topic, deduplicated. Use when writing a "
"citation rather than reading the material.\","
"\"inputSchema\":{\"type\":\"object\",\"properties\":{"
"\"topic\":{\"type\":\"string\"}},\"required\":[\"topic\"]}},"

"{\"name\":\"research_recent\",\"description\":"
"\"Documents added to the corpus within the last N days. Feeds the weekly "
"brief.\","
"\"inputSchema\":{\"type\":\"object\",\"properties\":{"
"\"days\":{\"type\":\"integer\",\"description\":\"Window in days, default 7.\""
"}},\"required\":[]}}]";

mcp_result_t mcp_handle(rq_handle_t *rq, const char *req, time_t now,
                        char *out, size_t cap) {
    sb_t s;
    sb_init(&s, out, cap);

    json_doc_t d;
    if (!req || json_parse(&d, req) != 0)
        return err_resp(&s, NULL, -1, -32700, "parse error");

    int id      = json_obj_get(&d, 0, "id");
    int mnode   = json_obj_get(&d, 0, "method");
    const char *method = json_str(&d, mnode);

    if (!method)
        return err_resp(&s, &d, id, -32600, "invalid request: no method");

    /* A JSON-RPC notification is a request with no id, and answering
     * one is a protocol violation — the client is not reading. This is
     * how notifications/initialized is handled, and it must stay a
     * blanket rule: a client may send any notification at any time. */
    if (id < 0) return MCP_NO_RESPONSE;

    if (strcmp(method, "initialize") == 0) {
        sb_addf(&s, "{\"jsonrpc\":\"2.0\",\"id\":");
        sb_id(&s, &d, id);
        sb_addf(&s, ",\"result\":{\"protocolVersion\":\"%s\","
                    "\"capabilities\":{\"tools\":{}},"
                    "\"serverInfo\":{\"name\":\"sloth-research\","
                    "\"version\":\"%s\"}}}",
                MCP_PROTOCOL_VERSION, SLOTH_VERSION);
        return finish(&s);
    }

    if (strcmp(method, "tools/list") == 0) {
        sb_addf(&s, "{\"jsonrpc\":\"2.0\",\"id\":");
        sb_id(&s, &d, id);
        sb_addf(&s, ",\"result\":{\"tools\":%s}}", TOOLS_JSON);
        return finish(&s);
    }

    if (strcmp(method, "tools/call") == 0) {
        int params = json_obj_get(&d, 0, "params");
        const char *tool = json_str(&d, json_obj_get(&d, params, "name"));
        if (!known_tool(tool))
            return err_resp(&s, &d, id, -32602,
                            tool ? "unknown tool" : "missing tool name");

        int args = json_obj_get(&d, params, "arguments");
        char text[TEXT_MAX];
        sb_t t;
        sb_init(&t, text, sizeof(text));
        int is_err = run_tool(rq, &d, args, tool, now, &t);
        if (t.over) return err_resp(&s, &d, id, -32603,
                                    "result too large to encode");

        sb_addf(&s, "{\"jsonrpc\":\"2.0\",\"id\":");
        sb_id(&s, &d, id);
        sb_addf(&s, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
        sb_json(&s, text);
        sb_addf(&s, "}],\"isError\":%s}}", is_err ? "true" : "false");
        return finish(&s);
    }

    return err_resp(&s, &d, id, -32601, "method not found");
}
