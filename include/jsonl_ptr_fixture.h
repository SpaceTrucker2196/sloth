#ifndef JSONL_PTR_FIXTURE_H
#define JSONL_PTR_FIXTURE_H

/* #165: the one dns record that links sloth's writer to slothweb's
 * passive_ptr reader. tests/test_jsonl.c :: test_emit_dns_ptr_answer
 * asserts sloth emits exactly this line; web/tests/test_ptr.c feeds the
 * same line to slothweb. One copy, so a change to either side's shape
 * fails a test instead of leaving two literals that agree only by
 * hand. Test-only; here because include/ is the one directory on both
 * suites' include path. The target is 48 bytes, past the 45 sloth's
 * answer held before #165. */
#define SLOTH_PTR_NAME "ec2-203-0-113-25.us-west-2.compute.amazonaws.com"
#define SLOTH_PTR_LINE \
    "{\"type\":\"dns\",\"ts\":1792627200,\"src\":\"192.0.2.53\"," \
    "\"qname\":\"25.113.0.203.in-addr.arpa\",\"qtype\":\"PTR\"," \
    "\"answer\":\"" SLOTH_PTR_NAME "\"," \
    "\"is_resp\":1}"

#endif
