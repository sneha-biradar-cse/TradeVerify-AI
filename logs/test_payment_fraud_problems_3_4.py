"""Regression tests for Problem 3 (back-to-back card failures) and Problem 4 (bot-speed payments).

Run:  python logs/test_payment_fraud_problems_3_4.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import account_scout as a
from fraud_policy import POLICY

D = POLICY["risk_scoring"]["decisions"]
CARD = POLICY["carding"]
BOT = POLICY["bot"]
BLOCK_SEC = CARD["block_duration_seconds"]
N = CARD["account_failures"]["count"]            # back-to-back failures that block the account
assert N == 4 and CARD["same_payment_method_failures"]["count"] == 4, "policy: block on the 4th failure in a row"
assert BOT["strike_count"] == 2, "policy: warn on the first too-fast payment, block on the repeat"


def attempt(sess, fp, acct, ip, t, ok):
    """One customer payment exactly as checkout runs it: card check + ONE timing event."""
    pre = a.record_card_authorization(sess, fp, success=None, ip=ip, account_id=acct, timestamp=t)
    bot = a.record_transaction_event(sess, timestamp=t, account_id=acct, ip=ip)
    post = a.record_card_authorization(sess, fp, success=ok, ip=ip, account_id=acct,
                                       timestamp=t + 0.001, register_attempt=False)
    risk = a.evaluate_payment_risk(post, bot, account_id=acct, ip=ip)
    return pre, bot, post, risk


def card_only(sess, fp, acct, t, ok, ip="10.9.9.9"):
    a.record_card_authorization(sess, fp, success=None, ip=ip, account_id=acct, timestamp=t)
    return a.record_card_authorization(sess, fp, success=ok, ip=ip, account_id=acct, timestamp=t + 0.001, register_attempt=False)


# ------------------------------------------------------------------ decision bands
assert a._risk_decision(D["allow_below"] - 1) == "ALLOW"
assert a._risk_decision(D["allow_below"]) == "STEP_UP_REQUIRED"
assert a._risk_decision(D["step_up_below"]) == "REVIEW"
assert a._risk_decision(D["block_at_or_above"]) == "BLOCK"
print("ok  decision bands match fraud_policy.json")

# ============================ PROBLEM 3: back-to-back card failures ============================
# stolen card tried at human pace: blocked on the 4th failure, and it is NOT mistaken for a bot
a.reset_live_state()
res = [attempt("s3", "stolen1", "exporter:thief", "10.0.0.1", 1000 + i * 3, False) for i in range(4)]
assert [r[2]["status"] for r in res] == ["PASSED", "PASSED", "PASSED", "CARDING_RED_FLAG"], [r[2]["status"] for r in res]
assert all(r[1]["status"] == "PASSED" for r in res), "human-paced failures must not look like a bot"
print("ok  P3 stolen card, 4 failures in a row: blocked on the 4th")

# the customer is warned how many tries are left
a.reset_live_state()
left = [card_only("g1", "cardG", "acctG", 100 + i * 5, False)["attempts_remaining"] for i in range(4)]
assert left == [3, 2, 1, 0], left
print("ok  P3 tries-left warning:", left)

# 4 DIFFERENT stolen cards in a row, each from a NEW session: still caught (account-wide)
a.reset_live_state()
res = [card_only(f"sess{i}", f"card{i}", "acctK", 100 + i * 30, False) for i in range(4)]
assert [r["status"] for r in res] == ["PASSED", "PASSED", "PASSED", "CARDING_RED_FLAG"], [r["status"] for r in res]
assert res[3]["account_failures_in_window"] >= N
print("ok  P3 rotating cards + sessions: blocked on the 4th failure in a row")

# slow, spread-out failures do not add up
a.reset_live_state()
res = [card_only(f"sess{i}", f"card{i}", "acctL", 100 + i * 250, False) for i in range(4)]
assert all(r["status"] == "PASSED" for r in res)
a.reset_live_state()
res = [card_only("sx", "cardX", "acctX", 100 + i * 480, False) for i in range(4)]
assert all(r["status"] == "PASSED" for r in res)
print("ok  P3 failures spread over many minutes are not blocked")

# genuine customer: a successful payment ends the streak
a.reset_live_state()
for i in range(3):
    card_only("g2", "cardH", "acctH", 100 + i * 5, False)
ok = card_only("g2", "cardH", "acctH", 115, True)
assert ok["status"] == "PASSED" and ok["failed_attempts"] == 0
later = card_only("g2", "cardH", "acctH", 120, False)
assert later["status"] == "PASSED" and later["failed_attempts"] == 1 and later["attempts_remaining"] == 3, later
print("ok  P3 genuine customer: success ends the streak (tries_left back to 3)")
a.reset_live_state()
seq = [card_only("g3", "cardI", "acctI", 100 + i * 5, False)["status"] for i in range(4)]
assert seq[-1] == "CARDING_RED_FLAG"
print("ok  P3 control: without a success in between, the 4th failure blocks")

# the block is explained, timed and expires by itself
a.reset_live_state()
for i in range(4):
    blocked = card_only("g5", "cardM", "acctM", 100 + i * 5, False)
assert blocked["retry_after_seconds"] == BLOCK_SEC and blocked["block_type"] == "carding"
assert a.record_card_authorization("g5", "cardM", success=None, account_id="acctM", timestamp=100 + BLOCK_SEC - 10)["status"] == "CARDING_RED_FLAG"
assert a.record_card_authorization("g5b", "cardN", success=None, account_id="acctM", timestamp=115 + BLOCK_SEC + 5)["status"] == "PASSED"
print(f"ok  P3 lock lasts {BLOCK_SEC // 60} minutes, then the customer can pay again")

# admin sees a card-testing block, labelled as such, and can unblock the whole thing
a.reset_live_state()
for i in range(4):
    attempt("sa", "stolenA", "exporter:carl", "10.1.1.1", 500 + i * 3, False)
rows = {b["key"]: b["meta"] for b in a.list_blocked(now=515.0)}
assert rows["account:exporter:carl"]["type"] == "carding" and rows["account:exporter:carl"]["reason"]
assert all(m.get("type") == "carding" for m in rows.values()), rows
assert a.unblock("account:exporter:carl") is True
assert a.record_card_authorization("sb", "freshCard", success=None, account_id="exporter:carl", timestamp=520.0)["status"] == "PASSED"
print("ok  P3 admin sees a CARDING block and unblock restores the account")

# =============================== PROBLEM 4: payment speed a human cannot reach ===============================
EV = a.record_transaction_event

# first too-fast payment = WARNING (refused with "slow down"), nothing blocked yet
a.reset_live_state()
r1 = EV("s4", timestamp=9000.0, account_id="exporter:bob", ip="10.0.0.4")
r2 = EV("s4", timestamp=9000.3, account_id="exporter:bob", ip="10.0.0.4")
assert r1["status"] == "PASSED"
assert r2["status"] == "SUSPECT" and r2["slow_down"] is True and r2["retry_after_seconds"] == a.SLOW_DOWN_SECONDS, r2
assert "slow down" in r2["alert"].lower() and a.list_blocked(now=9001.0) == [], "a warning must not block"
print("ok  P4 first too-fast payment: 'slow down' warning, nothing blocked")

# the repeat blocks the account right then
r3 = EV("s4", timestamp=9000.6, account_id="exporter:bob", ip="10.0.0.4")
assert r3["status"] == "BOT_RED_FLAG" and r3["block_type"] == "bot" and "bot" in r3["alert"].lower()
assert r3["retry_after_seconds"] == BLOCK_SEC
print("ok  P4 repeat within %ds: bot alert + block" % BOT["strike_window_seconds"])

# the ACCOUNT is blocked: a new session cannot get around it
assert EV("brand-new-session", timestamp=9001.0, account_id="exporter:bob", ip="10.0.0.9")["status"] == "BOT_RED_FLAG"
card = a.record_card_authorization("brand-new-session", "cardZ", success=None, ip="10.0.0.9", account_id="exporter:bob", timestamp=9001.0)
assert card["status"] == "CARDING_RED_FLAG" and card["block_type"] == "bot"
print("ok  P4 the ACCOUNT is blocked: a new session cannot get around it (reported as bot)")

# admin sees it, and Unblock restores everything (session, account, counters)
m = [b for b in a.list_blocked(now=9001.0) if b["key"] == "account:exporter:bob"][0]["meta"]
assert m["type"] == "bot" and m["account_id"] == "exporter:bob" and "session:s4" in m["related"]
assert a.unblock("account:exporter:bob") is True and a.list_blocked(now=9001.0) == []
assert EV("s4", timestamp=9002.0, account_id="exporter:bob", ip="10.0.0.4")["status"] == "PASSED"
assert EV("s4", timestamp=9004.0, account_id="exporter:bob", ip="10.0.0.4")["status"] == "PASSED"
print("ok  P4 admin sees the bot block and Unblock restores the account")

# a double-click / retry (ONE fast gap) is only warned; the warning expires
a.reset_live_state()
EV("sd", timestamp=100.0, account_id="exporter:dbl", ip="1.1.1.1")
assert EV("sd", timestamp=100.2, account_id="exporter:dbl", ip="1.1.1.1")["status"] == "SUSPECT"
assert EV("sd", timestamp=104.0, account_id="exporter:dbl", ip="1.1.1.1")["status"] == "PASSED"     # person carries on normally
EV("sd", timestamp=200.0, account_id="exporter:dbl", ip="1.1.1.1")
assert EV("sd", timestamp=200.2, account_id="exporter:dbl", ip="1.1.1.1")["status"] == "SUSPECT"   # 100 s later: warned again, not blocked
assert a.list_blocked(now=201.0) == []
print("ok  P4 a double-click is warned, never blocked, and the warning expires")

# unblocking from the SESSION row clears the whole incident too
a.reset_live_state()
for ts in (100.0, 100.2, 100.4):
    EV("s7", timestamp=ts, account_id="exporter:eve", ip="1.1.1.1")
assert {b["key"] for b in a.list_blocked(now=101.0)} == {"session:s7", "account:exporter:eve"}
assert a.unblock("session:s7") is True and a.list_blocked(now=101.0) == []
print("ok  P4 unblocking either row clears the whole incident")

# card-testing freezes are labelled carding and are never reported as a bot
a.reset_live_state()
for i in range(4):
    attempt("sc", "cardQ", "exporter:cara", "10.0.0.7", 500 + i * 3, False)
assert {b["meta"].get("type") for b in a.list_blocked(now=512.0)} == {"carding"}
assert EV("sc", timestamp=513.0, account_id="exporter:cara", ip="10.0.0.7")["status"] == "PASSED"
print("ok  card-testing blocks are labelled carding and never reported as a bot")

# people are never flagged
a.reset_live_state()
assert {attempt("s4b", "cardD", "acctBB", "10.0.0.5", 9500 + i * 3, True)[1]["status"] for i in range(6)} == {"PASSED"}
a.reset_live_state()
assert {EV("sH", timestamp=7000 + i * 2.5, account_id="exporter:human", ip="7.7.7.9")["status"] for i in range(20)} == {"PASSED"}
a.reset_live_state()
assert {EV("sP3", timestamp=8000 + i * 1.5, account_id="exporter:p3", ip="7.7.7.10")["status"] for i in range(12)} == {"PASSED"}
print("ok  P4 payments 3 s, 2.5 s and 1.5 s apart (human pace, Problem 3 demos) are never flagged")

# speed rule 2 (rate): about one payment per second. Warning at the 4th payment, block at the 5th.
RL_N, RL_W = BOT["rate_limit_count"], BOT["rate_limit_window_seconds"]
assert (RL_N, RL_W) == (4, 4)
a.reset_live_state()
res = [EV("sR", timestamp=5000 + i * 1.0, account_id="exporter:rate", ip="7.7.7.7") for i in range(8)]
assert [r["status"] for r in res[:5]] == ["PASSED", "PASSED", "PASSED", "SUSPECT", "BOT_RED_FLAG"], [r["status"] for r in res]
assert res[4]["gap_ms"] >= BOT["minimum_human_gap_ms"], "must be the RATE rule, not the gap rule"
assert "payments within" in res[4]["details"] and "alert" in res[4]
row = [b for b in a.list_blocked(now=5005.0) if b["key"] == "account:exporter:rate"][0]["meta"]
assert row["type"] == "bot" and "payments within" in row["reason"]
print("ok  P4 one payment per second: warned at payment 4, blocked at payment 5, admin sees the reason")

# a bot that changes its session id every payment cannot dodge it; Unblock resets the counters
a.reset_live_state()
res = [EV(f"newsess{i}", timestamp=6000 + i * 1.0, account_id="exporter:rot", ip="7.7.7.8") for i in range(6)]
assert [r["status"] for r in res[3:5]] == ["SUSPECT", "BOT_RED_FLAG"], [r["status"] for r in res]
assert a.unblock("account:exporter:rot") is True
assert EV("afterFix", timestamp=6005.0, account_id="exporter:rot", ip="7.7.7.8")["status"] == "PASSED"
print("ok  P4 changing session ids does not help a bot; Unblock also resets the counters")

# ================================ BOTH TOGETHER ================================
a.reset_live_state()
slow = [attempt("bs", "stolenS", "exporter:slow", "10.2.2.2", 2000 + i * 3, False) for i in range(4)]
assert slow[3][2]["status"] == "CARDING_RED_FLAG" and slow[3][3]["decision"] in ("BLOCK", "REVIEW")
assert {b["meta"]["type"] for b in a.list_blocked(now=2010.0)} == {"carding"}
a.reset_live_state()
fast = [attempt("bf", f"stolenF{i}", "exporter:fast", "10.3.3.3", 3000 + i * 0.2, False) for i in range(4)]
assert [f[1]["status"] for f in fast[:3]] == ["PASSED", "SUSPECT", "BOT_RED_FLAG"], [f[1]["status"] for f in fast]
assert {b["meta"]["type"] for b in a.list_blocked(now=3001.0)} == {"bot"}
print("ok  BOTH: stolen card at human pace = card-testing block (4th failure); at machine speed = warning, then bot block")

# ================================ LIVE STATUS BADGE ================================
a.reset_live_state()
S = a.account_security_status
assert S("exporter:badge", now=1.0)["state"] == "clean"
card_only("sb", "cardB1", "exporter:badge", 100, False)
st = S("exporter:badge", now=101.0)
assert st["state"] == "warning" and st["kind"] == "carding" and "1 failed payment" in st["label"], st
for i in range(3):
    card_only("sb", "cardB1", "exporter:badge", 105 + i * 3, False)
st = S("exporter:badge", now=115.0)
assert st["state"] == "blocked" and st["kind"] == "carding", st
a.unblock("account:exporter:badge")
a.reset_live_state()
EV("sw", timestamp=300.0, account_id="exporter:fast", ip="1.1.1.1"); EV("sw", timestamp=300.2, account_id="exporter:fast", ip="1.1.1.1")
st = S("exporter:fast", now=301.0)
assert st["state"] == "warning" and st["kind"] == "bot", st
EV("sw", timestamp=300.4, account_id="exporter:fast", ip="1.1.1.1")
st = S("exporter:fast", now=301.0)
assert st["state"] == "blocked" and st["kind"] == "bot" and "bot" in st["label"].lower(), st
a.unblock("account:exporter:fast")
assert S("exporter:fast", now=302.0)["state"] == "clean"
print("ok  LIVE badge: protected -> warning -> blocked (card or bot) -> clean after unblock, all automatic")

print("\nALL PROBLEM 3 & 4 REGRESSION TESTS PASSED")
