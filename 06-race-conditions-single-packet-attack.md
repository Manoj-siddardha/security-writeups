# Race Conditions: Why the Single-Packet Attack Works

A breakdown of race conditions in web applications — what they actually are, why
sending requests "at the same time" is harder than it sounds, why the
single-packet attack solves it, and where these bugs show up in real targets.

This isn't a lab walkthrough. It's an attempt to explain the *mechanism* clearly,
because once the mechanism clicks, spotting these bugs in the wild gets a lot
easier.

> **TL;DR:** Race conditions live in the gap between "check" and "update." Sending
> requests fast fails because of network jitter; the single-packet attack fixes
> this by packing HTTP/2 requests into one TCP packet. Hunt wherever an app
> enforces "only once."

---

## The bug in one sentence

A race condition happens when an application **checks something, then acts on it,
and there's a gap in between** — and an attacker slips a second request into that
gap before the first one finishes.

That's the whole idea. Everything below is detail on top of it.

---

## The race window

Take a simple, common operation: applying a one-time discount code. Under the
hood, the server usually does three separate steps:

1. **Check** — has this code already been used? (reads the database)
2. **Use** — apply the discount
3. **Update** — mark the code as used (writes to the database)

The developer *assumes* these run start-to-finish as one unit before anything
else touches the data. But they don't have to.

The **race window** is the gap between step 1 (check) and step 3 (update). During
that window, the database still says `used = false`, because step 3 hasn't run
yet.

Now send two requests at almost the same instant:

```
Request 1:  check(used? false) → apply ✓ → set used = true
Request 2:  check(used? false) → apply ✓ → set used = true
            ↑ both read "false" BEFORE either one wrote "true"
```

Both requests read `false`, both pass the check, both apply the discount. A code
that was meant to work once now works twice — or twenty times. This is often
called a **limit overrun**: you exceed a limit the business logic was supposed to
enforce.

Compare that to the requests arriving one after another:

```
Request 1:  check(false) → apply ✓ → set used = true
Request 2:  check(TRUE) → rejected
```

Same code, same server. The only difference is *timing*. That's what makes race
conditions feel strange at first — the vulnerability isn't in the logic you can
read, it's in *when* things happen.

---

## Why naive attempts fail

The obvious first attempt is: "just fire the requests really fast, one after
another." It almost never works, and the reason is **network jitter**.

Even if you send two requests back-to-back, they travel across the network
independently. They pass through different buffers, get processed by different
threads, and arrive milliseconds apart. The race window can be a fraction of a
millisecond — so "a few milliseconds apart" is often enough to *miss* it
completely.

You can send 50 requests in a loop and watch every single one get rejected,
because by the time request #2 actually reaches the check, request #1 has already
finished writing `used = true`. The requests are racing, but they're not arriving
*together*, so there's no collision.

The problem was never "send faster." The problem is **synchronising arrival**.

---

## What actually works — the single-packet attack

The single-packet attack solves the synchronisation problem directly.

The trick: with HTTP/2, you can send **multiple complete requests inside a single
TCP packet**. When that packet lands, the server receives all of those requests
at effectively the same instant and starts processing them together. Network
jitter is removed from the equation, because there's only one packet to deliver.

This is why the attack **requires HTTP/2**. On HTTP/1.1 you can't pack requests
this way, so the technique doesn't apply (you'd fall back to older, less reliable
tricks like last-byte synchronisation).

Two practical ways to run it:

**1. Burp Repeater — "Send group in parallel"**

Add your requests to a tab group, then use the parallel send option. Burp
assembles them into a single-packet attack for you. This is the fastest way for
simple cases and it works in both Professional and Community editions.

**2. Turbo Intruder** — for anything more complex (retries, staggered timing, or a
large number of requests):

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Queue 20 copies of the request into one gate — nothing is sent yet.
    for i in range(20):
        engine.queue(target.req, gate='1')

    # Open the gate — all 20 requests fire together, in parallel.
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```

The mental model that helped me: it's a **horse-race starting gate**. `queue()`
lines all the horses up behind the gate without letting them run. `openGate()`
fires the gun, and every horse bursts out at once. That simultaneous burst is
what lands inside the tiny race window.

A couple of things worth knowing in practice:

- **Single-endpoint** races (spamming the same endpoint with different values) stay
  naturally in sync, because every request does the same work and takes the same
  time.
- **Multi-endpoint** races (two *different* endpoints that share a critical window)
  are harder. Even fired together, the two requests can reach their windows at
  different times because different endpoints process at different speeds. The fix
  is **connection warming** — send a throwaway request (like `GET /`) first to
  absorb the connection-setup delay, so the real requests then sync up.

---

## Root cause

Underneath all of this, the root cause is simple: **the operation isn't atomic.**

"Atomic" means a sequence of steps runs as one indivisible unit — nothing else can
observe or interfere with the data while it's mid-way through. The discount check
above is *not* atomic: there's a moment, between reading and writing, where the
application is in a temporary in-between state (`used` is still `false` even though
a redemption is already in progress). An attacker who catches that state wins.

This is a classic **time-of-check to time-of-use (TOCTOU)** flaw: the app checks a
condition at one moment, then acts on it a moment later, assuming nothing changed
in between.

---

## The fix

Defenders close the window by making the check-and-update genuinely atomic, or by
letting the datastore reject duplicates:

- **Atomic database transactions** — perform the check, the action, and the update
  as a single transaction so no other request can slip in between.
- **Locks** — take a lock on the relevant record (e.g. row-level locking / `SELECT
  ... FOR UPDATE`) so concurrent requests queue instead of racing.
- **Unique constraints** — enforce uniqueness at the database level (e.g. one
  redemption row per (user, code) pair). Even if two requests race, the second
  insert fails.
- **Idempotency keys** — require a client-supplied key per operation and reject
  repeats, so a duplicated request is a no-op instead of a second effect.

The theme across all of these: don't rely on application-layer "check then write"
logic to enforce a limit. Push the guarantee down to a layer that can enforce it
atomically.

---

## Where I'd hunt for this in real apps

The pattern to look for is always the same: **anywhere the app enforces "only
once" or "only N times," and does it with a separate check step and update step.**
Some of the highest-value places:

- **Coupon / promo code redemption** — redeem a one-time code multiple times.
- **Gift card redemption** — credit a balance more than once from a single card.
- **Rate limits** — beat "you've tried too many times" when the counter is checked
  before it's incremented (relevant to brute-force protection).
- **2FA / OTP attempts** — exceed the allowed number of verification attempts.
- **Account balances** — withdraw or transfer more than the balance, because two
  requests both read the old balance before either deducts.
- **Invite / referral limits** — send more invites or claim more referral rewards
  than the cap allows.
- **"Claim once" rewards, votes, and ratings** — anything meant to be a single
  action per user.

When I find one of these features, the question I ask is: *is the check and the
update atomic, or is there a window between them?* If there's a window, it's worth
testing with a single-packet attack.
