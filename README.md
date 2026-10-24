# Phish MSG Ticketmaster Monitor — Chrome v7.3

v7.3 keeps the v7.2 Facets-authoritative alert policy and improves alert deduplication, email retries, parser safety, and polling recovery.

## What changed

**Facets is now authoritative for alerts.** The monitor passively captures Ticketmaster's EventFacets response from the real event page and only alerts when it sees concrete, positive-count **primary** inventory that is not identifiable as Official Platinum or resale-only inventory.

**AVSC is now early-warning only.** AVSC may report active seat/section positions even when the consumer ticket list is empty. AVSC activity is logged as `AVSC_ACTIVITY`, but it cannot send a Gmail/macOS alert by itself.

**AVSC changes trigger verification.** Once an AVSC baseline exists, a changed AVSC fingerprint can cause a short burst of refreshes to try to capture a confirming Facets response. The defaults are 3 attempts, 1 second apart, with a 5-second capture window per attempt. AVSC changes do not by themselves create duplicate ticket alerts.

**Alert fingerprints are stable.** Facets are normalized and sorted before hashing. AVSC fingerprints are stored separately, so seat-map changes do not resend an unchanged availability alert.

**Failed email alerts retry.** A failed Gmail send is saved as undelivered and retried after the configured delay. A retry does not reopen the browser or repeat the macOS notification.

**Polling backs off on errors.** The normal and fast-window rounds are configurable. Network/capture errors trigger exponential backoff up to the configured cap, with a small random delay to avoid synchronized refreshes. The schedule uses the configured timezone.

**Two Facets hosts are recognized.** The monitor watches both:

- `services.ticketmaster.com`
- `offeradapter.ticketmaster.com`

This matters because Ticketmaster's frontend can move the same inventory endpoint between hosts.

## v7.3 states

- `AVAILABLE` — confirmed standard-primary Facets inventory. **Alerts.**
- `EMPTY` — valid Facets response with no available facets. No alert.
- `PLATINUM_ONLY` — Facets inventory exists but is identifiable as Official Platinum only. No alert.
- `RESALE_ONLY` — Facets inventory is resale only. No alert.
- `NONSTANDARD_ONLY` — Facets returned inventory, but it did not pass the standard-primary test. No alert.
- `AVSC_ACTIVITY` — AVSC has active positions/sections but Facets did not confirm consumer inventory. No alert.
- `NO_SIGNAL` — neither authoritative inventory nor a useful AVSC signal was captured. No alert.
- `PRIMARY_UNRESOLVED` — a candidate facet lacks a reliable quantity or its offer type is mixed/ambiguous. No alert.

## What counts as a confirmed Ticketmaster alert

A Facets entry must have an explicit positive integer quantity and concrete inventory fields such as an offer, ticket type, section, place, place-group, or area. If `inventoryTypes` is present, it must include `primary`. Facets identified as resale or Platinum are excluded. Mixed or unresolved offer types do not alert. Because Ticketmaster represents Official Platinum internally as `inventoryType=primary` and `offerType=standard`, the monitor resolves embedded offer records and, when needed, maps Facets ticket-type IDs against the AVSC offer definitions before treating inventory as standard.

The alert email includes the Facets source URL plus the first several standard-primary facet details, including quantity, inventory type, section, price range when Ticketmaster exposes it, and an offer ID when available.

## Install

```bash
cd phish_richmond_ticketmaster_tracker_chrome_v7_2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure Gmail

Credentials are not stored in `config.json`. Set:

```bash
export TICKET_GMAIL_USER="youraddress@gmail.com"
export TICKET_ALERT_EMAIL_TO="where-you-want-alerts@example.com"
read -s TICKET_GMAIL_APP_PASSWORD
export TICKET_GMAIL_APP_PASSWORD
```

`TICKET_ALERT_EMAIL_TO` may contain comma-separated recipients.

## Test Gmail

```bash
python tracker.py --test-email
```

## Run

```bash
python tracker.py
```

A normal startup should include:

```text
INFO Gmail alerts configured for 1 recipient(s).
INFO Ready. Monitoring 2 MSG event(s) with v7.3 facets-authoritative detection.
```

A map/AVSC-only state should now look roughly like:

```text
WARNING MSG 4-Day: AVSC_ACTIVITY | FACETS=NO_SIGNAL | AVSC=ACTIVITY reserved=1730 sections=17 ...
```

That does **not** generate an email.

A genuine primary drop should look like:

```text
INFO MSG 4-Day: FACETS=AVAILABLE_STANDARD lengths=[...] | ... => AVAILABLE
WARNING ALERT MSG 4-Day: ...
WARNING MSG 4-Day: Gmail alert sent
```

## Polling schedule

The config uses America/New_York time, a 5-minute normal round, and a 3-minute fast window from 09:55 to 11:30. A round includes the configured event refresh and capture time. On errors, the delay grows exponentially up to one hour and returns to the normal schedule after a clean round. Tune `normal_round_seconds`, `fast_round_seconds`, `fast_poll_window`, `poll_jitter_fraction`, and `max_error_backoff_seconds` in `config.json`.

Failed Gmail sends are retried after `email_retry_seconds` while the same standard-primary availability remains present. Gmail delivery state is stored per event in the state JSON.

## Tuning AVSC verification

In `config.json`:

```json
"avsc_facets_verify_attempts": 3,
"avsc_facets_verify_delay_seconds": 1.0,
"avsc_facets_verify_capture_seconds": 5.0
```

Set attempts to `0` if you want AVSC changes logged without the extra verification refreshes.

## Security / behavior

This monitor only observes Ticketmaster pages and network responses. It does not cart tickets, purchase, bypass queues, or bypass CAPTCHA. Captured response bodies and AVSC collections are size-bounded, and malformed data is logged as a diagnostic. Gmail credentials remain in environment variables and are never included in the ZIP.
# phish_richmond_ticketmaster_tracker_chrome_v7_2
# phish_richmond_ticketmaster_tracker_chrome_v7_2
