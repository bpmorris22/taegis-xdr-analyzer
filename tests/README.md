# Regression tests

Browser tests for the analyzer. They load a build in an iframe, drive its real
functions and DOM, and report pass / fail per check. All test data is fabricated
(built inside `regression.js`, plus `sample/taegis-sample-synthetic.csv`) — no
case data is needed or used.

## Run

Requires Node.js (any current version; no packages to install).

```sh
node tests/serve.js
```

Then open <http://127.0.0.1:8765/tests/run.html>. The page tests the newest
`Taegis-NetFlow-Analyzer-*.html` in the repo root and shows the result in the
heading and the tab title (`PASS · …` / `FAIL · …`).

- Another port: `node tests/serve.js 9000`
- A specific build: `…/tests/run.html?build=Taegis-NetFlow-Analyzer-v0.6.4.html`

The server only listens on `127.0.0.1` and only serves files from this repo. It
is needed because browsers block a page opened from `file://` from reading the
other files.

## What is covered

| Test | Checks |
|---|---|
| `sample` | The synthetic sample loads with the expected event / netflow / auth / reset counts |
| `csv-1` | Text after a closing quote (`"abc"def`) stays in the same field and row |
| `csv-2` | Skipping unused columns leaves the kept columns identical |
| `1` | Words in an IOC comment line are not treated as indicators |
| `2` | The Netflow export contains exactly the rows the table shows |
| `3` | Epoch timestamps in s / ms / µs / ns resolve to the same instant |
| `4` | A file dropped on the IOC tab loads as an IOC list and keeps the dataset |
| `5a` | Loading a second file resets dropdowns and filters and re-runs the IOC sweep |
| `5b` | A failed load keeps the previous dataset and its file name |
| `6` | Failure values (`UNSUCCESSFUL`, `INVALID_PASSWORD`, `MFA_NOT_USED`, …) are not coloured as success |
| `7` | The IOC sweep matches IPv6, NAT, additional-address, defanged and URL indicators |
| `8` | Clicking an IP pivots to that exact address; partial text is still a substring match |
| `9` | CSV export neutralises formula cells and quotes carriage returns |
| `10a` | A redraw reads the filter inputs a fixed number of times, not once per row |
| `10b` | Typing in a text filter redraws once, not per keystroke |
| `10c` | Raw CSV rows are not kept in memory after loading |
| `11` | The IOC sweep checks every populated domain column, not only the first |
| `12` | A CSV that ends inside a quoted field is rejected and the loaded dataset is kept |
| `13` | "Full range" keeps events in the last fraction of a second |
| `14` | Exports include the MFA result, failure detail and application the tables show |
| `15` | "Public IP only" classifies IPv6 by range and rejects malformed addresses |
| `16` | IOC highlights refresh on every table after a sweep and after clearing the list |
| `17` | A CSV without the required Taegis columns is rejected; a sparse export still loads |
| `18` | "Copy for case notes" copies the timeline as filtered and sorted on screen |
| `19` | IPv4 parsing is strict and the private ranges have the right boundaries |

Tests `1`–`10c` correspond to the ten findings fixed in v0.6.3 (they fail on
v0.6.2); `11`–`18` to the eight fixed in v0.6.4 (they fail on v0.6.3). The rest
are guards that pass on all of those builds.

These tests check behaviour, not speed. Do not read load or redraw timings off a
browser tab that is in the background: browsers run hidden pages at reduced
priority, which can inflate them several-fold.

## Adding a test

Add an `await test('id','what it checks',()=>{ … return {pass, detail}; })` block
in `regression.js`. Build rows with the `nf({...})` / `au({...})` helpers and load
them with `load([...])`; every test starts with filters and the IOC list cleared.
