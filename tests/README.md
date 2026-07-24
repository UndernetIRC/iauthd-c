# iauthd-c Integration Tests

Python/pytest suite that rebuilds/ups **[undernet-development-env](https://github.com/UndernetIRC/undernet-development-env)**
with this checkout as `IAUTHD_SRC`, then drives clients against that stack.

| Role | Where |
|------|--------|
| ircd hub/leaf | undernet-development-env containers |
| CHECK | real GNUWorld (`channels.undernet.org`) |
| VERIFY | host-side fake P10 peer linked to hub `:4400` |
| SASL | real gnuworld/cservice (`channels.undernet.org`) |
| Clients | leaf `:6667` |

There is **no** separate iauthd-c Docker image or compose file in this repo.

## Topology

```
pytest (host)
  ├─ IRCClient ──────────────────────────► leaf :6667
  └─ XQueryService (verify.test.net) ───► hub  :4400
         │
         └─ undernet-development-env
              hub + leaf (iauthd-c from this tree) + db + gnuworld
              (CHECK + SASL via channels.undernet.org / cservice)
```

## Prerequisites

- Docker + Docker Compose v2
- Checkout of **undernet-development-env** (default
  `~/undernet-development-env`, override with `UNDERNET_ENV`)
- That env’s `.env` may still point `IRCU2_SRC` / `GNUWORLD_SRC` at your trees;
  these tests always set `IAUTHD_SRC` to **this** iauthd-c repo when composing
- Python 3.10+

## Setup

```bash
cd tests
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running tests

From `tests/`:

```bash
pytest -v
```

On session start the suite:

1. Installs a test `etc/iauthd-c.conf` into undernet-development-env (backed up)
2. Injects Connect/UWorld stanzas for the host-side peers into `etc/hub.conf`
3. Runs `docker compose up --build -d hub leaf db gnuworld` with `IAUTHD_SRC`
   pointing at this repo
4. Waits for leaf `:6667`, hub `:4400`, and gnuworld uplink

On session end it restores the undernet `etc/` files and restarts hub/leaf.
Set `UNDERNET_TEARDOWN=1` to also `docker compose down`.

## Writing tests

- **Registration / CHECK:** use `make_client` (and usually `verify_ok_peer` so
  VERIFY does not block). Assert on `001` and/or `iauthd_log("leaf")`.
- **VERIFY MORE/AGAIN:** see `test_verify.py` — peer replies with opaque
  challenge notices, then OK (out-of-band approval). SASL uses real cservice
  (`Admin` / `temPass2020@`).

## Troubleshooting

```bash
export UNDERNET_ENV=~/undernet-development-env
cd "$UNDERNET_ENV"
docker compose logs hub leaf gnuworld
docker compose exec leaf cat /tmp/iauthd-c.log
docker compose ps
```
