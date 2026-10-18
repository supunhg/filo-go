# REST API

`filo api` serves filo's analyzers over HTTP. Request and response bodies are JSON.

## Security model

The server is locked down by default:

| Setting | Default | Notes |
|---|---|---|
| Listen address | `127.0.0.1:8080` | `--addr`, or `--port` to change only the port |
| Authentication | none on localhost | Any other address requires `--token` (or `FILO_API_TOKEN`); `--insecure-no-auth` overrides this, for use behind an authenticating proxy only |
| File access | disabled | `--root DIR` enables path endpoints for files under `DIR` only |
| Upload limit | 64 MiB | `--max-upload` (MiB) |

How paths are resolved:

- Paths are relative to `--root`; absolute paths inside it also work.
- Symlinks are resolved before the containment check, so `../` and links cannot reach files
  outside the root.
- Missing files outside the root are reported as "access denied", which avoids revealing what
  exists there.

When a token is set, send it on every request except `/api/health`:

```bash
curl -H "Authorization: Bearer $FILO_API_TOKEN" ...
```

Responses carry `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and a restrictive
Content Security Policy. Put TLS in front of the server with a reverse proxy if you expose it
beyond localhost.

## Response envelope

```json
{
  "success": true,
  "data": { ... },
  "meta": { "version": "v0.6.0", "timestamp": "2026-10-18T04:07:24Z", "duration": "1.2ms" }
}
```

On failure, `success` is `false` and `error` holds a message. Status codes:

| Code | Meaning |
|---|---|
| 400 | Bad request, or the path is not a regular file / directory |
| 401 | Missing or wrong bearer token |
| 403 | Path outside `--root`, or path endpoints disabled |
| 404 | File not found |
| 405 | Wrong HTTP method |
| 413 | Body or upload too large |

## Endpoints

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/health` | | `{"status": "healthy"}` (no auth) |
| `GET` | `/api/version` | | Server version |
| `POST` | `/api/analyze` | `{"path"}` | Same object as `filo analyze --json` |
| `POST` | `/api/scan` | `{"path", "formats"?, "nested"?}` | Array of embedded files: `offset`, `size`, `format`, `mime`, `description` |
| `POST` | `/api/hash` | `{"path", "algorithms"?}` | Digests (default MD5, SHA-1, SHA-256) |
| `POST` | `/api/strings` | `{"path", "min_length"?, "max_count"?}` | Strings with offsets |
| `POST` | `/api/crypto` | `{"path"}` | Entropy, chi-square, verdict, container |
| `POST` | `/api/stego` | `{"path"}` | Steganography indicators (experimental) |
| `POST` | `/api/metadata` | `{"path"}` | EXIF, XMP, IPTC |
| `POST` | `/api/batch` | `{"directory", "workers"?, "recursive"?}` | Per-file analysis summary |
| `POST` | `/api/upload` | multipart field `file` | `{"filename", "size", "analysis"}` |

`/api/upload` works without `--root`: the file is analyzed in memory and never written to disk.

## Examples

```bash
filo api --root ./evidence

curl -s localhost:8080/api/analyze -d '{"path": "sample.bin"}' | jq .data.description
curl -s localhost:8080/api/scan -d '{"path": "fw.bin", "formats": ["squashfs", "uimage"]}'
curl -s localhost:8080/api/hash -d '{"path": "sample.bin", "algorithms": ["sha256"]}'
curl -s localhost:8080/api/upload -F file=@suspicious.docx
```

## Docker

```bash
export FILO_API_TOKEN=$(openssl rand -hex 32)
mkdir -p data && cp sample.bin data/
docker compose up -d
curl -H "Authorization: Bearer $FILO_API_TOKEN" localhost:8080/api/analyze -d '{"path": "sample.bin"}'
```

The bundled `docker-compose.yml`:

- publishes the port on `127.0.0.1` only;
- mounts `./data` read-only as the root;
- runs the container with a read-only filesystem;
- refuses to start without `FILO_API_TOKEN`.
