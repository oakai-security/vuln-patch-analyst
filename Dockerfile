# Multi-stage non-root container for vuln-patch-analyst
FROM python:3.12-slim-bookworm AS builder

WORKDIR /app
RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md /app/
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

COPY src /app/src
RUN uv pip install --no-cache-dir .

# Runtime stage
FROM python:3.12-slim-bookworm AS runtime

# Create dedicated non-root user (UID 1002) in group oakai (GID 2000)
RUN groupadd -g 2000 oakai && \
    useradd -u 1002 -g oakai -s /bin/false -m vuln-patch

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV UDS_PATCH_SOCKET="/run/oakai/patch.sock"
ENV UDS_REQUEST_SOCKET="/run/oakai/request.sock"

# Pre-create socket directory with permissions
RUN mkdir -p /run/oakai && chown -R vuln-patch:oakai /run/oakai && chmod 770 /run/oakai

USER vuln-patch:oakai

EXPOSE 0
ENTRYPOINT ["vuln-patch-analyst"]
CMD ["serve"]
