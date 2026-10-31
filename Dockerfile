# Built by GoReleaser (dockers_v2), which puts each platform's skope binary
# at $TARGETPLATFORM/skope in the build context.
FROM litestream/litestream:0.5.17@sha256:dff47ab648faddd4b6385e9eeebc1649edd84fb020c576e8b9311cf1dc4a0155 AS litestream

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 skope \
 && mkdir /data && chown skope /data
COPY --from=litestream /usr/local/bin/litestream /usr/local/bin/litestream
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/skope /usr/local/bin/skope
COPY deploy/litestream.yml /etc/litestream.yml
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint

USER skope
ENV SKOPE_DB=/data/skope.db \
    SKOPE_LISTEN=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["entrypoint"]
CMD ["serve"]
