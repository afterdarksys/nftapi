FROM alpine:3.22
RUN apk add --no-cache nftables
COPY nftapi /usr/local/bin/nftapi
COPY nftapi.test /usr/local/bin/nftapi.test
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY docker-test-inner.sh /docker-test-inner.sh
RUN chmod 755 /docker-entrypoint.sh /docker-test-inner.sh /usr/local/bin/nftapi /usr/local/bin/nftapi.test
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/docker-test-inner.sh"]
