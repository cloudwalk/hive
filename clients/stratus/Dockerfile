# Build
FROM stratus_base as builder
# Runtime
FROM rust:1.75 as runtime

WORKDIR /app
COPY --from=builder /app/target/release/stratus /app/stratus
COPY --from=builder /app/config /config

ADD stratus.sh /stratus.sh
RUN chmod +x /stratus.sh
RUN apt-get update && apt-get install -y bash curl jq
ADD hive-bin/createcontracts.sh /hive-bin/createcontracts.sh
RUN chmod +x /hive-bin/createcontracts.sh

RUN echo "1.0.0" > /version.txt

EXPOSE 8545 8546 8547 8551 30303 30303/udp

ENTRYPOINT ["/stratus.sh"]
