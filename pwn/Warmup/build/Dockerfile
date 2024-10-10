FROM alpine:latest AS builder


WORKDIR /app
COPY challenge /app/run
RUN chmod +x /app/run

FROM pwn.red/jail



RUN mkdir /srv/app
COPY --from=builder /app/run /srv/app/run
COPY flag.txt /srv/app/flag.txt

# New user for chal
# Set permissions
RUN chmod +x /srv/app/run
RUN chown -R root:root /srv/app
RUN chmod 600 /srv/app/flag.txt
# Expose the service port
EXPOSE 6000
ENV JAIL_PORT=6000 JAIL_TMP_SIZE=1M JAIL_TIME=120
