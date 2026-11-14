# Crimson public sandbox image. Build:  docker build -t crimson .   Run:  docker run -p 8080:8080 -e PORT=8080 crimson
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /crimson .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -h /app crimson
WORKDIR /app
COPY --from=build /crimson /app/crimson
USER crimson
# Public hosting mode: demo accounts only, real systems must prove ownership, no private-network scanning.
ENV CRIMSON_SANDBOX=1 CRIMSON_DATA=/app/crimson-data.json
EXPOSE 8080
CMD ["/app/crimson", "serve"]
