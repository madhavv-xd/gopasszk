FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -o /out/migrate ./cmd/migrate

FROM alpine:3.20
COPY --from=build /out/ /app/
EXPOSE 8080
# AutoMigrate is idempotent, so running it on every start is safe.
ENTRYPOINT ["/bin/sh", "-c", "/app/migrate && exec /app/server"]
