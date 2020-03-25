# Build
FROM golang:latest AS build
COPY . /app
RUN go build

# Release
FROM scratch AS release
COPY --from=build /app/cifs-exporter /usr/local/bin/cifs-exporter
USER 9999:9999
EXPOSE 9695
ENTRYPOINT ["/usr/local/bin/cifs-exporter"]
