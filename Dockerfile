FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /out/mattermost-agent-registrar . && mkdir -p /out/data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/mattermost-agent-registrar /mattermost-agent-registrar
# The enrollment token store (ENROLLMENT_STORE, default /data/enrollments.json).
COPY --from=build --chown=nonroot:nonroot /out/data /data
VOLUME /data
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mattermost-agent-registrar"]
