# unifi_proxy
Change your unifi firewall rules programmatically!

## Disable a firewall rule
```shell
go run main.go --insecure --host="http://<host>" --user=<user> --pass=<pass> --disable-rule="<Rule Name>"
```

## Enable a firewall rule
```shell
go run main.go --insecure --host="http://<host>" --user=<user> --pass=<pass> --enable-rule="<Rule Name>"
```

## Run via docker
1. Set UNIFI_HOST, UNIFI_USER, UNIFI_PASS environment variables
2. Use twoboxen/unifi_proxy:latest
3. Map port 8080 if you want
3. Send some payloads!
```shell
curl -X "POST" -H "Content-Type: application/json" \
    -d '{"name": "<Rule Name>", "enabled": true/false}' \
    http://<host>:8080/rules
```

