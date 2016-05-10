# network-slave
Simple server mapping network requests to local commands

## Usage
To start the server, simply invoke it by using:
```bash
network-slave [PATH-TO-CONFIG-FILE]
```

## Configuration
You can define HTTP and UDP server settings in the config file like so:
```ini
[host]
bind=127.0.0.1

[ports]
http=23000
udp=23001

[commands]
play=/opt/play.sh
door=/opt/door.sh
alarm=/opt/alarm.sh
```

## HTTP
To connect to the HTTP server, simply send an HTTP 1.1 request:
```bash
curl http://$MACHINE:$PORT/$COMMAND/$PARAMS
```

## UDP
To connect to the UDP server, simply send a datagram like so:
```bash
echo -n "$COMMAND/$PARAMS" | ncat -u "$HOST" "$PORT"
```
