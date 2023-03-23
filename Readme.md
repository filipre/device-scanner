# 🍓 Device Scanner

Scan your network and see who is connected

## Getting Started

1. Create a `config.yml` file
```yml
# map MAC addresses to names
people:
  Bud Spencer:
    - FF:FF:FF:FF:FF:00 # Smartphone 1/2
    - FF:FF:FF:FF:FF:11 # Smartphone 2/2
  Terence Hill:
    - FF:FF:FF:FF:FF:22 # Smartphone 1/2
    - FF:FF:FF:FF:FF:33 # Smartphone 2/2

# store who is currently online on redis
redis_enable: false
redis_host: 192.168.0.2
redis_port: 6379

# store who is currently online on file
file_enable: false
file_path: "./scan.txt"

# persist who is online when
log_enable: false
log_path: "./log.txt" 
```

2. Create a `docker-compose.yml` and reference to the code here
```yml
services:
  device-scanner:
    container_name: device-scanner
    build: .
    volumes:
      - ${SCAN_PATH}:/app/scan.txt
      - ${SCAN_LOG_PATH}:/app/log.txt
      - ${CONFIG_PATH}:/app/config.yml
    network_mode: host
    environment:
      DEVICE_SCANNER_CONFIG: /app/config.yml
```

3. Start the application
```
docker-compose up
```