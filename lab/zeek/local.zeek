# SentinelX Zeek configuration
@load policy/tuning/json-logs
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/modbus

# Rotate logs hourly
redef Log::default_rotation_interval = 1 hr;
redef LogAscii::use_json = T;
redef ignore_checksums = T;

