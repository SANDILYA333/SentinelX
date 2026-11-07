# SentinelX Zeek configuration
@load policy/tuning/json-logs
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/modbus

# Keep log filenames stable for live tailing (disable automatic time-rotation file renaming)
redef Log::default_rotation_interval = 0 hrs;
redef LogAscii::use_json = T;
redef ignore_checksums = T;

