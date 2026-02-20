-- add_pending.lua
-- KEYS[1] = auth:{id}
-- KEYS[2] = state:pending
-- ARGV[1] = id
-- ARGV[2] = json_blob
-- ARGV[3] = timestamp
-- ARGV[4] = max_pending (as number)

if redis.call("EXISTS", KEYS[1]) == 1 then
  return { err = "already_exists" }
end

local count = redis.call("SCARD", KEYS[2])
if count >= tonumber(ARGV[4]) then
  return { err = "limit_reached" }
end

redis.call("HSET", KEYS[1],
  "state", "pending",
  "json", ARGV[2],
  "updated", ARGV[3]
)

redis.call("SADD", KEYS[2], ARGV[1])
return "OK"
