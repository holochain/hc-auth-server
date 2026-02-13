-- transition.lua
-- KEYS[1] = obj:{id}
-- KEYS[2] = state:old
-- KEYS[3] = state:new
-- ARGV[1] = id
-- ARGV[2] = expected_old_state
-- ARGV[3] = new_state
-- ARGV[4] = timestamp

local current = redis.call("HGET", KEYS[1], "state")
if not current then
  return { err = "not_found" }
end

if current ~= ARGV[2] then
  return { err = "invalid_state" }
end

redis.call("HSET", KEYS[1], "state", ARGV[3], "updated", ARGV[4])
redis.call("SREM", KEYS[2], ARGV[1])
redis.call("SADD", KEYS[3], ARGV[1])

return "OK"
