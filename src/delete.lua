-- delete.lua
-- KEYS[1] = obj:{id}
-- ARGV[1] = id

local state = redis.call("HGET", KEYS[1], "state")
if state then
  redis.call("SREM", "state:" .. state, ARGV[1])
end

redis.call("DEL", KEYS[1])
return "OK"
