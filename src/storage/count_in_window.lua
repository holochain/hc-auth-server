-- count_in_window.lua
-- Counts a hit in a fixed window that starts at the first hit.
-- KEYS[1] = counter key
-- ARGV[1] = window length in seconds
-- Returns the number of hits in the current window, this one included.

local n = redis.call("INCR", KEYS[1])
if n == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end

return n
