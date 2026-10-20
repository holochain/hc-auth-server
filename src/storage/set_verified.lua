-- set_verified.lua
-- Replaces a record's `verified` object, in any state.
-- KEYS[1] = auth:{key}
-- ARGV[1] = verified JSON object
-- ARGV[2] = timestamp
-- Returns 1 when the record was updated, 0 when it does not exist.
--
-- `verified` is its own hash field, beside `json`, so writing it never
-- touches `json` and a concurrent rewrite of `json` never loses it.
-- Readers merge the two.

if redis.call("EXISTS", KEYS[1]) == 0 then
  return 0
end

redis.call("HSET", KEYS[1], "verified", ARGV[1], "updated", ARGV[2])

return 1
