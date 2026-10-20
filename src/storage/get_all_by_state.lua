-- get_all_by_state.lua
-- KEYS[1]: set key for the state (e.g., state:pending)
-- Returns: A flat list of [key, json, verified] triples. `verified` is
-- the empty string when the record has none.

local state_key = KEYS[1]
local keys = redis.call('SMEMBERS', state_key)
local results = {}

for _, key in ipairs(keys) do
    local auth_key = 'auth:' .. key
    local json, verified =
        unpack(redis.call('HMGET', auth_key, 'json', 'verified'))
    if json then
        table.insert(results, key)
        table.insert(results, json)
        table.insert(results, verified or '')
    end
end

return results
