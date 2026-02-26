-- get_all_by_state.lua
-- ARGS[1]: set key for the state (e.g., state:pending)
-- Returns: A list of [key, json] pairs

local state_key = KEYS[1]
local keys = redis.call('SMEMBERS', state_key)
local results = {}

for _, key in ipairs(keys) do
    local auth_key = 'auth:' .. key
    local json = redis.call('HGET', auth_key, 'json')
    if json then
        table.insert(results, key)
        table.insert(results, json)
    end
end

return results
