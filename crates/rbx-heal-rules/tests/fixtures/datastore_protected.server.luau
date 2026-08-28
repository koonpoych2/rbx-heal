local service = game:GetService("DataStoreService")
local store = service:GetDataStore("Players")
local ok, value = pcall(function()
    return store:GetAsync("key")
end)
return ok and value
