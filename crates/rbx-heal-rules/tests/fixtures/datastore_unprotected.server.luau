local service = game:GetService("DataStoreService")
local store = service:GetDataStore("Players")
local value = store:GetAsync("key")
return value
