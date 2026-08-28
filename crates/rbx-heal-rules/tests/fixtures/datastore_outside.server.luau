local dataStoreService = game:GetService("DataStoreService")
local store = dataStoreService:GetDataStore("Players")
return store:GetAsync("key")
