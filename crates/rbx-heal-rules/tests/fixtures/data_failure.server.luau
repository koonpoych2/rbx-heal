local store = game:GetService("DataStoreService"):GetDataStore("Players")

local function load(player)
	local ok, result = pcall(function()
		return store:GetAsync("Player_" .. player.UserId)
	end)
	if not ok then
		return { cash = 0 }
	end
	return result
end

