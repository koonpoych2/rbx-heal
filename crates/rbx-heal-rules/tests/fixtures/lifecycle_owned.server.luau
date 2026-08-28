local Players = game:GetService("Players")
local connections = {}
Players.PlayerAdded:Connect(function(player)
	table.insert(connections, player.CharacterAdded:Connect(function() end))
end)
