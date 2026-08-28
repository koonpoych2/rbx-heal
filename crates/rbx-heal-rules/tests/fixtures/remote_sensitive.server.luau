local Buy = {}

Buy.OnServerEvent:Connect(function(player, amount)
	player.cash += amount
end)

