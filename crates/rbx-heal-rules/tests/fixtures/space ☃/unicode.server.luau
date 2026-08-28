-- Comments between tokens should not change binding or range facts.
local Remote = {}
Remote.OnServerEvent:Connect(function(player: Player, amount: number)
	local alias: number = amount
	if amount then
		alias = amount + 1
	end
	data.Cash = alias
end)
