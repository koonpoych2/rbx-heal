local Buy = {}

Buy.OnServerEvent:Connect(function(player, itemId)
	if not RateLimiter:Allow(player) then
		return
	end
	PurchaseService:Buy(player, itemId)
end)

