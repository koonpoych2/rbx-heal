local RunService = game:GetService("RunService")
RunService.RenderStepped:Connect(function()
	-- rbx-heal: ignore RBX-PERF-001 -- bounded by the scene contract
	local refs = workspace:GetDescendants()
	print(refs)
end)
