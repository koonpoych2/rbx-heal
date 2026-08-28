local RunService = game:GetService("RunService")

RunService.RenderStepped:Connect(function()
	for _, instance in ipairs(workspace:GetDescendants()) do
		instance.Transparency = 0
	end
end)

