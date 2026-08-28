local refs = workspace:GetDescendants()
local RunService = game:GetService("RunService")

RunService.RenderStepped:Connect(function()
	print(#refs)
end)

