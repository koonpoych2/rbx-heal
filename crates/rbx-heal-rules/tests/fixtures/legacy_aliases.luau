local Players = game:service("Players")
local touched = workspace.Part.Touched:connect(function() end)
local connection = touched
connection:disconnect()

