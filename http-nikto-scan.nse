description = [[ "This script will run nikto on web servers found" ]] 
author = {"Sanoop Thomas a.k.a. @s4n7h0"} 
category = {"safe","discovery","vuln"}

local shortport = require('shortport')
local stdnse = require('stdnse')

portrule = shortport.http

action = function(host,port)
	
	local result 
	local filename = "http-nikto-scan-" .. host.ip .. ":" .. port.number .. ".html"
	local cmd = "nikto -host " .. host.ip .. " -port " .. port.number .. " -Format html -output " .. filename .. "> /dev/null"
	if(nmap.registry.args.display == "on") then
		local cmd = "nikto -host " .. host.ip .. " -port " .. port.number .. " -Format html -output " .. filename
	end
	
	local ret = os.execute(cmd)
	if ret then
		result = "Nikto scan result saved to " .. filename
	end
	return stdnse.format_output(true, result)    
end
