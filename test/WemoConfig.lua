-- Wemo controller config

-- Detect Wemo switch devices and confirm from user and save the host that the Wemo controller can use

local u = require("LuaUPNP")

local stat,msg

local function listTestSave(devs)
	for i = 1,#devs do
		print("-------- DEVICE #"..i.."--------------")
		for l,m in pairs(devs[i]) do
			print("  ",l,m)
		end
	end
	io.write("Select Device>")
	local opt = io.read()
	if tonumber(opt) ~= 0 then
		if not devs[tonumber(opt)] then
			print("Not a valid choice. Exiting.")
		else
			print("Reading device control information...")
			stat,msg = devs[tonumber(opt)]:getInfo()
			if not stat then
				print("Cannot read control info from the device: "..msg)
			else
				print("Testing the Device...")
				io.write("Turning the switch ON...")
				devs[tonumber(opt)]:send("controllee","basicevent","SetBinaryState",{BinaryState=1})
				io.write("DONE\n")
				io.write("Waiting 3 seconds...")
				local ctime = os.clock()
				while os.clock() - ctime < 3 do
				end
				io.write("DONE\n")
				
				io.write("Turning the switch OFF...")
				devs[tonumber(opt)]:send("controllee","basicevent","SetBinaryState",{BinaryState=0})
				io.write("DONE\n")
				io.write("Waiting 3 seconds...")
				ctime = os.clock()
				while os.clock() - ctime < 3 do
				end
				io.write("DONE\n")
				
				-- Save the device info to file
				io.write("Enter file name to save device information (Enter to exit) >")
				local fName = io.read()
				if fName and #fName > 0 then
					stat,msg = devs[tonumber(opt)]:saveHost(fName)
					if not stat then
						print("Could not save file: "..msg)
					else
						print("File successfully saved")
					end
				end
			end
		end
	end
end

local uo,err = u.new()
if not uo then
	print("Error setting up UPNP connection: "..err)
else
	print("Listen passively for UPNP devices on network...")
	stat,msg = uo:pcap(3)
	
	print("Searching for UPNP devices on network...")
	stat,msg = uo:msearch(3)
	
	if #uo.hosts == 0 then 
		print("Could not find any UPNP devices on the network.")
	else
		-- Get the XML file of all the detected hosts 1 by 1 to filter out the Wemo devices
		local wemoH = {}
		for k,v in pairs(uo.hosts) do
			local xfile = uo.httpGetFile(v.xmlFile)
			-- Check if this file has Wemo Switch text
			if xfile and xfile:lower():match("wemo switch") then
				wemoH[#wemoH + 1] = v
			end
		end
		
		if #wemoH > 0 then
			print("The following devices found that seem to be Wemo switches. Please select a device number to save or 0 to exit:")
			listTestSave(wemoH)
		else
			print("Cannot detect Wemo switch devices, here is a list of all the UPNP devices detected. Select a device or 0 to exit:")
			listTestSave(uo.hosts)
		end
	end
end