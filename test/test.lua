-- package.path = package.path..";./src/?.lua"	-- For Zerobrane
--package.path = package.path..";./../src/?.lua"

u = require("LuaUPNP")

uo,err = u.new()
print(uo,err)

print("Listen passively")
print(uo.pcap)
print(uo:pcap(3))

print("Do m-search")
print(uo.msearch)
print(uo:msearch(3))

print("Hosts accumulated are: ")
for k,v in pairs(uo.hosts) do
	print(k,v)
	for l,m in pairs(v) do
		print("    ",l,m)
	end
	if v.xmlFile == [[http://192.168.0.191:49153/setup.xml]] then
		i = k
	end
end

-- Belkin Wemo device commands to turn ON/OFF
-- If it does not work play with the client UDP socket setsockname IP address in the creation of the UPNP object

--i = 2
print(uo.hosts[i]:getInfo())
print(uo.hosts[i]:send("controllee","basicevent","SetBinaryState",{BinaryState=1}))
--print(uo.hosts[i]:send("controllee","basicevent","GetBinaryState",{BinaryState=0}))