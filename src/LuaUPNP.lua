-- uPnP module for Lua
local socket = require("socket")
local mime = require("mime")
local ltn12 = require("ltn12")
local http = require("socket.http")
local type = type
local setmetatable = setmetatable
local getmetatable = getmetatable
local pcall = pcall
local pairs = pairs
local tostring = tostring
local tonumber = tonumber
local lxml = require("LXML")
local table = table

local ostime = os.time

-- For debugging
--local print = print
--local io = io



-- Create the module table here
local M = {}
package.loaded[...] = M
if setfenv then
	setfenv(1,M)	-- Lua 5.1
else
	_ENV = M		-- Lua 5.2
end
-- Create the module table ends

-- OBJECTS

-- UPnP object
-- CREATE:
-- new = function(ip,port,iface)
-- MEMBER FUNCTIONS:
-- close() - close the object connections
-- pcap(timeout) - timeout is optional specifying in seconds the duration of listening
-- msearch(timeout, searchType, searchName) - all parameters optional. timeout as in pcap. searchType and searchName substituted in the ST header of the msearch message if given.
-- MEMBER OBJECTS
-- hosts - array of host objects
-- clnt - client socket (used in msearch)
-- srvr - server socket (used in pcap)
-- msearchHeaders - table containing headers sent during msearch
-- MEMBER VARIABLES
-- ip - multicast ip for uPnP
-- port = 1900 uPnP port
-- iface = "*" interface 

-- uPnP host object
-- CREATE:
-- On doing msearch or pcap the hosts array is populated with discovered hosts
-- MEMBER FUNCTIONS
-- getInfo(hostObj) --  get the full information for the host. This populates all the ''devices'' tables for the host containing all the services, state variables and actions for the device.
-- send(hostObj, devName, serviceName, actionName, sendArgs) -- send a SOAP command
-- MEMBER VARIABLES
-- xmlFile - full url path of xmlFile describing the service
-- host - url of host
-- page - xml file name NOTE: Usually: xmlFile = protocol.."://"..host.."/"..page
-- upnpType - info of the SERVER tag in the xmlFile
-- protocol - such as http
-- enumerated - if true then all information already enumerated
-- serverType - Type of server returned as the server field in the header when the service XML is downloaded
-- devices[] - Table containing list of devices with their data structure of their offered services (populated when getInfo() called). Table keys are the device names which are extracted from the text of the deviceType tag by picking the text after 'device:'. This is from the xmlFile of the host object
--		.deviceType - Info in the deviceType tag of the device XML file
-- 		.friendlyName - Info from the same name XML tag if existed
--		.modelDescription - Info from the same name XML tag if existed
--		.modelName - Info from the same name XML tag if existed
--		.modelNumber - Info from the same name XML tag if existed
--		.modelURL - Info from the same name XML tag if existed
--		.presentationURL - Info from the same name XML tag if existed
--		.UDN - Info from the same name XML tag if existed
--		.UPC - Info from the same name XML tag if existed
--		.manufacturer - Info from the same name XML tag if existed
--		.manufacturerURL - Info from the same name XML tag if existed
--
--		.services[]	- Table containing list of services with their data structure offered by the device. Table keys are the service names which are extracted from the text of the serviceType tag by picking the text after 'service:'. This is from the xmlFile of the host object.
--			.serviceType - Info in the serviceType tag of the device XML file
-- 			.serviceId - Info from the same name XML tag if existed
--			.controlURL - Info from the same name XML tag if existed
--			.eventSubURL - Info from the same name XML tag if existed
--			.SCPDURL - Info from the same name XML tag if existed
--			
--			.actions[] - Table containing list of actions with their data structure of arguments in the service extracted from the XML in SCPDURL of the service description. Table keys are the action names which is the text of the name tag of the action.
--				.arguments[] - Table containing the list of arguments the action takes and their description. Table keys are the argument names which is the text of the name tag of the argument
--					.direction - Info from the same name XML tag if existed
--					.relatedStateVariable - Info from the same name XML tag if existed
--			.serviceStateVariables[] - Table containing list of service state variables with their data structure of values in the service extracted from the XML in SCPDURL of the service description. Table keys are the state variable names which is the text of the name tag of the stateVariable
-- 				.sendEvents - Info from the same name XML tag if existed
--				.dataType - Info from the same name XML tag if existed
-- 				.defaultValue - Info from the same name XML tag if existed
--				.allowedValues[] - Array containing allowed values for the state variable
--				.allowedValueRange - Table with 1st element the minimum value and 2nd element as maximum value


-- LOCAL MODULE FUNCTIONS
-- httpGetFile - get the file from URL and return the content and the returned http headers
-- receive - receive a set size of data from the socket connection with a specified timeout
-- parseSSDP - function to parse the ssdp response and generate a tentative host object. This function is used by msearch and pcap functions
-- sendSOAP - function to send a SOAP request

local upnpMeta = {
		ip = "239.255.255.250", 
		port = 1900,
		iface = "*",
		close = function(o)
			if o.clnt then
				o.clnt:close()	-- Close the receiving socket
			end
			if o.srvr then
				o.srvr:close()	-- close the sending socket
			end
		end
}	-- upnp connection object

upnpMeta.__index = upnpMeta

-- meta table for host object
local hostMeta = {

}

hostMeta.__index = hostMeta

_VERSION = "1.2014.09.11"
_UPNPVERSION = "1.0"

-- Upnp Object constants


local function receive(sckt,size,timeout)
	if not sckt then
		return nil, "Socket object needed"
	end
	if timeout and type(timeout) == "number" then
		--print("set time out")
		sckt:settimeout(timeout)
	end
	if size and type(size) == "number" then
		return sckt:receive(size)
	else
		return sckt:receive()
	end
end

local function httpGetFile(path)
	-- Set the headers
	local hdrs = {["USER-AGENT"] = "uPNP/".._UPNPVERSION}
	local ft = {}
	--print("Get File: ",path)
	-- Now get the File
	local resp = {http.request{
							url = path,
							sink = ltn12.sink.table(ft),
							headers = hdrs
						}
				}
	if not resp[1] then 
		return nil,resp[2]
	end
	--for k,v in pairs(resp) do print(k,v) end
	return table.concat(ft),resp[3]	-- Return the File and the headers	
end

-- host object functions

local function sendSOAP(host,serviceType,serviceURL,actionName,sendArgs)
	-- Create argStr containing all the arguments and values
	local argStr = ""
	for k,v in pairs(sendArgs) do
		--print(k,v)
		argStr = "<"..k..">"..v[1]..[[</]]..k..[[>]]
	end
	-- Create the SOAP request
	local soapBody = 	[[<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body>
	<m:]]..actionName..[[ xmlns:m="]]..serviceType..[[">
		]]..argStr.."\n\t"..[[</m:]]..actionName..[[>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>]]

	--print("SENDING SOAP REQUEST:")
	--print(soapBody)

	-- Attach the headers to send with the request
	local hdrs = {
						["Host"] = host,
						["Content-Length"] = #soapBody,
						["Content-Type"] = "text/xml",
						["SOAPAction"] = [["]]..serviceType.."#"..actionName..[["]]
					}
	
	-- The response table
	local ft = {}
	-- Now get the File
	local resp = {http.request{
							url = serviceURL,
							sink = ltn12.sink.table(ft),
							headers = hdrs,
							method = "POST",
							source = ltn12.source.string(soapBody)
						}
				}
	if not resp[1] then 
		return nil,resp[2]
	end
	return table.concat(ft)-- Return the body of the response
end

-- sendArgs is a table with key as argument name and value as the argument value string (unencoded)
hostMeta.send = function(hostObj, devName, serviceName, actionName, sendArgs)
	if not(hostObj.devices and hostObj.devices[devName] and hostObj.devices[devName].services and hostObj.devices[devName].services[serviceName]) then
		return nil,"Host "..hostObj.host.." does not have data for device: "..devName..", service: "..serviceName
	end
	
	-- Get the service URL
	local serviceURL = 	hostObj.devices[devName].services[serviceName].controlURL
	if not serviceURL then
		return nil, "No controlURL found for the service"
	end
	if serviceURL:sub(1,1) ~= [[/]] then
		serviceURL = hostObj.protocol..[[://]]..hostObj.host..[[/]]..serviceURL
	else
		serviceURL = hostObj.protocol..[[://]]..hostObj.host..serviceURL
	end
	
	-- Get the action information
	if not(hostObj.devices[devName].services[serviceName].actions and hostObj.devices[devName].services[serviceName].actions[actionName] and hostObj.devices[devName].services[serviceName].actions[actionName].arguments) then
		return nil, "Host "..hostObj.host.." does not have data for device: "..devName..", service: "..serviceName..", action: "..actionName
	end
	
	-- Convert all sendArgs to string
	if sendArgs then
		for k,v in pairs(sendArgs) do
			if type(k) ~= "string" or type(v) ~= "string" then
				local key,value
				key = tostring(k)
				value = tostring(v)
				sendArgs[k] = nil
				sendArgs[key] = value
			end
		end
	end
	local argS = hostObj.devices[devName].services[serviceName].actions[actionName].arguments
	local serviceType = hostObj.devices[devName].services[serviceName].serviceType
	local returnTags = {}
	for argName, argVals in pairs(argS) do
		local actionStateVar = argVals.relatedStateVariable
		if actionStateVar then
			actionStateVar = hostObj.devices[devName].services[serviceName].serviceStateVariables[actionStateVar]
			if actionStateVar then
				if argVals.direction and argVals.direction:lower() == "in" then
					if not sendArgs then
						sendArgs = {}
					end
					if sendArgs[argName] then
						-- check if there are allowedValues then the provided value should be one of them
						if actionStateVar.allowedValues then
							local found
							for i=1,#actionStateVar.allowedValues do
								if actionStateVar.allowedValues[i] == sendArgs[argName] then
									found = true
									break
								end
							end
							if not found then
								return nil, "Provided value: "..sendArgs[argName].." for argument: "..argName.." does not match the allowed values for the argument."
							end
						end
					elseif actionStateVar.defaultValue then
						sendArgs[argName] = {actionStateVar.defaultValue}
					else
						return nil, "Value for required argument "..argName.." not provided"
					end
					sendArgs[argName] = sendArgs[argName]:match("^%s*(.-)%s*$")
					if actionStateVar.dataType == "bin.base64" then
						sendArgs[argName] = mime.b64(sendArgs[argName])
					end
					sendArgs[argName] = {sendArgs[argName],actionStateVar.dataType}
				else
					-- if it is not an argument to send then it is a receiving argument
					returnTags[#returnTags + 1] = {argName,actionStateVar.dataType}
				end		-- if argVals.direction and argVals.direction:lower() == "in" then ends
			end		-- if actionStateVar then ends
		end		-- if actionStateVar then ends
	end		-- for argName, argVals in pairs(argS) do ends
	
	-- Send the SOAP request now
	local err,msg =  sendSOAP(hostObj.host,serviceType,serviceURL,actionName,sendArgs)
	if not err then
		return nil, msg
	else
		return err, returnTags
	end
end

hostMeta.getInfo = function(hostObj)
	if hostObj.enumerated then
		return true
	end
	local xml,hdrs = httpGetFile(hostObj.xmlFile)
	if not xml then
		return xml,hdrs
	end
	
	-- Now parse the XML using LXML module
	
	-- Use the domHandler
	local handler = lxml.handlers.domHandler()
	local parser = lxml.Parser(handler)
	parser:parse(xml)
	
	-- Some XML info extraction functions
	local function parseServiceStateVars(xmlFile, xmlDom,getElemFunc,serviceEntry)
		local varValTags = {"sendEvents","dataType","defaultValue"}
		local srvcStateTblTag = "serviceStateTable"
		local stateVarTag = "stateVariable"
		local nameTag = "name"
		local allowedValListTag = "allowedValueList"
		local allowedValTag = "allowedValue"
		local allowedValRngeTag = "allowedValueRange"
		local minTag = "minimum"
		local maxTag = "maximum"
		
		-- Create the service state variables table here
		serviceEntry.serviceStateVariables = {}
		local stateVars = serviceEntry.serviceStateVariables
		
		-- Now get the state variables
		local stateVarsList = getElemFunc(xmlDom._children,srvcStateTblTag)
		if not stateVarsList[1] then
			return nil,"Could not retrieve the service state table from the service info XML file: "..xmlFile
		end
		stateVarsList = getElemFunc(stateVarsList[1]._children,stateVarTag)	-- Although it should just return stateVarsList[1]._children but this way its safer
		if not stateVarsList[1] then
			return nil,"No state variables found"
		end
		
		for i = 1,#stateVarsList do
			local node = getElemFunc(stateVarsList[i]._children,nameTag)
			local name
			if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
				name = node[1]._children[1]._text
			end
			if not name then
				name = "StateVariable_"..tostring(i)
			end
			stateVars[name] = {}
			for j = 1,#varValTags do
				node = getElemFunc(stateVarsList[i]._children,varValTags[j])
				if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
					stateVars[name][varValTags[j]] = node[1]._children[1]._text
				else
					if stateVarsList[i]._attr and stateVarsList[i]._attr[varValTags[j]] then
						stateVars[name][varValTags[j]] = stateVarsList[i]._attr[varValTags[j]]
					else
						stateVars[name][varValTags[j]] = "N/A"
					end
				end						
			end		-- for j = 1,#varValTags do ends
			
			-- Now get the allowed values for the state variable
			local allowedValsList = getElemFunc(stateVarsList[i]._children,allowedValListTag)
			if allowedValsList[1] then
				allowedValsList = getElemFunc(allowedValsList[1]._children,allowedValTag)	-- Although it should just return allowedValsList[1]._children but this way its safer
			end
			if allowedValsList[1] then
				stateVars[name].allowedValues = {}
				local av = stateVars[name].allowedValues
				for j = 1,#allowedValsList do
					if allowedValsList[j]._children[1] and allowedValsList[j]._children[1]._type == "TEXT" then
						av[#av+1] = allowedValsList[j]._children[1]._text
					end
				end		-- for j = 1,#allowedValsList do ends
			end
			
			-- Now get the allowed value range for this variable
			local allowedValRange = getElemFunc(stateVarsList[i]._children,allowedValRngeTag)
			if allowedValRange[1] then
				stateVars[name].allowedValueRange = {}
				local av = stateVars[name].allowedValueRange
				-- minimum value
				node = getElemFunc(allowedValRange[1]._children,minTag)
				if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
					av[1] = node[1]._children[1]._text
				end
				-- maximum value
				node = getElemFunc(allowedValRange[1]._children,maxTag)
				if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
					av[2] = node[1]._children[1]._text
				end
			end
			
		end		-- for i = 1,#stateVarsList do ends
		
		return true
	end
	
	local function parseServiceInfo(xmlDom,serviceEntry)
		local actionArgTags = {"direction","relatedStateVariable"}
		local actionListTag = "actionList"
		local actionTag = 'action'
		local nameTag = 'name'
		local argumentListTag = 'argumentList'
		local argumentTag = 'argument'
		
		-- Get the XML file for the service description\
		local xmlFile
		if not serviceEntry.SCPDURL then
			return nil,"SCPD URL not present so no service info extracted."
		end
		if serviceEntry.SCPDURL:match("^"..hostObj.protocol..[[%:%/%/]]) then
			xmlFile = serviceEntry.SCPDURL
		else
			xmlFile = hostObj.protocol..[[://]]..hostObj.host
			if serviceEntry.SCPDURL:sub(1,1) ~= [[/]] then
				xmlFile = xmlFile..[[/]]..serviceEntry.SCPDURL
			else
				xmlFile = xmlFile..serviceEntry.SCPDURL
			end
		end
		xmlFile = xmlFile:gsub("^%s*",""):gsub("%s*$","")
		
		-- Now create the table for the service actions data structure
		serviceEntry.actions = {}
		local xml,hdrs = httpGetFile(xmlFile)	-- Get the service XML file
		--print("XML file is: ", xml,hdrs)
		if not xml then
			return nil,"Could not retrieve the service info XML file: "..xmlFile
		end

		-- Now parse the XML using LXML module
		
		-- Use the domHandler
		local domH = lxml.handlers.domHandler()
		local prsr = lxml.Parser(domH)
		prsr:parse(xml)
		
		-- Now get the actions
		local actionList = domH.getElementsByTagName(domH.root._children,actionListTag)
		--print("actionList: ", actionList,#actionList)
		if not actionList[1] then
			return nil,"Could not retrieve the action list from the service info XML file: "..xmlFile
		end
		actionList = domH.getElementsByTagName(actionList[1]._children,actionTag)	-- Although it should just return actionList[1]._children but this way its safer
		--print("actionList: ", actionList,#actionList)
		if not actionList[1] then
			return nil,"No Actions found"
		end
		
		-- Now parse all the actions
		for i = 1,#actionList do
			--print("action ",i)
			local node = domH.getElementsByTagName(actionList[i]._children,nameTag)
			local name
			--print("node ",node,#node)
			if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
				name = node[1]._children[1]._text
				--print(node[1]._children[1]._text)
			end
			if not name then
				name = "Action_"..tostring(i)
			end
			--print("name",name)
			serviceEntry.actions[name] = {arguments = {}}
			local argS = serviceEntry.actions[name].arguments
			-- Parse all the action arguments
			local argList = domH.getElementsByTagName(actionList[i]._children,argumentListTag)
			if argList[1] then
				argList = domH.getElementsByTagName(argList[1]._children,argumentTag)	-- Although it should just return argList[1]._children but this way its safer
				if argList[1] then
					for j = 1,#argList do
						name = nil
						node = domH.getElementsByTagName(argList[j]._children,nameTag)
						if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
							name = node[1]._children[1]._text
						end
						if name then
							argS[name] = {}
							-- Now get the remaining tags
							for k = 1,#actionArgTags do
								node = domH.getElementsByTagName(argList[j]._children,actionArgTags[k])
								if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
									argS[name][actionArgTags[k]] = node[1]._children[1]._text
								end						
							end		-- for j = 1,#serviceTags do ends
						end		-- if name then ends			
					end		-- for j = 1,#argList do ends
				end		-- if argList[1] then ends
			end		-- if argList[1] then ends
		end		-- for i = 1,#actionList do ends
		
		-- Now parse all the service state variables
		local stat,err = parseServiceStateVars(xmlFile, domH.root,domH.getElementsByTagName,serviceEntry)
		if not stat then
			return nil,err
		end
		
		return true
	end
	
	local function parseServiceList(xmlDom,getElemFunc,deviceEntry)
		local stat,err
		local serviceListTag = "serviceList"
		local serviceTag = "service"
		local serviceTypeTag = "serviceType"
		local serviceTags = {"serviceId","controlURL","eventSubURL","SCPDURL"}
		
		deviceEntry.services = {}
		-- Extract the list of services offered by the device from the device xmlDom
		local servList = getElemFunc(xmlDom._children,serviceListTag)
		if servList[1] and servList[1]._children then
			local servType, servName, node
			servList = getElemFunc(servList[1]._children,serviceTag)
			for i = 1,#servList do
				--print("service ",i)
				node = getElemFunc(servList[i]._children,serviceTypeTag)
				if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
					servType = node[1]._children[1]._text
					servName = servType:match(".-service%:(.-)%:.+")
				end
				if servType or servName then
					-- Add the service to the hostObj
					deviceEntry.services[servName] = {serviceType = servType}
					for j = 1,#serviceTags do
						--print("Looking for service tag: ",serviceTags[j])
						node = getElemFunc(servList[i]._children,serviceTags[j])
						--print("Node: ",node, #node)
						if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
							deviceEntry.services[servName][serviceTags[j]] = node[1]._children[1]._text
							--print("Node text = ",node[1]._children[1]._text)
						end						
					end		-- for j = 1,#serviceTags do ends
				end		-- if servType or servName then ends
				-- Now get the service information
				stat,err = parseServiceInfo(servList[i],deviceEntry.services[servName])
				if not stat then
					return nil,err
				end
			end		-- for i = 1,#servList do ends
		else
			return nil,"No serviceList tag found!"
		end		-- if servList[1] and servList[1]._children then ends
		return true
	end

	local function parseXMLDeviceInfo(xmlDom)
		local stat,err
		local devTag = "device"
		local devTypeTag = "deviceType"
		local deviceTags = {"friendlyName","modelDescription","modelName","modelNumber","modelURL","presentationURL","UDN","UPC","manufacturer","manufacturerURL"}
		
		-- Find all device entries in the xmlRoot
		local devices = xmlDom.getElementsByTagName(xmlDom.root._children,devTag)
		--print("Devices found = ",#devices)
		for i = 1,#devices do
			local deviceType, deviceName, node
			--print("device ",i)
			node = xmlDom.getElementsByTagName(devices[i]._children,devTypeTag)
			if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
				deviceType = node[1]._children[1]._text
				deviceName = deviceType:match(".-device%:(.-)%:.+")
				--print("deviceType=",deviceType,"deviceName=",deviceName)
			end
			if deviceType or deviceName then
				-- Add the information to the hostObj
				if not hostObj.devices then
					hostObj.devices = {}
				end
				hostObj.devices[deviceName] = {deviceType = deviceType}
				for j = 1,#deviceTags do
					node = xmlDom.getElementsByTagName(devices[i]._children,deviceTags[j])
					if node[1] and node[1]._children[1] and node[1]._children[1]._type == "TEXT" then
						hostObj.devices[deviceName][deviceTags[j]] = node[1]._children[1]._text
					end
				end		-- for j = 1,#deviceTags do ends here
			end		-- if deviceType or deviceName then ends
			-- Parse the service list for the device
			stat,err = parseServiceList(devices[i],xmlDom.getElementsByTagName,hostObj.devices[deviceName])
			if not stat then
				return nil, err
			end
		end		-- for i = 1,#devices do ends here
		return true
	end		-- local function parseXMLDeviceInfo(xmlDom)
	
	hostObj.serverType = hdrs.server
	local stat,err = parseXMLDeviceInfo(handler)
	if not stat then
		return nil, err
	end
	
	hostObj.enumerated = true
	return true
end

-- Upnp object functions

-- Parse the SSDP (Simple Service Discovery Protocol) strings and return table of hosts
local function parseSSDP(str)
	-- Local functions for parsing
	-- To extract information for a specified tag in the header
	local function parseHeader(header,tag)
		local st,stp = header:upper():find("\n%s*"..tag:upper().."%s*:%s*")
		local info
		st,stp,info = header:find("(.-)\n",stp+1)
		return info
	end

	-- Parse a URL and extract the host address and page name
	local function parseURL(url)
		local host,page
		if url then
			host,page = url:match([[.-://(.+)/(.-)$]])
			if not host then
				page = url
			end
			return host,page
		end
	end
	
	if not str then
		return nil
	end
	--print("parseSSDP: "..str)
	local hosts = {}
	local headers = {
		NOTIFY = "notification",	-- Notification header
		["HTTP/1.1 200 OK"] = "reply"	-- reply header
	}
	local msgType
	for k,v in pairs(headers) do
		msgType = v
		if str:upper():sub(1,#k) == k:upper() then
			break
		else
			msgType = nil
		end
	end
	
	--print(msgType)
	
	if msgType then
		hosts[#hosts + 1] = {}
		hosts[#hosts].upnpType = parseHeader(str,"SERVER")
		--print("upnpType: "..hosts[#hosts].upnpType)
		hosts[#hosts].xmlFile = parseHeader(str,"LOCATION"):gsub("^%s*",""):gsub("%s*$","")
		--print("xmlFile: "..hosts[#hosts].xmlFile)
		hosts[#hosts].host,hosts[#hosts].page = parseURL(hosts[#hosts].xmlFile)
		if not hosts[#hosts].page or not hosts[#hosts].xmlFile then
			return nil,"XML service description not found in header "..str
		end
		hosts[#hosts].protocol = hosts[#hosts].xmlFile:match([[(.-)://]])
		-- Check if this is duplicate
		for i = 1,#hosts-1 do
			if hosts[i].protocol == hosts[#hosts].protocol and hosts[i].upnpType == hosts[#hosts].upnpType and hosts[i].xmlFile == hosts[#hosts].xmlFile then
				-- This is a duplicate
				hosts[#hosts] = nil
				break
			end
		end
		return hosts
	end
	
end

-- Actively search for UPNP hosts using M-SEARCH queries
upnpMeta.msearch = function(o,timeout, searchType,searchName)
	if getmetatable(o) ~= upnpMeta then
		return nil, "Need upnp Object as the 1st argument"
	end
	if not timeout or type(timeout) ~= "number" then
		return nil, "Provide a timeout number in seconds"
	end
	if timeout < 0 then
		return nil, "Provide a positive timeout number in seconds"
	end
	local ip, port = o.ip, o.port
	local st = "upnp:rootdevice"
	
	if searchType and searchName then
		st = "urn:schemas-upnp-org:"..searchType..":"..searchName..":".._UPNPVERSION:match("(.-)%..+")
	end
	
	request = [[M-SEARCH * HTTP/1.1]].."\r\nHOST:"..o.ip..":"..o.port.."\r\nST:"..st.."\r\n"
	
	local recTimeout = 3
	for k,v in pairs(o.msearchHeaders) do
		request = request..tostring(k)..":"..tostring(v).."\r\n"
		if k:upper() == "MX" then
			recTimeout = tonumber(v)
		end
	end
	request = request.."\r\n"

	local srvr = o.clnt
	-- Create a new socket to get responses

	--print("Sending Request:")
	--print(request)
	
	srvr:sendto(request,ip,port)
	
	local startTime = ostime()
	local lastTime = startTime
	if timeout < 3 then
		recTimeout = timeout
	end
	while ostime() < startTime + timeout do
		--print(receive(srvr,1024,timeout))
		if ostime() > lastTime + recTimeout then
			srvr:sendto(request,ip,port)
			lastTime = ostime()
		end
		local hosts = parseSSDP(receive(srvr,1024,recTimeout))
		if hosts then
			-- Check if this is duplicate
			for j = 1,#hosts do
				local found
				for i = 1,#o.hosts do
					if o.hosts[i].protocol == hosts[j].protocol and o.hosts[i].upnpType == hosts[j].upnpType and o.hosts[i].xmlFile == hosts[j].xmlFile then
						-- This is a duplicate
						found = true
						break
					end
				end		-- for i ends here
				if not found then
					o.hosts[#o.hosts + 1] = hosts[j]
					setmetatable(o.hosts[#o.hosts],hostMeta)
				end
			end		-- for j ends here	
		end		-- if hosts then ends
	end		-- while ends here
end

-- Look for UPNP notify packets and add all detected hosts
upnpMeta.pcap = function(o, timeout)
	if getmetatable(o) ~= upnpMeta then
		return nil, "Need upnp Object as the 1st argument"
	end
	local sckt = o.srvr
	if not sckt then
		return nil, "Socket object needed"
	end
	if not timeout or type(timeout) ~= "number" then
		return nil, "Provide a timeout number in seconds"
	end
	if timeout < 0 then
		return nil, "Provide a positive timeout number in seconds"
	end
	--print("timeout",timeout)
	local startTime = ostime()
	--print("start time",startTime)
	while ostime() < startTime + timeout do
		--print("ostime",ostime())
		--print(receive(sckt,1024,timeout))
		local hosts = parseSSDP(receive(sckt,1024,timeout))
		--print("hosts returned by parseSSDP is: "..tostring(hosts))
		if hosts then
			-- Check if this is duplicate
			for j = 1,#hosts do
				--[[print("Now into hosts["..tostring(j).."]")
				for k,v in pairs(hosts[j]) do
					print(k,v)
				end]]
				local found
				for i = 1,#o.hosts do
					if o.hosts[i].protocol == hosts[j].protocol and o.hosts[i].upnpType == hosts[j].upnpType and o.hosts[i].xmlFile == hosts[j].xmlFile then
						-- This is a duplicate because the protocols, upnpType and the xmlFile all match
						found = true
						break
					end
				end		-- for i ends here
				if not found then
					o.hosts[#o.hosts + 1] = hosts[j]
					setmetatable(o.hosts[#o.hosts],hostMeta)
				end
			end		-- for j ends here
		end		-- if hosts ends here
	end		-- while ends here
end


-- To create and return a new uPnP object
new = function(ip,port,iface)
	local err,msg
	local obj = {
			hosts = {},	-- Store list of hosts found
			-- These are object instance specific headers which can be manipulated to send with the msearch command
			msearchHeaders = {
				MAN = '"ssdp:discover"',
				MX = "3"				
			}
		}
	setmetatable(obj,upnpMeta)
	
	if iface then
		obj.iface = iface
	end
	if ip then
		obj.ip = ip
	end
	if port then
		obj.port = port
	end
	
	-- Set up client socket (used by msearch)
	obj.clnt = socket.udp()
	if not obj.clnt then
		return nil, "Failed to initialize upnp sockets"
	end
	local done,msg = pcall(obj.clnt.setoption,obj.clnt,"reuseaddr",true)
	if not done then
		return nil, "Failed to initialize upnp sockets: "..msg
	end
	-- For BSD systems
	pcall(obj.clnt.setoption,obj.clnt,"reuseport",true)
	done,msg = obj.clnt:setsockname("*",0)	-- Setting this to an unused port on windows otherwise it drops responses
	--done,msg = obj.clnt:setsockname("*",60000)
	if not done then
		return nil, "Failed to initialize upnp sockets: "..msg
	end

	-- Set up server socket (used by pcap)
	obj.srvr = socket.udp()
	if not obj.srvr then
		return nil, "Failed to initialize upnp sockets"
	end
	err,msg = pcall(obj.srvr.setoption,obj.srvr,"reuseaddr",true)
	if not err then
		return nil, "Failed to initialize upnp sockets: "..msg
	end
	-- For BSD systems
	pcall(obj.srvr.setoption,obj.srvr,"reuseport",true)
	-- Join the multicast group here
	err,msg = obj.srvr:setsockname("*",obj.port)
	if not err then
		return nil, "Failed to initialize upnp sockets: "..msg
	end
	err,msg = pcall(obj.srvr.setoption,obj.srvr,"ip-add-membership" ,{ multiaddr = obj.ip, interface = obj.iface})
	if not err then
		return nil, "Failed to initialize upnp sockets: "..msg
	end

	return obj
end
