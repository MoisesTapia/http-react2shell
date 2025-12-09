local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local string = require "string"

description = [[
Detects React2Shell (CVE-2025-55182 / CVE-2025-66478) in 
React Server Components / Next.js applications using a safe side-channel technique.

The script sends a POST multipart/form-data request containing a specially crafted 
React Flight payload that:
  - On vulnerable servers triggers a 500 response containing the pattern E{"digest"...}
  - On patched or non-vulnerable setups does NOT produce this pattern.

The script does NOT attempt any code execution nor exploit the vulnerability; 
it only triggers the documented error path used for safe detection.
]]

---
-- @usage
--  nmap -p80,443 --script http-react2shell \
--    --script-args 'react2shell.path=/,react2shell.timeout=10000' <host>
--
-- @args react2shell.path     Path to test (default "/").
-- @args react2shell.timeout  HTTP timeout in ms (default 10000).
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- | http-react2shell:
-- |   VULNERABLE: possible React2Shell (CVE-2025-55182 / CVE-2025-66478)
-- |     Path: /
-- |     Evidence: HTTP 500 + E{"digest" found in response
-- |_    Notes: result based on safe side-channel; verify manually and patch immediately.

author = "ChatGPT (adapted for React2Shell detection)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = shortport.http

-- Builds the "safe" multipart payload similar to the side-channel described
-- by researchers: two fields:
--   field "1" = {}              (empty object)
--   field "0" = ["$1:aa:aa"]    (attempt to access a missing property)
--
-- On vulnerable servers this causes React to follow invalid reference chains,
-- ending in a 500 error with a characteristic digest.
local function build_safe_multipart_payload()
  local boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

  local body_parts = {
    "--" .. boundary .. "\r\n",
    'Content-Disposition: form-data; name="1"' .. "\r\n\r\n",
    "{}\r\n",
    "--" .. boundary .. "\r\n",
    'Content-Disposition: form-data; name="0"' .. "\r\n\r\n",
    '["$1:aa:aa"]' .. "\r\n",
    "--" .. boundary .. "--\r\n"
  }

  local body = table.concat(body_parts)
  local content_type = "multipart/form-data; boundary=" .. boundary
  return body, content_type
end

local function is_potentially_vulnerable(resp)
  if not resp then
    return false, "no-response"
  end

  -- High-fidelity side-channel check:
  --  - status must be 500
  --  - body must contain 'E{"digest"'
  --
  -- Some platforms (Vercel, Netlify, etc.) inject mitigations
  -- that may create similar patterns; to reduce false positives,
  -- we inspect common platform headers.
  if resp.status ~= 500 or not resp.body or not resp.body:find('E{"digest"') then
    return false, "no-crash-pattern"
  end

  local headers = resp.header or {}

  local server = headers["server"] or headers["Server"] or ""
  local netlify_vary = headers["Netlify-Vary"] or headers["netlify-vary"]

  if server:lower():find("vercel") or netlify_vary then
    -- Likely protected by platform-level mitigation; do not flag as vulnerable
    return false, "mitigated-platform"
  end

  return true, "crash-pattern"
end

action = function(host, port)
  local path = stdnse.get_script_args("react2shell.path") or "/"
  local timeout = tonumber(stdnse.get_script_args("react2shell.timeout")) or 10000

  local out = {}
  table.insert(out, ("Path: %s"):format(path))

  local body, content_type = build_safe_multipart_payload()

  local headers = {
    ["Content-Type"] = content_type,
    ["User-Agent"] = "Nmap-React2Shell-check",
    -- Typical Server Actions / RSC headers used to route the request
    ["Next-Action"] = "x",
    ["X-Requested-With"] = "XMLHttpRequest"
  }

  local opts = {
    header = headers,
    timeout = timeout
  }

  local resp = http.post(host, port, path, opts, body)

  if not resp then
    table.insert(out, "ERROR: no HTTP response received (timeout or connection failed)")
    return stdnse.format_output(true, out)
  end

  local vulnerable, reason = is_potentially_vulnerable(resp)

  if vulnerable then
    table.insert(out, "VULNERABLE: possible React2Shell (CVE-2025-55182 / CVE-2025-66478)")
    table.insert(out, ("  Evidence: HTTP %d + E{\"digest\" found in response"):format(resp.status))
    table.insert(out, "  Notes: high-fidelity side-channel; verify manually and patch immediately.")
  else
    if reason == "mitigated-platform" then
      table.insert(out, "INCONCLUSIVE: error pattern seen but host appears protected by platform-level mitigations (e.g., Vercel/Netlify).")
      table.insert(out, "  Recommendation: check deployed React/Next.js versions and apply patches, even if runtime mitigation exists.")
    elseif reason == "no-crash-pattern" then
      table.insert(out, "No characteristic crash pattern observed.")
      table.insert(out, "  This suggests the tested endpoint is not vulnerable or is patched,")
      table.insert(out, "  but this is not a guarantee (other RSC/Server Actions paths may exist).")
    else
      table.insert(out, "INCONCLUSIVE: could not determine vulnerability using this method.")
    end
  end

  return stdnse.format_output(true, out)
end
