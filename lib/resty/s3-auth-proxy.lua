local ngx_log      = ngx.log
local ERR          = ngx.ERR
local INFO         = ngx.INFO
local re_match     = ngx.re.match
local re_gmatch    = ngx.re.gmatch
local str_lower    = string.lower
local tbl_insert   = table.insert
local tbl_concat   = table.concat
local str          = require('resty.string')
local str_to_hex   = str.to_hex
local resty_hmac   = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local os           = require('os')
local os_date      = os.date

-- Constants
local CONST_AWS_HMAC_TYPE         = 'AWS4-HMAC-SHA256'
local CONST_AWS_PAYLOAD_STREAMING = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
local CONST_AWS_PAYLOAD_UNSIGNED  = 'UNSIGNED-PAYLOAD'

-- Internal functions  for XML handling
local xml_error_format = [[<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>%s</Code>
  <Message>%s</Message>
  <Resource>%s</Resource>
  <RequestId>%s</RequestId>
</Error>
]]


local xml_error = function(err_code, err_msg, status, resource, id)
    ngx_log(ERR, err_code)
    ngx.status = status
    ngx.header['Content-Type'] = 'application/xml'
    ngx.say(xml_error_format:format(err_code, err_msg, (resource or ''), (id or '')))
    ngx.exit(ngx.HTTP_OK)
end


local xml_invalid_access_key_id = function(msg)
    return xml_error('InvalidAccessKeyId', (msg or 'The access key Id you provided does not exist in our records.'), 403)
end


local xml_invalid_request = function(msg)
    return xml_error('InvalidRequest', (msg or 'Invalid Request'), 400)
end


local sha256_string = function(input)
    local hash = resty_sha256:new()
    hash:update(input or '')
    return str_to_hex(hash:final())
end


local function iso8601_full(t)
    return os_date('!%Y%m%dT%H%M%SZ', tonumber(t))
end


local function iso8601_short(t)
    return os_date('!%Y%m%d', tonumber(t))
end


-- Auth proxy Public Interface
local S3AuthProxy = {}


function S3AuthProxy:new(config)
    if not config['keys'] then
        ngx_log(ERR, 'S3AuthProxy requires "keys" config option to be a table!')
        return None
    end

    local o    = { config = config, keypairs = {}, keycount = 0 }

    local self = setmetatable(o, {__index = S3AuthProxy})
    self:load_keys(config['keys'])
    return self
end


function S3AuthProxy:load_keys(keys)
    for fqdn, secrets in pairs(keys) do
        self['keypairs'][secrets['aws_access_key_id']] = { fqdn = fqdn, aws_secret_access_key = secrets['aws_secret_access_key'] }
        self['keycount'] = self['keycount'] + 1
    end

    ngx_log(INFO, 'Loaded ', self['keycount'], ' Access Keys...')
end


function S3AuthProxy:authenticate()
    local keypairs = self['keypairs']
    local headers = ngx.req.get_headers()

    ngx_log(INFO, cjson.encode(headers))

    local auth_header = headers['authorization']
    local amz_content = headers['x-amz-content-sha256']
    local amz_date    = headers['x-amz-date']

    -- Block requests without an auth header
    if not auth_header then
	return xml_invalid_access_key_id()
    end

    -- Parse auth header
    local auth_parts, err = re_match(auth_header, "(?<auth_type>[^\\s]+) (?<remaining>.+)", "jo")

    if not auth_parts then
	ngx_log(ERR, 'auth_parts regex failed: ', err)
	return xml_invalid_access_key_id()
    end

    -- Validate auth_type
    local auth_type, auth_remaining = auth_parts[0], auth_parts[1]

    if auth_parts['auth_type'] ~= CONST_AWS_HMAC_TYPE then
	return xml_invalid_request('Please use ' .. CONST_AWS_HMAC_TYPE)
    end

    -- Parse remaining auth header variables
    local auth_remaining_items, err = re_gmatch(auth_parts['remaining'], "(?<name>[^=]+)=(?<value>[^,]+)*,?", "jo")

    if not auth_remaining_items then
	ngx_log(ERR, 'auth_remaining_items regex failed: ', err)
	return xml_invalid_request('Authorization header invalid.')
    end

    local auth_args  = {}
    while true do
        local arg, err = auth_remaining_items()
        if not arg then
            break
        end
        local arg_name      = str_lower(arg['name']) -- Normalize all args
        local arg_value     = arg['value']
        auth_args[arg_name] = arg_value
    end

    -- Parse credential
    local cred, err = re_match(auth_args['credential'], "(?<access_key_id>[A-Z0-9]+)\\/(?<scope>(?<date>[0-9]{8})\\/(?<region>[a-zA-Z0-9\\-]+)\\/(?<service>[a-zA-Z0-9\\-]+)\\/aws4_request)", "jo")

    if not cred then
	ngx_log(ERR, 'cred regex failed: ', err)
	return xml_invalid_access_key_id()
    end

    local access_details = keypairs[cred['access_key_id']]

    if not access_details then
	ngx_log(ERR, 'access_key_id ', cred['access_key_id'], ' not found in configuration.')
	return xml_invalid_access_key_id()
    end

    -- Parse signed headers
    local signed_header_items, err = re_gmatch(auth_args['signedheaders'], "(?<header>[a-z0-9\\-]+);?", "jo")

    if not signed_header_items then
	ngx_log(ERR, 'signed_header_items regex failed: ', err)
	return xml_invalid_access_key_id()
    end

    local signed_header_pairs  = {}
    while true do
        local arg, err = signed_header_items()
        if not arg then
            break
        end
        local h = str_lower(arg['header'])
        tbl_insert(signed_header_pairs, {h, headers[h]})
    end

    local payload

    -- Signed Chunked upload
    if amz_content == CONST_AWS_PAYLOAD_STREAMING then
	ngx_log(ERR, CONST_AWS_PAYLOAD_STREAMING, ' is not supported.')
	return xml_invalid_request(CONST_AWS_PAYLOAD_STREAMING .. ' is not supported.')

    -- Unsigned upload
    elseif amz_content == CONST_AWS_PAYLOAD_UNSIGNED then
        payload = ''

    -- Signed single upload
    else
        ngx.req.read_body()
        payload = ngx.req.get_body_data()
    end

    local canonical_request = self:get_canonical_request(signed_header_pairs, payload)

    local string_to_sign = tbl_concat({
        CONST_AWS_HMAC_TYPE,
        iso8601_full(amz_date),
        cred['scope'],
        sha256_string(canonical_request)
    }, "\n")

    local h = resty_hmac:new()
    local date_key    = h:digest('sha256', 'AWS4' .. access_details['aws_secret_access_key'], cred['date'], true)
    local region_key  = h:digest('sha256', date_key, cred['region'], true)
    local service_key = h:digest('sha256', region_key, cred['service'], true)
    local signing_key = h:digest('sha256', service_key, 'aws4_request', true)

    local signature = h:digest('sha256', signing_key, string_to_sign, false)

    -- Check if signature matches
    if auth_args['signature'] ~= signature then
        ngx_log(ERR, 'Request signature mismatch: ', signature, ' does not match ', auth_args['signature'])
    else
        ngx_log(INFO, 'Signature ', signature, ' verified')
    end
end


function S3AuthProxy:get_canonical_request(headers, payload)
    -- Generate signed and canonical header tables from input
    local signed_headers    = {}
    local canonical_headers = {}
    for _, header in ipairs(headers) do
        tbl_insert(signed_headers, header[1])
        tbl_insert(canonical_headers, header[1] .. ':' .. header[2])
    end

    return tbl_concat({
        ngx.var.request_method,
        ngx.var.request_uri,
        ngx.var.args or '',
        tbl_concat(canonical_headers, "\n") or '',
        tbl_concat(signed_headers, ";") or '',
        sha256_string(payload)
    },"\n")
end

return S3AuthProxy
