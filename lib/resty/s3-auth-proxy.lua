local ngx_log      = ngx.log
require "resty.core"
local ERR          = ngx.ERR
local INFO         = ngx.INFO
local DEBUG        = ngx.DEBUG
local ngx_re       = require "ngx.re"
local re_split     = ngx_re.split
local re_match     = ngx.re.match
local re_gmatch    = ngx.re.gmatch
local str_lower    = string.lower
local tbl_insert   = table.insert
local tbl_concat   = table.concat
local str          = require('resty.string')
local str_to_hex   = str.to_hex
local str_sub      = string.sub
local str_len      = string.len
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

local xml_signature_mismatch = function(msg)
    return xml_error('SignatureDoesNotMatch', (msg or 'The request signature we calculated does not match the signature you provided.'), 403)
end

local xml_invalid_bucket = function(msg)
    return xml_error('InvalidBucketName', (msg or 'The specified bucket is not valid.'), 400)
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
    if not config['client_keys'] then
        ngx_log(ERR, 'S3AuthProxy requires "client_keys" config option to be a table!')
        return nil
    end

    local o    = { config = config, keypairs = {}, keycount = 0, secret_access_key = config['secret_access_key'] or '', access_key_id = config['access_key_id'] or '' }

    local self = setmetatable(o, {__index = S3AuthProxy})
    self:load_keys(config['client_keys'])
    return self
end


function S3AuthProxy:load_keys(keys)
    for fqdn, secrets in pairs(keys) do

        -- Split FQDN into parts
        local fqdn_parts, err = re_split(fqdn, '.', "jo")

        if not fqdn_parts then
            ngx_log(ERR, 'fqdn_parts regex failed: ', err)
            return nil
        end

        -- Build valid bucket names from fqdn parts (e.g. puppet-test01, puppet-test01.dc2, puppet-test01.dc2.domain, puppet-test01.dc2.domain.co, etc - all valid)
        local valid_bucket_names  = {}
        local cur_bucket_name     = nil

        for _, label in ipairs(fqdn_parts) do
            if cur_bucket_name then
                cur_bucket_name = cur_bucket_name .. '.' .. label
            else
                cur_bucket_name = label
            end
            tbl_insert(valid_bucket_names, '/' .. cur_bucket_name .. '/')
        end

        self['keypairs'][secrets['aws_access_key_id']] = { fqdn = fqdn, aws_secret_access_key = secrets['aws_secret_access_key'], buckets = valid_bucket_names }
        self['keycount'] = self['keycount'] + 1
    end

    ngx_log(INFO, 'Loaded ', self['keycount'], ' Access Keys...')
end


function S3AuthProxy:authenticate()
    local keypairs = self['keypairs']
    local headers = ngx.req.get_headers()

    local auth_header = headers['authorization']
    local amz_content = headers['x-amz-content-sha256']
    local amz_date    = headers['x-amz-date']
    local vars        = ngx.var

    -- Block requests without an auth header
    if not auth_header then
        return xml_invalid_access_key_id()
    end

    -- Parse auth header
    local auth_parts, err = re_split(auth_header, ' ', 'jo', nil, 2)

    if not auth_parts then
        ngx_log(ERR, 'auth_parts split failed: ', err)
        return xml_invalid_access_key_id()
    end

    -- Validate auth_type
    local auth_type, auth_remaining = auth_parts[1], auth_parts[2]

    if auth_type ~= CONST_AWS_HMAC_TYPE then
        return xml_invalid_request('Please use ' .. CONST_AWS_HMAC_TYPE)
    end

    -- Parse remaining auth header variables
    local auth_remaining_items, err = re_split(auth_remaining, ',', 'jo')

    if not auth_remaining_items then
        ngx_log(ERR, 'auth_remaining_items split failed: ', err)
        return xml_invalid_request('Authorization header invalid.')
    end

    local auth_args  = {}
    for _, auth_item in ipairs(auth_remaining_items) do
        local auth_pair, err = re_split(auth_item, '=', 'jo', nil, 2)
        if not auth_pair then
            ngx_log(ERR, 'auth_pair split failed: ', err)
            return xml_invalid_request('Authorization header invalid.')
        end

        auth_args[auth_pair[1]] = auth_pair[2]
    end

    -- Parse credential - no split here as we want to validate the contents of each field
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
    local signed_header_items, err = re_split(auth_args['signedheaders'], ';', 'jo')

    if not signed_header_items then
        ngx_log(ERR, 'signed_header_items split failed: ', err)
        return xml_invalid_access_key_id()
    end

    local signed_header_pairs  = {}
    for _, signed_header in ipairs(signed_header_items) do
        local h = str_lower(signed_header)
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

    local signed_headers    = {}
    local canonical_headers = {}
    for _, header in ipairs(signed_header_pairs) do
        tbl_insert(signed_headers, header[1])
        tbl_insert(canonical_headers, header[1] .. ':' .. header[2])
    end

    local canonical_request = self:get_canonical_request(signed_headers, canonical_headers, payload)

    local signature = self:generate_signature(amz_date, cred['scope'], canonical_request, access_details['aws_secret_access_key'], cred['region'], cred['service'])

    -- Check if signature matches
    if auth_args['signature'] ~= signature then
        ngx_log(ERR, 'Client ', access_details['fqdn'], ' request signature mismatch: ', signature, ' invalid (', auth_args['signature'], ' expected)')
        return xml_signature_mismatch()
    else
        ngx_log(DEBUG, 'Signature ', signature, ' verified')
    end

    -- Now we need to validate the bucket that the user is accessing

    if vars.request_uri ~= '/' then
        local valid_bucket_names = access_details['buckets']
        local found = false
        for _, bucket_name in ipairs(valid_bucket_names) do
            if str_sub(vars.request_uri, 0, str_len(bucket_name)) == bucket_name then
                found = true
                break
            end
        end

        if not found then
            ngx_log(ERR, 'Client ', access_details['fqdn'], ' URI ', vars.request_uri, ' does not start with one of ', tbl_concat(valid_bucket_names, ', '))
            return xml_invalid_bucket()
        end
    end

    -- Generate new signature based on local secret_access_key
    local new_signature = self:generate_signature(amz_date, cred['scope'], canonical_request, self['secret_access_key'], cred['region'], cred['service'])

    local auth = tbl_concat({
        CONST_AWS_HMAC_TYPE,
        tbl_concat({
            'Credential='    .. tbl_concat({ self['access_key_id'], cred['scope'] }, '/'),
            'SignedHeaders=' .. tbl_concat(signed_headers, ';'),
            'Signature='     .. new_signature,
        }, ',')
    }, ' ')

    ngx.req.set_header('Authorization', auth)
end


function S3AuthProxy:get_canonical_request(signed_headers, canonical_headers, payload)
    local vars = ngx.var
    -- Generate signed and canonical header tables from input

    return tbl_concat({
        vars.request_method,
        vars.request_uri,
        vars.args or '',
        tbl_concat(canonical_headers, "\n") or '',
        '', -- Add newline to end of canonical headers, always
        tbl_concat(signed_headers, ";") or '',
        sha256_string(payload)
    },"\n")
end


function S3AuthProxy:generate_signature(date, scope, canonical_request, secret_access_key, region, service)
    local string_to_sign = tbl_concat({
        CONST_AWS_HMAC_TYPE,
        date,
        scope,
        sha256_string(canonical_request)
    }, "\n")

    local h = resty_hmac:new()

    local date_key    = h:digest('sha256', 'AWS4' .. secret_access_key, str_sub(date,0,8), true)
    local region_key  = h:digest('sha256', date_key, region, true)
    local service_key = h:digest('sha256', region_key, service, true)
    local signing_key = h:digest('sha256', service_key, 'aws4_request', true)

    return h:digest('sha256', signing_key, string_to_sign, false)
end

return S3AuthProxy
