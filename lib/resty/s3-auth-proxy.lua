local ngx_log      = ngx.log
local ERR          = ngx.ERR
local INFO         = ngx.INFO
local DEBUG        = ngx.DEBUG
local encode_args  = ngx.encode_args
local re_match     = ngx.re.match
local re_gmatch    = ngx.re.gmatch
local str_lower    = string.lower
local tbl_insert   = table.insert
local tbl_concat   = table.concat
local tbl_sort     = table.sort
local str          = require('resty.string')
local str_to_hex   = str.to_hex
local str_sub      = string.sub
local str_len      = string.len
local resty_hmac   = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local resty_md5    = require('resty.md5')
local os           = require('os')
local os_date      = os.date
local io_open      = io.open

-- Constants
local CONST_AWS_HMAC_TYPE         = 'AWS4-HMAC-SHA256'
local CONST_AWS_PAYLOAD_STREAMING = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'
local CONST_AWS_PAYLOAD_UNSIGNED  = 'UNSIGNED-PAYLOAD'
local CONST_PAYLOAD_HASH_EMPTY    = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

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

local xml_bad_digest = function(msg)
    return xml_error('BadDigest', (msg or 'The request body digest we calculated does not match the x-amz-content-sha256 header you provided.'), 400)
end

-- Auth proxy Public Interface
local S3AuthProxy = {}


function S3AuthProxy:new(config)
    if not config['client_keys'] then
        ngx_log(ERR, 'S3AuthProxy: "client_keys" config option must be a table!')
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
        local fqdn_parts, err = re_gmatch(fqdn, "(?<label>[^\\.]+)\\.?", "jo")

        if not fqdn_parts then
            ngx_log(ERR, 'fqdn_parts regex failed: ', err)
            return nil
        end

        -- Build valid bucket names from fqdn parts (e.g. puppet-test01, puppet-test01.ash2, puppet-test01.ash2.squiz, puppet-test01.ash2.squiz.co, etc - all valid)
        local valid_bucket_names  = {}
        local cur_bucket_name     = nil

        while true do
            local arg, err = fqdn_parts()
            if not arg then
                break
            end
            local cur_label = arg['label']
            if cur_bucket_name then
                cur_bucket_name = cur_bucket_name .. '.' .. cur_label
            else
                cur_bucket_name = cur_label
            end
            tbl_insert(valid_bucket_names, '/' .. cur_bucket_name .. '/')
        end

        self['keypairs'][secrets['aws_access_key_id']] = { fqdn = fqdn, aws_secret_access_key = secrets['aws_secret_access_key'], buckets = valid_bucket_names }
        self['keycount'] = self['keycount'] + 1
    end

    ngx_log(INFO, 'S3AuthProxy: Loaded ', self['keycount'], ' Access Keys...')
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

    local payload_hash

    -- Signed Chunked upload
    if amz_content == CONST_AWS_PAYLOAD_STREAMING then
        ngx_log(ERR, CONST_AWS_PAYLOAD_STREAMING, ' is not supported.')
        return xml_invalid_request(CONST_AWS_PAYLOAD_STREAMING .. ' is not supported.')

    -- Unsigned upload
    elseif amz_content == CONST_AWS_PAYLOAD_UNSIGNED then
        payload_hash = CONST_PAYLOAD_HASH_EMPTY

    -- Signed single upload
    else
        payload_hash = self:hash_body()
    end

    ngx_log(DEBUG, 'Calculated Payload SHA256: ', payload_hash)
    ngx_log(DEBUG, 'Header     Payload SHA256: ', amz_content)

    -- Check if payload hash matches
    if payload_hash ~= amz_content then
        ngx_log(ERR, 'Client ', access_details['fqdn'], ' payload hash mismatch: ', payload_hash, ' invalid (', amz_content, ' expected)')
        return xml_bad_digest()
    end

    -- Generate signed and canonical header tables from input
    local signed_headers        = {}
    local canonical_headers     = {}
    local new_signed_headers    = {}
    local new_canonical_headers = {}
    for _, header in ipairs(signed_header_pairs) do
        tbl_insert(signed_headers, header[1])
        tbl_insert(canonical_headers, header[1] .. ':' .. header[2])
        -- Do not allow 'expect' header to be signed onwards - this is not forwarded by nginx
        if header[1] ~= 'expect' then
            tbl_insert(new_signed_headers, header[1])
            tbl_insert(new_canonical_headers, header[1] .. ':' .. header[2])
        end
    end

    local canonical_request_hash = self:get_canonical_request_hash(signed_headers, canonical_headers, payload_hash)
    local signature = self:generate_signature(amz_date, cred['scope'], canonical_request_hash, access_details['aws_secret_access_key'], cred['region'], cred['service'])

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

    ngx_log(DEBUG, 'Verified, regenerating signature!')

    -- Generate new signature based on local secret_access_key
    local new_canonical_request_hash = self:get_canonical_request_hash(new_signed_headers, new_canonical_headers, payload_hash)
    local new_signature = self:generate_signature(amz_date, cred['scope'], new_canonical_request_hash, self['secret_access_key'], cred['region'], cred['service'])

    local auth = tbl_concat({
        CONST_AWS_HMAC_TYPE,
        tbl_concat({
            'Credential='    .. tbl_concat({ self['access_key_id'], cred['scope'] }, '/'),
            'SignedHeaders=' .. tbl_concat(new_signed_headers, ';'),
            'Signature='     .. new_signature,
        }, ',')
    }, ' ')

    ngx.req.set_header('Authorization', auth)
end

function S3AuthProxy:hash_body()
    local chunk_size = self.chunk_size or 1048576
    local hash = resty_sha256:new()

    ngx.req.read_body()

    local payload = ngx.req.get_body_data()

    -- If body was read from memory, hash directly
    if payload ~= nil then
        hash:update(payload)
    else
        local body_data_file = ngx.req.get_body_file()

        -- If no body data file, payload was empty
        if body_data_file == nil then
            return CONST_PAYLOAD_HASH_EMPTY
        end

        -- Otherwise, read file in chunks, updating the hash for each chunk
        local file, msg = io_open(body_data_file, "r")
        if file then
            while True do
                local data = file:read(chunk_size)
                if data == nil then
                    break
                end
                hash:update(data)
            end
            file:close()
        else
	    ngx_log(ERR, 'Client failed body signature generation - unable to open temporary file ', body_data_file)
	    return xml_signature_mismatch()
        end
    end

    return str_to_hex(hash:final())
end


function S3AuthProxy:get_encoded_args()
    local args = ngx.req.get_uri_args()

    local o    = {}
    local keys = {}

    for k, v in pairs(args) do
        tbl_insert(keys, k)
    end

    tbl_sort(keys)

    for _, key in ipairs(keys) do
        local value = args[key]
        -- Value = true should mean 'key='
        if value == true then
            value = ''
        end
        tbl_insert(o, tbl_concat({ key, ngx.escape_uri(value or '') }, '='))

    end

    return tbl_concat(o, '&')
end

function S3AuthProxy:get_canonical_request_hash(signed_headers, canonical_headers, payload_hash)
    local vars = ngx.var
    local hash = resty_sha256:new()

    hash:update(tbl_concat({
        vars.request_method,
        vars.uri, -- TODO: Switch this to using vars.request_uri with query_string stripped (this is *not* equivalent but works if the URL is not rewritten!)
        self:get_encoded_args(), -- Encode query string values (but *not* = delimiter)
        tbl_concat(canonical_headers, "\n") or '',
        '', -- Add newline to end of canonical headers, always
        tbl_concat(signed_headers, ";") or '',
        payload_hash
    },"\n"))

    return str_to_hex(hash:final())
end


function S3AuthProxy:generate_signature(date, scope, canonical_request_hash, secret_access_key, region, service)
    local string_to_sign = tbl_concat({
        CONST_AWS_HMAC_TYPE,
        date,
        scope,
        canonical_request_hash
    }, "\n")

    local h = resty_hmac:new()

    local date_key    = h:digest('sha256', 'AWS4' .. secret_access_key, str_sub(date,0,8), true)
    local region_key  = h:digest('sha256', date_key, region, true)
    local service_key = h:digest('sha256', region_key, service, true)
    local signing_key = h:digest('sha256', service_key, 'aws4_request', true)

    return h:digest('sha256', signing_key, string_to_sign, false)
end

return S3AuthProxy
