local ngx_log = ngx.log
local ngx_DEBUG = ngx.DEBUG
local ngx_ERR = ngx.ERR
local ngx_shared = ngx.shared
local ngx_time = ngx.time
local resty_resolver = require "resty.dns.resolver"
local resty_lrucache = require "resty.lrucache"
local cjson = require "cjson"
local json_encode = cjson.encode
local json_decode = cjson.decode
local tbl_concat = table.concat

local debug_log = function(msg, ...)
    if type(msg) == 'table' then
        local ok, json = pcall(json_encode, msg)
        if ok then
            msg = json
        else
            ngx_log(ngx_ERR, json)
        end
    end
    ngx_log(ngx_DEBUG, msg, ...)
end

local _M = {
    _VERSION = '0.01',
    TYPE_A      = resty_resolver.TYPE_A,
    TYPE_NS     = resty_resolver.TYPE_NS,
    TYPE_CNAME  = resty_resolver.TYPE_CNAME,
    TYPE_PTR    = resty_resolver.TYPE_PTR,
    TYPE_MX     = resty_resolver.TYPE_MX,
    TYPE_TXT    = resty_resolver.TYPE_TXT,
    TYPE_AAAA   = resty_resolver.TYPE_AAAA,
    TYPE_SRV    = resty_resolver.TYPE_SRV,
    TYPE_SPF    = resty_resolver.TYPE_SPF,
    CLASS_IN    = resty_resolver.CLASS_IN
}

local DEBUG = false

local mt = { __index = _M }

local lru_cache_defaults = {200}
local resolver_defaults = {
    nameservers = {"8.8.8.8", "8.8.4.4"}
}

-- Global lrucache instance
local lru_cache


function _M.init_cache(max_items)
    max_items = max_items or 200
    local err
    lru_cache, err = resty_lrucache.new(max_items)
    if not lru_cache then
        return nil, err
    end
end


function _M.new(opts)
    opts = opts or {}

    -- Set defaults
    local self = {
        normalise_ttl  = opts.normalise_ttl  or true,
        negative_ttl   = opts.negative_ttl   or false,
        minimise_ttl   = opts.minimise_ttl   or false,
    }

    local err
    opts.resolver = opts.resolver or resolver_defaults
    self.resolver, err = resty_resolver:new(opts.resolver)
    if not self.resolver then
        return nil, err
    end

    if opts.dict then
        self.dict = ngx_shared[opts.dict]
    end

    return setmetatable(self, mt)
end


function _M.set_timeout(self, ...)
    return self.resolver:set_timeout(...)
end


local function minimise_ttl(answer)
    local ttl
    for _, ans in ipairs(answer) do
        if DEBUG then debug_log('TTL ', ans.name, ': ', ans.ttl) end
        if ttl == nil or ans.ttl < ttl then
            ttl = ans.ttl
        end
    end
    return ttl
end


local function normalise_ttl(self, data)
    -- Calculate time since query and subtract from answer's TTL
    if self.normalise_ttl then
        local diff = ngx_time() - data.now
        if DEBUG then debug_log("Normalising TTL, diff: ", diff) end
        for _, answer in ipairs(data.answer) do
            if DEBUG then debug_log("Old: ", answer.ttl, ", new: ", answer.ttl - diff) end
            answer.ttl = answer.ttl - diff
        end
    end
    return data
end


local function cache_get(self, key)
    -- Try local LRU cache first
    local data, lru_stale
    if lru_cache then
        data, lru_stale = lru_cache:get(key)
        if data then
            if DEBUG then
                debug_log('lru_cache HIT: ', key)
                debug_log(data)
            end
            return normalise_ttl(self, data).answer
        elseif DEBUG then
            debug_log('lru_cache MISS: ', key)
        end
    end

    -- lru_cache miss, try shared dict
    local dict = self.dict
    if dict then
        local data, flags, stale = dict:get(key)

        if data then
            -- shared dict populates 'data' even if stale, decode it now
            data = json_decode(data)
        else
            -- No data in dict cache, return stale lru_cache if possible
            if DEBUG then debug_log('shared_dict MISS: ', key) end
            if lru_stale then
                if DEBUG then
                    debug_log('lru_cache STALE: ', key)
                    debug_log(lru_stale)
                end
                return nil, normalise_ttl(self, data).answer
            end
            return nil
        end

        -- Return nil and dict cache if its stale
        if stale then
            if DEBUG then debug_log('shared_dict STALE: ', key) end
            return nil, normalise_ttl(self, data).answer
        end

        -- Fresh HIT from dict, repopulate the lru_cache
        if DEBUG then debug_log('shared_dict HIT: ', key) end
        if lru_cache then
            local ttl = data.expires - ngx_time()
            if DEBUG then debug_log('lru_cache SET: ', key, ' ', ttl) end
            lru_cache:set(key, data, ttl)
        end
        return normalise_ttl(self, data).answer
    end

    if not lru_cache or dict then
        ngx_log(ngx_ERR, "No cache defined")
    end
end


local function cache_set(self, key, answer, ttl)
    -- Don't cache records with 0 TTL
    if ttl == 0 or ttl == nil then
        return
    end

    -- Calculate absolute expiry - used to populate lru_cache from shared_dict
    local now = ngx_time()
    local data = {
        answer = answer,
        now = now,
        expires = now + ttl
    }

    -- Set lru cache
    if lru_cache then
        if DEBUG then debug_log('lru_cache SET: ', key, ' ', ttl) end
        lru_cache:set(key, data, ttl)
    end

    -- Set dict cache
    local dict = self.dict
    if dict then
        if DEBUG then debug_log('shared_dict SET: ', key, ' ', ttl) end
        local ok, err, forcible = dict:set(key, json_encode(data), ttl)
        if not ok then
            ngx_log(ngx_ERR, 'shared_dict ERR: ', err)
        end
        if forcible then
            ngx_log(ngx_DEBUG, 'shared_dict full')
        end
    end
end


local function _resolve(resolver, query_func, host, opts)
    if DEBUG then debug_log('Querying: ', host) end
    local answers, err = query_func(resolver, host, opts)
    if not answers then
        return answers, err
    end
    if DEBUG then debug_log(answers) end

    return answers
end


local function _query(self, host, opts, tcp)
    -- Build cache key
    local key = host
    if opts and opts.qtype then
        key = tbl_concat({key,'|',opts.qtype})
    end

    -- Check caches
    local answer, stale = cache_get(self, key)
    if answer then
        -- Don't return negative cache hits if negative_ttl is off in this instance
        if not answer.errcode or self.negative_ttl then
            return answer
        end
    end

    -- No fresh cache entry, try to resolve
    local resolver = self.resolver
    local query_func = resolver.query
    if tcp then
        query_func = resolver.tcp_query
    end

    local answer, err = _resolve(resolver, query_func, host, opts)
    if not answer then
        -- Couldn't resolve, return stale if we have it
        if DEBUG then
            debug_log('Resolver error ', key, ': ', err)
            if stale then debug_log('Returning STALE: ', key) end
        end
        return nil, err, stale
    end

    local ttl

    -- Cache server errors for negative_cache seconds, default to not caching them
    if answer.errcode then
        if self.negative_ttl then
            ttl = self.negative_ttl
        else
            return answer
        end
    end

    -- Cache for the lowest TTL in the chain of responses...
    if self.minimise_ttl then
        ttl = minimise_ttl(answer)
    elseif answer[1] then
        -- ... or just the first one
        ttl = answer[1].ttl or nil
    end

    -- Set cache
    cache_set(self, key, answer, ttl)
    return answer
end


function _M.query(self, host, opts)
    return _query(self, host, opts, false)
end


function _M.tcp_query(self, host, opts)
    return _query(self, host, opts, true)
end


return _M