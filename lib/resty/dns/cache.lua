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
    return true
end


function _M.initted()
    if lru_cache then return true end
    return false
end


function _M.new(opts)
    local self, err = {}, nil
    opts = opts or {}

    -- Set defaults
    if opts.normalise_ttl ~= nil then self.normalise_ttl = opts.normalise_ttl else self.normalise_ttl = true  end
    if opts.negative_ttl  ~= nil then self.negative_ttl  = opts.negative_ttl  else self.negative_ttl  = false end
    if opts.minimise_ttl  ~= nil then self.minimise_ttl  = opts.minimise_ttl  else self.minimise_ttl  = false end

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


function _M._debug(flag)
    DEBUG = flag
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
        local now = ngx_time()
        local diff = now - data.now
        if DEBUG then debug_log("Normalising TTL, diff: ", diff) end
        for _, answer in ipairs(data.answer) do
            if DEBUG then debug_log("Old: ", answer.ttl, ", new: ", answer.ttl - diff) end
            answer.ttl = answer.ttl - diff
        end
        data.now = now
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
        local data, flags, stale = dict:get_stale(key)

        -- Dict data is stale, prefer stale LRU data
        if stale and lru_stale then
            if DEBUG then
                debug_log('lru_cache STALE: ', key)
                debug_log(lru_stale)
            end
            return nil, normalise_ttl(self, lru_stale).answer
        end

        -- Definitely no lru data, going to have to try shared dict
        if data then
            data = json_decode(data)
        else
            -- Full MISS on dict, return nil
            if DEBUG then debug_log('shared_dict MISS: ', key) end
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
    elseif lru_stale then
        -- Return lru stale if no dict configured
        if DEBUG then
            debug_log('lru_cache STALE: ', key)
            debug_log(lru_stale)
        end
        return nil, normalise_ttl(self, lru_stale).answer
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
        queried = now,
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
    opts = opts or {}
    local qtype = opts.qtype or 1
    local key = tbl_concat({host,'|',qtype})

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

    -- Cache server errors for negative_cache seconds
    if answer.errcode then
        if self.negative_ttl then
            ttl = self.negative_ttl
        else
            return answer
        end
    else
        -- Cache for the lowest TTL in the chain of responses...
        if self.minimise_ttl then
            ttl = minimise_ttl(answer)
        elseif answer[1] then
            -- ... or just the first one
            ttl = answer[1].ttl or nil
        end
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