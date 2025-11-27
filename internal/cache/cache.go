package cache

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var DefaultUpdateTimeTickInterval = time.Millisecond * 300

var (
	ErrCacheIsNotFound = errors.New("cache is not found")
	ErrCacheWasExpired = errors.New("cache was expired")
)

type Cache[K comparable, V any] interface {
	Get(K) (V, error)
	Set(K, V)
	Delete(K)
	Contains(K) bool
	Stop()
}

type EvictCallback func(any, any)

type options struct {
	timeNowFn           func() int64
	maxSize             int
	interval            time.Duration
	expiration          time.Duration
	evictFn             EvictCallback
	checkCache          bool
	updateCacheExpOnGet bool
	deleteExpCacheOnGet bool
}

type Option interface{ apply(*options) }

type OptionFunc func(o *options)

func (f OptionFunc) apply(o *options) { f(o) }

func WithGoTimeNow() Option {
	return OptionFunc(func(o *options) { o.timeNowFn = func() int64 { return time.Now().UnixNano() } })
}

func WithMaxSize(maxSize int) Option {
	return OptionFunc(func(o *options) { o.maxSize = maxSize })
}

func WithInterval(interval time.Duration) Option {
	return OptionFunc(func(o *options) { o.interval = interval })
}

func WithExpiration(expiration time.Duration) Option {
	return OptionFunc(func(o *options) { o.expiration = expiration })
}

func WithEvictCallback(fn EvictCallback) Option {
	return OptionFunc(func(o *options) { o.evictFn = fn })
}

func WithUpdateCacheExpirationOnGet() Option {
	return OptionFunc(func(o *options) { o.updateCacheExpOnGet = true })
}

func WithDeleteExpiredCacheOnGet() Option {
	return OptionFunc(func(o *options) { o.deleteExpCacheOnGet = true })
}

func WithBackgroundCheckCache() Option {
	return OptionFunc(func(o *options) { o.checkCache = true })
}

type cacheEntry[K comparable, V any] struct {
	key     K
	value   V
	expires int64
}

var _ Cache[string, string] = (*LruCache[string, string])(nil)

type LruCache[K comparable, V any] struct {
	mu          sync.RWMutex
	lru         *list.List
	cache       map[K]*list.Element
	doneCh      chan struct{}
	opts        options
	fasttimeNow int64
}

func New[K comparable, V any](opt ...Option) Cache[K, V] {
	lc := &LruCache[K, V]{
		lru:         list.New(),
		cache:       make(map[K]*list.Element, 32),
		doneCh:      make(chan struct{}, 1),
		fasttimeNow: time.Now().UnixNano(),
		opts: options{
			maxSize:    100,
			interval:   30 * time.Second,
			expiration: 15 * time.Second,
		},
	}
	for _, o := range opt {
		o.apply(&lc.opts)
	}
	if lc.opts.checkCache {
		go lc.check()
	}
	// use fast time instead of go time.Now()
	if lc.opts.timeNowFn == nil {
		lc.opts.timeNowFn = func() int64 { return atomic.LoadInt64(&lc.fasttimeNow) }
		go lc.updateTick()
	}
	return lc
}

func (c *LruCache[K, V]) Contains(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.cache[key]
	return ok
}

func (c *LruCache[K, V]) Get(key K) (value V, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		cache := ele.Value.(*cacheEntry[K, V])
		now := c.opts.timeNowFn()
		if now >= cache.expires {
			// delete expired cache when get
			if c.opts.deleteExpCacheOnGet {
				c.delete(ele)
			}
			err = ErrCacheWasExpired
			return
		}
		c.lru.MoveToBack(ele)
		// update cache expiration when get
		if c.opts.updateCacheExpOnGet {
			cache.expires = now + c.opts.expiration.Nanoseconds()
		}
		value = cache.value
		return
	}
	err = ErrCacheIsNotFound
	return
}

func (c *LruCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		cache := ele.Value.(*cacheEntry[K, V])
		cache.value = value
		cache.expires = c.opts.timeNowFn() + c.opts.expiration.Nanoseconds()
		c.lru.MoveToBack(ele)
		return
	}
	if c.lru.Len() == c.opts.maxSize {
		c.delete(c.lru.Front())
	}
	cache := &cacheEntry[K, V]{
		key:     key,
		value:   value,
		expires: c.opts.timeNowFn() + c.opts.expiration.Nanoseconds(),
	}
	c.cache[key] = c.lru.PushBack(cache)
}

func (c *LruCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ele, ok := c.cache[key]; ok {
		c.delete(ele)
	}
}

func (c *LruCache[K, V]) Stop() {
	close(c.doneCh)
}

func (c *LruCache[K, V]) deleteOverflow() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.lru.Len() > c.opts.maxSize {
			c.delete(c.lru.Front())
		}
	}
}

func (c *LruCache[K, V]) delete(ele *list.Element) {
	cache := ele.Value.(*cacheEntry[K, V])
	delete(c.cache, cache.key)
	c.lru.Remove(ele)
	if c.opts.evictFn != nil {
		c.opts.evictFn(cache.key, cache.value)
	}
}

func (c *LruCache[K, V]) updateTick() {
	ticker := time.NewTicker(DefaultUpdateTimeTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.doneCh:
			return
		case <-ticker.C:
			atomic.StoreInt64(&c.fasttimeNow, time.Now().UnixNano())
		}
	}
}

func (c *LruCache[K, V]) check() {
	interval := c.opts.interval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-c.doneCh:
			return
		case <-timer.C:
			c.cleanup()
			timer.Reset(interval)
		}
	}
}

func (c *LruCache[K, V]) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.opts.timeNowFn()
	for _, ele := range c.cache {
		cache := ele.Value.(*cacheEntry[K, V])
		if cache.expires <= now {
			c.delete(ele)
		}
	}
}
