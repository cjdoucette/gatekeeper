return function (net_conf, numa_table)

	-- Init the LLS configuration structure.
	local lls_conf = staticlib.c.get_lls_conf()
	if lls_conf == nil then
		error("Failed to allocate lls_conf")
	end

	-- Change these parameters to configure the LLS block.

	-- Log level for LLS. Note: set to RTE_LOG_DEBUG
	-- to log routing table updates and to log all
	-- the cache when it is periodically scanned.
	lls_conf.log_level = staticlib.c.RTE_LOG_DEBUG

	-- XXX #155 Sample parameters, need to be tested for better performance.
	lls_conf.mailbox_max_entries_exp = 7
	lls_conf.mailbox_mem_cache_size = 0
	lls_conf.mailbox_burst_size = 32

	-- The maximum number of packets to retrieve/transmit.
	lls_conf.front_max_pkt_burst = 32
	lls_conf.back_max_pkt_burst = 32

	-- The maximum number of ARP or ND packets submitted by GK or GT.
	lls_conf.mailbox_max_pkt_burst = 32

	-- XXX #155 Sample parameters, need to be tested for better performance.
	lls_conf.lls_cache_records = 1024

	-- Length of time (in seconds) to wait between scans of the cache.
	lls_conf.lls_cache_scan_interval_sec = 10

	-- Log ratelimit interval and burst size.
	lls_conf.log_ratelimit_interval_ms = 5000
	lls_conf.log_ratelimit_burst = 10

	-- Setup the LLS functional block.
	lls_conf.lcore_id = staticlib.alloc_an_lcore(numa_table)
	local ret = staticlib.c.run_lls(net_conf, lls_conf)
	if ret < 0 then
		error("Failed to run lls block")
	end

	return lls_conf
end
