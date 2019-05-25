require "gatekeeper/staticlib"

local acc_start = ""
local reply_msg = ""

local dyc = staticlib.c.get_dy_conf()

local ret = dylib.c.add_fib_entry("172.31.5.0/24", NULL,
        "172.31.1.184", dylib.c.GK_FWD_GATEWAY_FRONT_NET, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

return "gk: successfully processed all the FIB entries\n" .. reply_msg
