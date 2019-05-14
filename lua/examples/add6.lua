require "gatekeeper/staticlib"

local acc_start = ""
local reply_msg = ""

local dyc = staticlib.c.get_dy_conf()

local ret = dylib.c.add_fib_entry("2600:1f16:354:f703::/64",
	"2600:1f16:354:f703:795:5efd:5335:f95c",
	"2600:1f16:354:f702:795:5efd:5335:abc1",
	dylib.c.GK_FWD_GRANTOR, dyc.gk)
if ret < 0 then
	return "gk: failed to add an FIB entry\n"
end

return "gk: successfully processed all the FIB entries\n" .. reply_msg
