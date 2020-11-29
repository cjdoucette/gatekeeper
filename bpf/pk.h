/*
 * Gatekeeper - DoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _PK_H_
#define _PK_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_common.h>

#include "gatekeeper_flow_bpf.h"
#include "bpf_mbuf.h"

#define NUM_PORT_KNOCKS 3

struct pk_params {
	/*
	 * Primary rate limit: kibibyte/second.
	 * This limit can never be exceeded.
	 */
	uint32_t tx1_rate_kib_sec;
	/*
	 * Secondary rate limit: kibibyte/second.
	 * This limit only applies to some part of the traffic.
	 *
	 * The traffic subject to the secondary rate limit is traffic that
	 * is allowed, but at a lower limit.
	 *
	 * When tx2_rate_kib_sec >= tx1_rate_kib_sec, it has no effect.
	 */
	uint32_t tx2_rate_kib_sec;
	/*
	 * The first value of send_next_renewal_at at
	 * flow entry comes from next_renewal_ms.
	 */
	uint32_t next_renewal_ms;
	/*
	 * How many milliseconds (unit) GK must wait
	 * before sending the next capability renewal
	 * request.
	 */
	uint32_t renewal_step_ms;

	/* Ports to knock, stored in network order. */
	uint16_t ports_be[NUM_PORT_KNOCKS];
} __attribute__ ((packed));

struct pk_state {
	/* When @budget_byte is reset. */
	uint64_t budget_renew_at;
	/*
	 * When @budget1_byte is reset,
	 * add @tx1_rate_kib_cycle * 1024 bytes to it.
	 */
	uint32_t tx1_rate_kib_cycle;
	/*
	 * When @budget2_byte is reset,
	 * reset it to @tx2_rate_kib_cycle * 1024 bytes.
	 */
	uint32_t tx2_rate_kib_cycle;
	/* How many bytes @src can still send in current cycle. */
	int64_t budget1_byte;
	/*
	 * How many bytes @src can still send in current cycle in
	 * the secondary channel.
	 */
	int64_t budget2_byte;
	/*
	 * When GK should send the next renewal to
	 * the corresponding grantor.
	 */
	uint64_t send_next_renewal_at;
	/*
	 * How many cycles (unit) GK must wait before
	 * sending the next capability renewal request.
	 */
	uint64_t renewal_step_cycle;

	/* Ports to knock, stored in network order. */
	uint16_t ports_be[NUM_PORT_KNOCKS];
	/* Number of currently correct knocks. */
	uint8_t correct_knocks;
};

static inline uint64_t
pk_init_inline(struct gk_bpf_init_ctx *ctx)
{
	struct gk_bpf_cookie *cookie = init_ctx_to_cookie(ctx);
	struct pk_params params = *(struct pk_params *)cookie;
	struct pk_state *state = (struct pk_state *)cookie;

	RTE_BUILD_BUG_ON(sizeof(params) > sizeof(*cookie));
	RTE_BUILD_BUG_ON(sizeof(*state) > sizeof(*cookie));

	state->budget_renew_at = ctx->now + cycles_per_sec;
	state->tx1_rate_kib_cycle = params.tx1_rate_kib_sec;
	state->tx2_rate_kib_cycle = params.tx2_rate_kib_sec;
	state->budget1_byte = (int64_t)params.tx1_rate_kib_sec * 1024;
	state->budget2_byte = (int64_t)params.tx2_rate_kib_sec * 1024;
	state->send_next_renewal_at = ctx->now +
		params.next_renewal_ms * cycles_per_ms;
	state->renewal_step_cycle = params.renewal_step_ms * cycles_per_ms;
	state->ports_be[0] = params.ports_be[0];
	state->ports_be[1] = params.ports_be[1];
	state->ports_be[2] = params.ports_be[2];
	state->correct_knocks = 0;

	return GK_BPF_INIT_RET_OK;
}

static inline uint64_t
pk_pkt_begin(const struct gk_bpf_pkt_ctx *ctx,
	struct pk_state *state, uint32_t pkt_len)
{
	if (ctx->now >= state->budget_renew_at) {
		int64_t max_budget1 = (int64_t)state->tx1_rate_kib_cycle * 1024;
		int64_t cycles = ctx->now - state->budget_renew_at;
		int64_t epochs = cycles / cycles_per_sec;

		state->budget_renew_at = ctx->now + cycles_per_sec -
			(cycles % cycles_per_sec);
		state->budget1_byte += max_budget1 * (epochs + 1);
		if (state->budget1_byte > max_budget1)
			state->budget1_byte = max_budget1;
		state->budget2_byte = (int64_t)state->tx2_rate_kib_cycle * 1024;
	}

	/* Primary budget. */
	state->budget1_byte -= pkt_len;
	if (state->budget1_byte < 0)
		return GK_BPF_PKT_RET_DECLINE;

	return GK_BPF_PKT_RET_FORWARD;
}

static inline uint64_t
pk_pkt_test_2nd_limit(struct pk_state *state, uint32_t pkt_len)
{
	state->budget2_byte -= pkt_len;
	if (state->budget2_byte < 0)
		return GK_BPF_PKT_RET_DECLINE;
	return GK_BPF_PKT_RET_FORWARD;
}

static inline uint64_t
pk_pkt_end(struct gk_bpf_pkt_ctx *ctx, struct pk_state *state)
{
	uint8_t priority = PRIORITY_GRANTED;

	if (ctx->now >= state->send_next_renewal_at) {
		state->send_next_renewal_at = ctx->now +
			state->renewal_step_cycle;
		priority = PRIORITY_RENEW_CAP;
	}

	if (gk_bpf_prep_for_tx(ctx, priority, false) < 0)
		return GK_BPF_PKT_RET_ERROR;

	return GK_BPF_PKT_RET_FORWARD;
}

#endif /* _PK_H_ */
