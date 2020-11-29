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

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "pk.h"

SEC("init") uint64_t
pk_init(struct gk_bpf_init_ctx *ctx)
{
	return pk_init_inline(ctx);
}

SEC("pkt") uint64_t
pk_pkt(struct gk_bpf_pkt_ctx *ctx)
{
	struct pk_state *state =
		(struct pk_state *)pkt_ctx_to_cookie(ctx);
	struct rte_mbuf *pkt = pkt_ctx_to_pkt(ctx);
	uint32_t pkt_len = pkt->pkt_len;
	uint64_t ret = pk_pkt_begin(ctx, state, pkt_len);
	uint16_t knocked_port;
	struct tcphdr *tcp_hdr;

	if (ret != GK_BPF_PKT_RET_FORWARD)
		return ret;

	if (state->correct_knocks == NUM_PORT_KNOCKS)
		goto done;

	if (ctx->l4_proto != IPPROTO_TCP)
		goto secondary;

	if (pkt->l4_len < sizeof(*tcp_hdr)) {
		/* Malformed TCP header. */
		return GK_BPF_PKT_RET_DECLINE;
	}
	tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct tcphdr *,
		pkt->l2_len + pkt->l3_len);
	knocked_port = tcp_hdr->th_dport;

	if (knocked_port == state->ports_be[state->correct_knocks])
		state->correct_knocks++;
	else
		state->correct_knocks = 0;

	if (state->correct_knocks == NUM_PORT_KNOCKS)
		goto done;
secondary:
	ret = pk_pkt_test_2nd_limit(state, pkt_len);
	if (ret != GK_BPF_PKT_RET_FORWARD)
		return ret;
done:
	return pk_pkt_end(ctx, state);
}
