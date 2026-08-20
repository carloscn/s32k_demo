/* Storage for the MU0 channel request/descriptor arrays that every
 * hse_dal service wrapper (hse_host_*.c) references as extern via
 * hse_host_global.h.
 *
 * IMPORTANT (S32K312 + this project's MPU/linker map):
 * Do NOT place these in .mcal_bss_no_cacheable (0x20408000+). HSE as an AHB
 * master rejects host buffers in the no-cacheable / shareable SRAM windows
 * with HSE_SRV_RSP_INVALID_ADDR — confirmed for this chip in AGENTS.md.
 * Explicit section(".bss") overrides any leftover MemMap pragma from
 * hse_host_global.h so they land in cacheable SRAM (0x20400000+). Clean the
 * descriptor before Hse_Ip_ServiceRequest (see hse_host_mac.c).
 */

#include "hse_host_global.h"

hseSrvDescriptor_t MbedTLS_aSrvDescriptor[HSE_NUM_OF_CHANNELS_PER_MU]
    __attribute__((section(".bss")));
Hse_Ip_ReqType MbedTLS_aRequest[HSE_NUM_OF_CHANNELS_PER_MU]
    __attribute__((section(".bss")));
