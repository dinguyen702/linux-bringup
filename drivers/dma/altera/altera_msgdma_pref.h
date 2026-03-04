/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026, Altera Corporation. All rights reserved
 */

#ifndef _ALTERA_MSGDMA_PREF_H
#define _ALTERA_MSGDMA_PREF_H

#include <linux/dma/altera_dma_metadata.h>
#include <linux/dmaengine.h>
#include <linux/device.h>
#include <linux/debugfs.h>
#include "dmaengine.h"

#define NUM_DESC_SIZE					    512
#define DMA_RING_SIZE			    (NUM_DESC_SIZE * 2)
#define SG_NO_SUPPORT					      1

/* mSGDMA Prefetcher Control */
#define MSGDMA_PREF_CTL_PARK                             BIT(4)
#define MSGDMA_PREF_CTL_RESET                            BIT(2)
#define MSGDMA_PREF_CTL_DESC_POLL_EN                     BIT(1)
#define MSGDMA_PREF_CTL_RUN                              BIT(0)

#define MSGDMA_PREF_POLL_FREQ_MASK                       0xFFFF

/* mSGDMA Prefetcher Status */
#define MSGDMA_PREF_STAT_IRQ                             BIT(0)

#define MSGDMA_DESC_TX_STRIDE                      (0x00010001)
#define MSGDMA_DESC_RX_STRIDE                      (0x00010001)
#define MSGDMA_DESC_RW_STRIDE                      (0x00010001)
#define MSGDMA_PREF_DESC_CTL_OWNED_BY_HW                BIT(30)
#define MSGDMA_DESC_CTL_GEN_SOP                          BIT(8)
#define MSGDMA_DESC_CTL_GEN_EOP                          BIT(9)
#define MSGDMA_DESC_CTL_END_ON_EOP			BIT(12)
#define MSGDMA_DESC_CTL_END_ON_LEN		        BIT(13)
#define MSGDMA_DESC_CTL_TR_COMP_IRQ		        BIT(14)
#define MSGDMA_DESC_CTL_GO				BIT(31)
#define MSGDMA_DESC_CTL_EARLY_IRQ			BIT(15)
#define MSGDMA_DESC_CTL_TR_ERR_IRQ                 (0xff << 16)
#define MSGDMA_DESC_CTL_TX_SINGLE       (MSGDMA_DESC_CTL_GEN_SOP |      \
					 MSGDMA_DESC_CTL_GEN_EOP |      \
					 MSGDMA_DESC_CTL_TR_COMP_IRQ |  \
					 MSGDMA_DESC_CTL_GO)

#define MSGDMA_SW_RESET_WATCHDOG_CNTR                    10000
#define MSGDMA_CSR_FILL_LEVEL_VALID               (0xffffffff)
#define MSGDMA_CSR_RESP_FILL_LEVEL_GET(v)   ((v) & 0x0000ffff)

#define MSGDMA_CSR_STAT_STOPPED                         BIT(5)
#define MSGDMA_CSR_CTL_STOP_DESCS                       BIT(5)

#define MSGDMA_CSR_STAT_MASK                             0x3FF
#define MSGDMA_CSR_CTL_RESET                             BIT(1)
#define MSGDMA_CSR_STAT_RESETTING                        BIT(6)

#define MSGDMA_MAX_TRANS_LEN				U32_MAX

/**
 * struct msgdma_pref_extended_desc - mSGDMA prefetcher extended descriptor format
 * @read_addr_lo:        Data buffer source address (low bits)
 * @write_addr_lo:       Data buffer destination address (low bits)
 * @len:                 Number of bytes to transfer
 * @next_desc_lo:        Next descriptor low address
 * @bytes_transferred:   Number of bytes transferred
 * @desc_status:         Descriptor status
 * @reserved_18:         Reserved
 * @burst_seq_num:       Write/read burst and sequence number
 *                        - bits 31:24: write burst
 *                        - bits 23:16: read burst
 *                        - bits 15:0:  sequence number
 * @stride:              Write/read stride
 *                        - bits 31:16: write stride
 *                        - bits 15:0:  read stride
 * @read_addr_hi:        Data buffer source address (high bits)
 * @write_addr_hi:       Data buffer destination address (high bits)
 * @next_desc_hi:        Next descriptor high address
 * @timestamp_96b:       Prefetcher mod reserved bits, response bits [191:160]
 * @desc_control:        Descriptor control
 */
struct msgdma_pref_extended_desc {
	u32 read_addr_lo;
	u32 write_addr_lo;
	u32 len;
	u32 next_desc_lo;
	u32 bytes_transferred;
	u32 desc_status;
	u32 reserved_18;
	u32 burst_seq_num;
	u32 stride;
	u32 read_addr_hi;
	u32 write_addr_hi;
	u32 next_desc_hi;
	u32 timestamp_96b[3];
	u32 desc_control;
};

#define msgdma_pref_descroffs(a) (offsetof(struct msgdma_pref_extended_desc, a))

/**
 * struct msgdma_pref_csr - Prefetcher control and status register map
 * @control:          Control register.
 *                    Defines prefetcher behavior (e.g., enable/disable,
 *                    start/stop, interrupt enables, configuration bits).
 * @next_desc_lo:     Next descriptor pointer (low 32 bits).
 *                    Lower half of the 64-bit DMA descriptor ring/address
 *                    that the prefetcher should fetch next.
 * @next_desc_hi:     Next descriptor pointer (high 32 bits).
 *                    Upper half of the 64-bit descriptor address to pair
 *                    with @next_desc_lo.
 * @desc_poll_freq:   Descriptor poll frequency register.
 *                    Controls how often the prefetcher polls for new
 *                    descriptors when polling mode is used
 * @status:           Status register.
 *                    Exposes prefetcher state bits, error conditions, and
 *                    completion/empty indicators.
 */
struct msgdma_pref_csr {
	u32 control;
	u32 next_desc_lo;
	u32 next_desc_hi;
	u32 desc_poll_freq;
	u32 status;
};

#define msgdma_pref_csroffs(a) (offsetof(struct msgdma_pref_csr, a))

/**
 * struct msgdma_csr - mSGDMA control and status register block
 * @status:           Status register (Read/Clear)
 * @control:          Control register (Read/Write)
 * @rw_fill_level:    Write/Read fill level
 *                      - bits 31:16: write fill level
 *                      - bits 15:0:  read fill level
 * @resp_fill_level:  Response fill level (bits 15:0)
 * @rw_seq_num:       Write/Read sequence number
 *                      - bits 31:16: write sequence number
 *                      - bits 15:0:  read sequence number
 * @pad:              Reserved
 */
struct msgdma_csr {
	u32 status;
	u32 control;
	u32 rw_fill_level;
	u32 resp_fill_level;
	u32 rw_seq_num;
	u32 pad[3];
};

#define msgdma_csroffs(a) (offsetof(struct msgdma_csr, a))

struct altera_fpga_chan_fifo {
	u32 fill_level;
	u32 reserved;
	u32 almost_full_threshold;
	u32 almost_empty_threshold;
	u32 cut_through_threshold;
	u32 drop_on_error;
};

#define fifo_csroffs(a) (offsetof(struct altera_fpga_chan_fifo, a))

/**
 * struct altera_msgdma_private - mSGDMA prefetcher channel private state
 * @pref_desc:           Pointer to the prefetcher extended descriptor ring in CPU memory.
 *                       This ring is consumed by the prefetcher engine.
 * @async_tx:            DMAengine async transaction descriptor currently being prepared
 *                       or tracked for completion.
 * @slave_cfg:           DMA slave configuration applied to this channel
 *                       (direction, addresses, burst sizes, widths).
 * @dma_metadata:        Pointer to per-transfer metadata buffer used for timestamp,
 *                       actual length, and auxiliary info exchange with hardware.
 * @debugfs_dir:         debugfs directory entry for this channel/device.
 * @dma_dev:             DMAengine device instance exported to the core.
 * @dma_chan:            Embedded DMAengine channel representing this MSGDMA channel.
 * @pref_descphys:       DMA-mapped physical address of @pref_desc (base of ring).
 * @fifo_info:           MMIO base for FIFO info/registers region.
 * @pref_csr:            MMIO base for prefetcher control/status registers.
 * @dma_csr:             MMIO base for core DMA control/status registers.
 * @dma_lock:            Spinlock protecting submit/completion critical sections and
 *                       shared channel state.
 * @pref_prod:           Producer index for the prefetch descriptor ring (host-owned).
 * @pref_cons:           Consumer index tracking hardware consumption of the ring.
 * @prefetch_capability: Prefetcher capability flags (exported/decoded from hardware).
 * @fifo_almost_empty:   FIFO almost-empty watermark threshold (in entries/words).
 * @fifo_almost_full:    FIFO almost-full watermark threshold (in entries/words).
 * @chan_poll_freq:      Channel descriptor polling frequency (when polling mode is used).
 * @pref_pending:        Count of prefetch descriptors pending in hardware.
 * @msg_enable:          Driver message verbosity mask (netif-style or driver-specific bits).
 * @fifo_depth:          Depth of the hardware FIFO (in entries/words).
 * @chan_ring_size:      Size of the prefetch descriptor ring (number of entries).
 * @dma_paused:          DMA channel paused state (true if paused).
 */
struct altera_msgdma_private {
	struct msgdma_pref_extended_desc *pref_desc;
	struct dma_async_tx_descriptor *async_tx;
	struct dma_slave_config slave_cfg;
	struct dma_metadata *dma_metadata;
	struct dentry *debugfs_dir;
	struct dma_device dma_dev;
	struct dma_chan dma_chan;
	dma_addr_t pref_descphys;
	void __iomem *fifo_info;
	void __iomem *pref_csr;
	void __iomem *dma_csr;
	spinlock_t dma_lock; /* Any operation which has contention uses this lock */
	u64 pref_prod;
	u64 pref_cons;
	u32 prefetch_capability;
	u32 fifo_almost_empty;
	u32 fifo_almost_full;
	u32 chan_poll_freq;
	u32 pref_pending;
	u32 msg_enable;
	u32 fifo_depth;
	u16 chan_ring_size;
	bool dma_paused;
};

#define chantopriv(dchan) container_of(dchan, struct altera_msgdma_private, dma_chan)

struct altera_msgdma_buffer {
	size_t len;
	dma_addr_t dma_addr;
	unsigned long flags;
};

#endif
