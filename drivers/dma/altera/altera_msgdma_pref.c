// SPDX-License-Identifier: GPL-2.0-or-later
/* Altera FPGA Ethernet DMA driver
 * Copyright (C) 2026 Altera Corporation. All rights reserved
 *
 * Contributors:
 *      Preetam Narayan
 */

#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/of_dma.h>
#include "altera_dma_utils.h"
#include "altera_msgdma_pref.h"

static uint msgdma_debug_level;
module_param(msgdma_debug_level, uint, 0644);
MODULE_PARM_DESC(msgdma_debug_level, "Global debug level for Altera mSGDMA driver");

static void altera_msgdma_pref_clear_irq(struct altera_msgdma_private *priv)
{
	dma_set_bit(priv->pref_csr, msgdma_pref_csroffs(status),
		    MSGDMA_PREF_STAT_IRQ);
}

static inline void altera_msgdma_dmaintr_enable(struct altera_msgdma_private *priv)
{
	altera_msgdma_pref_clear_irq(priv);
	dma_set_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		    MSGDMA_PREF_CTL_GLOBAL_INTR);
}

static inline void altera_msgdma_dmaintr_disable(struct altera_msgdma_private *priv)
{
	dma_clear_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		      MSGDMA_PREF_CTL_GLOBAL_INTR);
}

static int altera_request_and_map(struct platform_device *pdev, const char *name,
				  struct resource **res, void __iomem **ptr)
{
	struct resource *region;
	struct device *device = &pdev->dev;

	*res = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
	if (!*res) {
		dev_err(device, "resource %s not defined\n", name);
		return -ENODEV;
	}

	region = devm_request_mem_region(device, (*res)->start,
					 resource_size(*res), dev_name(device));
	if (!region) {
		dev_err(device, "unable to request %s\n", name);
		return -EBUSY;
	}

	*ptr = devm_ioremap(device, region->start,
			    resource_size(region));
	if (!*ptr) {
		dev_err(device, "ioremap of %s failed!", name);
		return -ENOMEM;
	}

	return 0;
}

static void *msgdma_get_metadata_ptr(struct dma_async_tx_descriptor *tx,
				    size_t *payload_len, size_t *max_len)
{
	struct altera_msgdma_private *priv = container_of(tx->chan,
							  struct altera_msgdma_private,
							  dma_chan);
	ptrdiff_t desc_index = tx - priv->async_tx;

	if (!(desc_index >= 0 && desc_index < priv->chan_ring_size))
		return NULL;

	if (payload_len)
		*payload_len = sizeof(struct dma_metadata);

	if (max_len)
		*max_len = sizeof(struct dma_metadata);

	return &priv->dma_metadata[desc_index];
}

static u32 altera_free_desc_available(struct altera_msgdma_private *priv)
{
	u32 chan_size = priv->chan_ring_size;
	u64 prod = priv->pref_prod;
	u64 cons = priv->pref_cons;

	return cons + chan_size - prod - 1;
}

static dma_cookie_t msgdma_tx_submit(struct dma_async_tx_descriptor *tx)
{
	dma_cookie_t cookie;

	cookie = dma_cookie_assign(tx);

	return cookie;
}

static int msgdma_desc_free(struct dma_async_tx_descriptor *tx)
{
	async_tx_clear_ack(tx);

	tx->cookie = DMA_MIN_COOKIE;
	tx->callback_result = NULL;

	return 0;
}

static struct dma_descriptor_metadata_ops msgdma_metadata_ops = {
	.get_ptr = msgdma_get_metadata_ptr,
};

static void coherent_mem_free(void *data)
{
	struct altera_msgdma_private *priv = data;
	struct msgdma_pref_extended_desc *descs;

	dma_free_coherent(priv->dma_dev.dev,
			  sizeof(*descs) * priv->chan_ring_size,
			  priv->pref_desc, priv->pref_descphys);
}

static int msgdma_pref_initialize(struct altera_msgdma_private *priv)
{
	struct msgdma_pref_extended_desc *descs;
	struct dma_async_tx_descriptor *async;
	struct dma_metadata meta;
	dma_addr_t descsphys;
	u32 chan_ring_size;
	int ret;
	int i;

	chan_ring_size = priv->chan_ring_size;

	priv->async_tx = devm_kcalloc(priv->dma_dev.dev,
				      chan_ring_size, sizeof(*async), GFP_KERNEL);
	if (!priv->async_tx)
		return -ENOMEM;

	priv->dma_metadata = devm_kcalloc(priv->dma_dev.dev,
					  chan_ring_size, sizeof(meta), GFP_KERNEL);
	if (!priv->dma_metadata)
		return -ENOMEM;

	priv->pref_desc = dma_alloc_coherent(priv->dma_dev.dev,
					     sizeof(*descs) * chan_ring_size,
					     &priv->pref_descphys, GFP_KERNEL);
	if (!priv->pref_desc)
		return -ENOMEM;

	descs = priv->pref_desc;
	descsphys = priv->pref_descphys;

	ret = devm_add_action_or_reset(priv->dma_dev.dev, coherent_mem_free, priv);
	if (ret) {
		dev_err(priv->dma_dev.dev,
			"dma coherent mem free registration failed %d\n", ret);
		return ret;
	}

	priv->pref_prod = 0;
	priv->pref_cons = 0;
	priv->pref_pending = 0;

	for (i = 0; i < chan_ring_size; i++) {
		descsphys = priv->pref_descphys +
			    (((i + 1) % chan_ring_size) *
			     sizeof(struct msgdma_pref_extended_desc));

		descs[i].next_desc_lo = lower_32_bits(descsphys);
		descs[i].next_desc_hi = upper_32_bits(descsphys);
		descs[i].burst_seq_num = i;

		dma_async_tx_descriptor_init(&priv->async_tx[i], &priv->dma_chan);
		priv->async_tx[i].tx_submit = msgdma_tx_submit;
		priv->async_tx[i].metadata_ops = &msgdma_metadata_ops;
		priv->async_tx[i].desc_free = msgdma_desc_free;
		priv->async_tx[i].cookie = DMA_MIN_COOKIE;
	}

	return 0;
}

static int altera_msgdma_config(struct dma_chan *dchan,
				struct dma_slave_config *config)
{
	struct altera_msgdma_private *priv = chantopriv(dchan);

	memcpy(&priv->slave_cfg, config, sizeof(*config));

	return 0;
}

static void altera_msgdma_confirm_fill_levels(struct altera_msgdma_private *priv)
{
	int counter = 0;
	int ret;

	do {
		ret = dma_read(priv->dma_csr, msgdma_csroffs(rw_fill_level));
		ret &= MSGDMA_CSR_FILL_LEVEL_VALID;

		if (ret == 0)
			break;

		udelay(1);
	} while (counter++ < MSGDMA_SW_RESET_WATCHDOG_CNTR);

	if (counter >= MSGDMA_SW_RESET_WATCHDOG_CNTR)
		dev_dbg(priv->dma_dev.dev,
			"DMA RW Fill level never cleared! 0x%X\n", ret);

	counter = 0;
	do {
		ret = MSGDMA_CSR_RESP_FILL_LEVEL_GET(dma_read(priv->dma_csr,
							      msgdma_csroffs(resp_fill_level)));
		if (ret == 0)
			break;

		udelay(1);
	} while (counter++ < MSGDMA_SW_RESET_WATCHDOG_CNTR);

	if (counter >= MSGDMA_SW_RESET_WATCHDOG_CNTR)
		dev_err(priv->dma_dev.dev,
			"DMA Resp Fill level never cleared! 0x%X\n", ret);
}

static void altera_msgdma_pref_quiesce(struct altera_msgdma_private *priv)
{
	int counter = 0;

	dma_set_bit(priv->dma_csr, msgdma_csroffs(control), MSGDMA_CSR_CTL_STOP_DESCS);

	do {
		if (dma_bit_is_set(priv->dma_csr, msgdma_csroffs(status),
				   MSGDMA_CSR_STAT_STOPPED))
			break;

		udelay(1);
	} while (counter++ < MSGDMA_SW_RESET_WATCHDOG_CNTR);

	if (counter >= MSGDMA_SW_RESET_WATCHDOG_CNTR)
		dev_dbg(priv->dma_dev.dev, "DMA stop bit not set");
}

static void altera_msgdma_reset(struct altera_msgdma_private *priv)
{
	int counter = 0;

	dma_write(MSGDMA_CSR_STAT_MASK, priv->dma_csr, msgdma_csroffs(status));
	dma_write(MSGDMA_CSR_CTL_RESET, priv->dma_csr, msgdma_csroffs(control));

	do {
		if (dma_bit_is_clear(priv->dma_csr, msgdma_csroffs(status),
				     MSGDMA_CSR_STAT_RESETTING))
			break;

		udelay(1);
	} while (counter++ < MSGDMA_SW_RESET_WATCHDOG_CNTR);

	if (counter >= MSGDMA_SW_RESET_WATCHDOG_CNTR)
		dev_warn(priv->dma_dev.dev,
			 "mSGDMA resetting bit never cleared!\n");

	dma_write(MSGDMA_CSR_STAT_MASK, priv->dma_csr, msgdma_csroffs(status));
}

static void altera_msgdma_pref_reset(struct altera_msgdma_private *priv)
{
	int counter = 0;

	dma_clear_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		      MSGDMA_PREF_CTL_DESC_POLL_EN);

	altera_msgdma_pref_quiesce(priv);

	altera_msgdma_confirm_fill_levels(priv);

	dma_write(MSGDMA_PREF_STAT_IRQ, priv->pref_csr, msgdma_pref_csroffs(status));
	dma_write(MSGDMA_PREF_CTL_RESET, priv->pref_csr, msgdma_pref_csroffs(control));

	do {
		if (dma_bit_is_clear(priv->pref_csr, msgdma_pref_csroffs(control),
				     MSGDMA_PREF_CTL_RESET))
			break;

		udelay(1);

	} while (counter++ < MSGDMA_SW_RESET_WATCHDOG_CNTR);

	if (counter >= MSGDMA_SW_RESET_WATCHDOG_CNTR)
		dev_warn(priv->dma_dev.dev,
			 "Prefetcher reset bit never cleared!\n");

	altera_msgdma_reset(priv);
}

static void altera_msgdma_pref_start_dma(struct altera_msgdma_private *priv)
{
	dma_write(priv->chan_poll_freq, priv->pref_csr,
		  msgdma_pref_csroffs(desc_poll_freq));
	dma_write(lower_32_bits(priv->pref_descphys), priv->pref_csr,
		  msgdma_pref_csroffs(next_desc_lo));
	dma_write(upper_32_bits(priv->pref_descphys), priv->pref_csr,
		  msgdma_pref_csroffs(next_desc_hi));
	dma_set_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		    MSGDMA_PREF_CTL_DESC_POLL_EN | MSGDMA_PREF_CTL_RUN);
}

static u64 timestamp_to_ns(struct msgdma_pref_extended_desc *desc)
{
	u64 ns = 0;
	u64 second;
	u32 tmp;

	tmp = desc->timestamp_96b[0] >> 16;
	tmp |= (desc->timestamp_96b[1] << 16);

	second = desc->timestamp_96b[2];
	second <<= 16;
	second |= ((desc->timestamp_96b[1] & 0xffff0000) >> 16);

	ns = second * NSEC_PER_SEC + tmp;

	return ns;
}

static enum dma_status altera_msgdma_tx_status(struct dma_chan *chan,
					       dma_cookie_t cookie,
					       struct dma_tx_state *state)
{
	struct altera_msgdma_private *priv;
	enum dma_status status;
	unsigned long flags;
	u32 pending = 0, ring_size;

	priv = chantopriv(chan);
	ring_size = priv->chan_ring_size;
	status = dma_cookie_status(chan, cookie, state);

	spin_lock_irqsave(&priv->dma_lock, flags);

	if (priv->dma_paused)
		status = DMA_PAUSED;

	if (state) {
		pending = (priv->pref_prod - priv->pref_cons + ring_size) % ring_size;
		state->residue = pending;
	}

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	return status;
}

static struct dma_async_tx_descriptor *
msgdma_pref_tx_buffer(struct altera_msgdma_private *priv,
		      struct altera_msgdma_buffer *buffer)
{
	struct msgdma_pref_extended_desc *tx_descs = priv->pref_desc;
	unsigned long flags;
	u32 desc_entry;

	spin_lock_irqsave(&priv->dma_lock, flags);

	desc_entry = (priv->pref_prod + priv->pref_pending) % priv->chan_ring_size;

	if (unlikely(tx_descs[desc_entry].desc_control
		     & MSGDMA_PREF_DESC_CTL_OWNED_BY_HW)) {
		spin_unlock_irqrestore(&priv->dma_lock, flags);
		dev_err(priv->dma_dev.dev,
			"Tx: desc_entry %d MSGDMA_PREF_DESC_CTL_OWNED_BY_HW set", desc_entry);

		return NULL;
	}

	tx_descs[desc_entry].len = buffer->len;
	tx_descs[desc_entry].read_addr_lo = lower_32_bits(buffer->dma_addr);
	tx_descs[desc_entry].read_addr_hi = upper_32_bits(buffer->dma_addr);
	tx_descs[desc_entry].stride = MSGDMA_DESC_TX_STRIDE;

	priv->async_tx[desc_entry].flags = buffer->flags;

	tx_descs[desc_entry].desc_control = MSGDMA_DESC_CTL_TX_SINGLE;

	/*
	 * client can decide to allocate multiple buffers before requesting communication
	 * with slave so we need to keep note of how many buffers available to be
	 * owned by Hardware
	 */
	priv->pref_pending++;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	return &priv->async_tx[desc_entry];
}

static struct dma_async_tx_descriptor *
msgdma_pref_add_rx_desc(struct altera_msgdma_private *priv,
			struct altera_msgdma_buffer *rxbuffer)
{
	struct msgdma_pref_extended_desc *rx_descs = priv->pref_desc;
	unsigned long flags;
	u32 desc_entry;

	spin_lock_irqsave(&priv->dma_lock, flags);

	desc_entry = (priv->pref_prod + priv->pref_pending) % priv->chan_ring_size;

	if (unlikely(rx_descs[desc_entry].desc_control
		     & MSGDMA_PREF_DESC_CTL_OWNED_BY_HW)) {
		spin_unlock_irqrestore(&priv->dma_lock, flags);
		dev_err(priv->dma_dev.dev,
			"Rx: desc_entry %d MSGDMA_PREF_DESC_CTL_OWNED_BY_HW set", desc_entry);

		return NULL;
	}

	rx_descs[desc_entry].len = rxbuffer->len;
	rx_descs[desc_entry].write_addr_lo = lower_32_bits(rxbuffer->dma_addr);
	rx_descs[desc_entry].write_addr_hi = upper_32_bits(rxbuffer->dma_addr);
	rx_descs[desc_entry].stride = MSGDMA_DESC_RX_STRIDE;

	rx_descs[desc_entry].desc_control = (MSGDMA_DESC_CTL_END_ON_EOP  |
					     MSGDMA_DESC_CTL_END_ON_LEN  |
					     MSGDMA_DESC_CTL_TR_COMP_IRQ |
					     MSGDMA_DESC_CTL_EARLY_IRQ   |
					     MSGDMA_DESC_CTL_TR_ERR_IRQ  |
					     MSGDMA_DESC_CTL_GO);

	/*
	 * client can decide to allocate multiple buffers before requesting communication
	 * with slave so we need to keep note of how many buffers available to be
	 * owned by Hardware
	 */
	priv->pref_pending++;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	return &priv->async_tx[desc_entry];
}

/**
 * altera_msgdma_prep_slave_sg - Prepare a single-buffer slave DMA transaction
 * @dchan: DMA channel to use for the transaction
 * @sgl: Pointer to the scatterlist array describing the buffer
 * @sg_len: Number of entries in the scatterlist (must be 1)
 * @dir: Direction of transfer (DMA_MEM_TO_DEV or DMA_DEV_TO_MEM)
 * @dma_flags: Transaction control flags (DMA_CTRL_ACK, DMA_PREP_INTERRUPT, etc.)
 * @context: Optional context pointer for driver-specific use
 *
 * Scatter-gather is not supported; only a single buffer is accepted.
 *
 * Return: Pointer to dma_async_tx_descriptor if successful, or NULL on failure.
 */
static struct dma_async_tx_descriptor *
altera_msgdma_prep_slave_sg(struct dma_chan *dchan,
			    struct scatterlist *sgl,
			    unsigned int sg_len,
			    enum dma_transfer_direction dir,
			    unsigned long dma_flags, void *context)
{
	struct dma_async_tx_descriptor *client_desc;
	struct altera_msgdma_private *priv;
	struct altera_msgdma_buffer buf;

	priv = chantopriv(dchan);
	client_desc = NULL;

	if (!sgl || sg_len != 1 ||
	    (dir != DMA_MEM_TO_DEV && dir != DMA_DEV_TO_MEM) ||
	    sg_dma_len(&sgl[0]) > MSGDMA_MAX_TRANS_LEN ||
	    altera_free_desc_available(priv) < 1)
		return NULL;

	buf.dma_addr = sg_dma_address(&sgl[0]);
	buf.len = sg_dma_len(&sgl[0]);
	buf.flags = 0;

	if (dir == DMA_MEM_TO_DEV)
		client_desc = msgdma_pref_tx_buffer(priv, &buf);
	else
		client_desc = msgdma_pref_add_rx_desc(priv, &buf);

	/* The DMA flags set by the client is set on the dma descriptors */
	if (client_desc)
		client_desc->flags = dma_flags;

	return client_desc;
}

static void copy_metadata_info(struct msgdma_pref_extended_desc *desc,
			       struct dma_metadata *metadata)
{
	metadata->timestamp_u64 = timestamp_to_ns(desc);
	metadata->transfer_len = desc->bytes_transferred;
}

static void msgdma_tasklet_cb(struct tasklet_struct *t)
{
	struct altera_msgdma_private *priv = from_tasklet(priv, t, tasklet_on_irq);
	struct dmaengine_result dma_result = {.result = DMA_TRANS_NOERROR};
	struct msgdma_pref_extended_desc *desc = priv->pref_desc;
	u32 chan_ring_size = priv->chan_ring_size;
	struct dma_async_tx_descriptor *async_tx;
	struct dma_metadata *metadata = NULL;
	u64 ix = priv->pref_cons;
	u64 snap_prod = 0;
	u32 real_cons = 0;
	bool is_irq_set = false;

	async_tx = priv->async_tx;

	snap_prod = priv->pref_prod;

	while (ix < snap_prod) {
		real_cons = ix++ % chan_ring_size;

		if (!(desc[real_cons].desc_control & MSGDMA_PREF_DESC_CTL_OWNED_BY_HW)) {
			metadata = &priv->dma_metadata[real_cons];

			copy_metadata_info(&desc[real_cons], metadata);

			dma_cookie_complete(&async_tx[real_cons]);

			if (async_tx[real_cons].flags & DMA_PREP_INTERRUPT)
				dmaengine_desc_get_callback_invoke(&async_tx[real_cons],
								   &dma_result);

			async_tx[real_cons].callback = NULL;
			async_tx[real_cons].callback_result = NULL;
			async_tx[real_cons].callback_param = NULL;
			async_tx[real_cons].flags = 0;
			priv->pref_cons++;
		} else {
			/* buffer comsumption happens serially */
			break;
		}
	}

	/*
	 * this is to cater to the narrow case where the above loop of callback handler is over
	 * and packet arrives. We can save on an IRQ generation
	 */
	is_irq_set = dma_bit_is_set(priv->pref_csr,
				    msgdma_pref_csroffs(status), MSGDMA_PREF_STAT_IRQ);

	if (is_irq_set) {
		altera_msgdma_pref_clear_irq(priv);
		tasklet_hi_schedule(&priv->tasklet_on_irq);
	} else {
		enable_irq(priv->irq);
	}
}

static void altera_msgdma_issue_pending(struct dma_chan *chan)
{
	struct msgdma_pref_extended_desc *desc;
	struct altera_msgdma_private *priv;
	unsigned long flags;
	u32 chan_ring_size;
	u32 idx = 0;

	priv = chantopriv(chan);
	desc = priv->pref_desc;
	chan_ring_size = priv->chan_ring_size;

	spin_lock_irqsave(&priv->dma_lock, flags);

	/* for all the descriptor buffers allocated but not used by hw, set hardware as owner */
	for (int ix = 0, pend_transfer = priv->pref_pending; ix < pend_transfer; ix++) {
		idx = priv->pref_prod % chan_ring_size;

		dma_wmb();

		desc[idx].desc_control |= MSGDMA_PREF_DESC_CTL_OWNED_BY_HW;

		priv->pref_prod++;
		priv->pref_pending--;
	}

	spin_unlock_irqrestore(&priv->dma_lock, flags);
}

static int altera_msgdma_alloc_chan_resources(struct dma_chan *dchan)
{
	struct altera_msgdma_private *priv;

	priv = chantopriv(dchan);

	altera_msgdma_pref_reset(priv);
	altera_msgdma_dmaintr_disable(priv);

	altera_msgdma_pref_start_dma(priv);
	enable_irq(priv->irq);

	tasklet_enable(&priv->tasklet_on_irq);

	altera_msgdma_dmaintr_enable(priv);
	priv->dma_paused = false;

	return 0;
}

static int altera_msgdma_device_pause(struct dma_chan *chan)
{
	struct altera_msgdma_private *priv;
	unsigned long flags;

	priv = chantopriv(chan);

	if (priv->dma_paused)
		return 0;

	altera_msgdma_dmaintr_disable(priv);

	tasklet_disable(&priv->tasklet_on_irq);

	spin_lock_irqsave(&priv->dma_lock, flags);

	dma_clear_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		      MSGDMA_PREF_CTL_RUN | MSGDMA_PREF_CTL_DESC_POLL_EN);

	priv->dma_paused = true;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	return 0;
}

static int altera_msgdma_device_resume(struct dma_chan *chan)
{
	struct altera_msgdma_private *priv;
	unsigned long flags;

	priv = chantopriv(chan);

	if (!priv->dma_paused)
		return 0;

	spin_lock_irqsave(&priv->dma_lock, flags);

	dma_clear_bit(priv->dma_csr, msgdma_csroffs(control),
		      MSGDMA_CSR_CTL_STOP_DESCS);
	dma_set_bit(priv->pref_csr, msgdma_pref_csroffs(control),
		    MSGDMA_PREF_CTL_RUN | MSGDMA_PREF_CTL_DESC_POLL_EN);

	altera_msgdma_dmaintr_enable(priv);
	priv->dma_paused = false;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	tasklet_enable(&priv->tasklet_on_irq);

	return 0;
}

static void altera_msgdma_slave_caps(struct dma_chan *dchan,
				     struct dma_slave_caps *caps)
{
	struct altera_msgdma_private *priv;

	priv = chantopriv(dchan);

	caps->directions =  BIT(DMA_MEM_TO_DEV) |
			    BIT(DMA_DEV_TO_MEM);

	caps->src_addr_widths = BIT(DMA_SLAVE_BUSWIDTH_4_BYTES) |
				BIT(DMA_SLAVE_BUSWIDTH_8_BYTES);

	caps->dst_addr_widths = BIT(DMA_SLAVE_BUSWIDTH_4_BYTES) |
				BIT(DMA_SLAVE_BUSWIDTH_8_BYTES);

	caps->residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR;
	caps->descriptor_reuse = false;
	caps->cmd_pause = true;
	caps->min_burst = 1;
	caps->max_burst = priv->prefetch_capability;
	caps->max_sg_burst = SG_NO_SUPPORT;
}

static int altera_msgdma_device_terminate_all(struct dma_chan *dchan)
{
	struct msgdma_pref_extended_desc *desc;
	struct altera_msgdma_private *priv;
	unsigned long flags;

	priv = chantopriv(dchan);
	desc = priv->pref_desc;

	altera_msgdma_dmaintr_disable(priv);
	disable_irq_nosync(priv->irq);

	altera_msgdma_pref_reset(priv);

	spin_lock_irqsave(&priv->dma_lock, flags);

	priv->dma_paused = true;

	for (u64 ix = 0; ix < priv->chan_ring_size; ix++) {
		desc[ix].desc_control = 0;
		msgdma_desc_free(&priv->async_tx[ix]);
	}

	priv->pref_prod = 0;
	priv->pref_cons = 0;
	priv->pref_pending = 0;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	return 0;
}

static void altera_msgdma_synchronize(struct dma_chan *dchan)
{
	struct dmaengine_result dma_result = {.result = DMA_TRANS_ABORTED};
	struct dma_async_tx_descriptor *async_tx;
	struct msgdma_pref_extended_desc *desc;
	struct altera_msgdma_private *priv;
	struct dma_async_tx_descriptor *tx;
	unsigned long flags;
	u32 real_cons = 0;
	u32 pend_idx = 0;

	priv = chantopriv(dchan);
	desc = priv->pref_desc;
	async_tx = priv->async_tx;

	tasklet_disable(&priv->tasklet_on_irq);

	spin_lock_irqsave(&priv->dma_lock, flags);

	/* handle the packets which has been processed but callbacks has not beed called yet */
	for (u64 ix = priv->pref_cons; ix < priv->pref_prod; ix++, priv->pref_cons++) {
		real_cons = ix % priv->chan_ring_size;
		tx = &async_tx[real_cons];

		if (!(desc[real_cons].desc_control & MSGDMA_PREF_DESC_CTL_OWNED_BY_HW)) {
			if (tx->callback_result && tx->flags & DMA_PREP_INTERRUPT)
				tx->callback_result(tx->callback_param, &dma_result);
		}
	}

	for (u32 ix = 0; ix < priv->pref_pending; ix++) {
		pend_idx = (priv->pref_prod + ix) % priv->chan_ring_size;
		tx = &async_tx[pend_idx];

		if (tx->callback_result && tx->flags & DMA_PREP_INTERRUPT)
			tx->callback_result(tx->callback_param, &dma_result);
	}

	priv->pref_pending = 0;

	spin_unlock_irqrestore(&priv->dma_lock, flags);

	tasklet_enable(&priv->tasklet_on_irq);
}

static void altera_msgdma_free_chan_resources(struct dma_chan *chan)
{
	struct altera_msgdma_private *priv = chantopriv(chan);

	altera_msgdma_device_terminate_all(chan);
	tasklet_disable(&priv->tasklet_on_irq);
}

static void altera_msgdma_remove(struct platform_device *pdev)
{
	struct altera_msgdma_private *priv;

	priv = platform_get_drvdata(pdev);

	if (pdev->dev.of_node)
		of_dma_controller_free(pdev->dev.of_node);

	altera_msgdma_device_terminate_all(&priv->dma_chan);
	altera_msgdma_synchronize(&priv->dma_chan);
	altera_msgdma_free_chan_resources(&priv->dma_chan);
	tasklet_kill(&priv->tasklet_on_irq);
	dma_async_device_unregister(&priv->dma_dev);
}

static inline int altera_msgdma_registration(struct platform_device *pdev)
{
	struct altera_msgdma_private *priv;
	int ret = 0;

	priv = platform_get_drvdata(pdev);

	dma_cookie_init(&priv->dma_chan);
	dma_cap_zero(priv->dma_dev.cap_mask);
	dma_cap_set(DMA_SLAVE, priv->dma_dev.cap_mask);

	priv->dma_dev.directions =  BIT(DMA_MEM_TO_DEV) |
				    BIT(DMA_DEV_TO_MEM);

	priv->dma_dev.max_sg_burst = SG_NO_SUPPORT;

	INIT_LIST_HEAD(&priv->dma_dev.channels);

	priv->dma_chan.device = &priv->dma_dev;
	priv->dma_dev.dev = &pdev->dev;
	priv->dma_chan.slave = &pdev->dev;
	list_add_tail(&priv->dma_chan.device_node, &priv->dma_dev.channels);

	priv->dma_dev.desc_metadata_modes = DESC_METADATA_ENGINE;
	priv->dma_dev.device_alloc_chan_resources = altera_msgdma_alloc_chan_resources;
	priv->dma_dev.device_free_chan_resources = altera_msgdma_free_chan_resources;
	priv->dma_dev.device_config = altera_msgdma_config;
	priv->dma_dev.device_prep_slave_sg = altera_msgdma_prep_slave_sg;
	priv->dma_dev.device_tx_status = altera_msgdma_tx_status;
	priv->dma_dev.device_issue_pending = altera_msgdma_issue_pending;
	priv->dma_dev.device_pause = altera_msgdma_device_pause;
	priv->dma_dev.device_resume = altera_msgdma_device_resume;
	priv->dma_dev.device_synchronize = altera_msgdma_synchronize;
	priv->dma_dev.device_terminate_all = altera_msgdma_device_terminate_all;
	priv->dma_dev.device_caps =  altera_msgdma_slave_caps;
	priv->dma_dev.copy_align = DMAENGINE_ALIGN_4_BYTES;

	ret = dma_async_device_register(&priv->dma_dev);
	if (ret) {
		dev_err(&pdev->dev, "dma async device register failed!\n");
		return ret;
	}

	ret = of_dma_controller_register(pdev->dev.of_node,
					 of_dma_xlate_by_chan_id,
					 (struct dma_device *)&priv->dma_dev);
	if (ret) {
		dev_warn(&pdev->dev, "DMA controller registration failed\n");
		dma_async_device_unregister(&priv->dma_dev);
		return ret;
	}

	return 0;
}

static irqreturn_t altera_msgdma_isr_handler(int irq, void *dev_id)
{
	struct altera_msgdma_private *priv;
	struct dma_chan *dchan = dev_id;

	priv = chantopriv(dchan);

	disable_irq_nosync(priv->irq);

	altera_msgdma_pref_clear_irq(priv);

	tasklet_hi_schedule(&priv->tasklet_on_irq);

	return IRQ_HANDLED;
}

static int altera_msgdma_dts_config(struct platform_device *pdev)
{
	struct altera_msgdma_private *priv;
	struct device_node *dmanp;
	struct resource *dma_res;
	const char *chan_name;
	int ret = 0;

	priv = platform_get_drvdata(pdev);

	dmanp = pdev->dev.of_node;

	priv->irq = platform_get_irq_byname(pdev, "dma-irq");
	if (priv->irq < 0)
		return priv->irq;

	ret = altera_request_and_map(pdev, "dma_csr", &dma_res,
				     (void __iomem **)(&priv->dma_csr));
	if (ret)
		return ret;

	ret = altera_request_and_map(pdev, "pref_csr", &dma_res,
				     (void __iomem **)(&priv->pref_csr));
	if (ret)
		return ret;

	if (of_property_read_u32(dmanp, "fifo-depth", &priv->fifo_depth)) {
		dev_info(&pdev->dev, "cannot obtain fifo-depth\n");
		priv->fifo_depth = 0x4000;
	}

	if (of_property_read_u32(dmanp, "fifo-almost-full", &priv->fifo_almost_full)) {
		dev_info(&pdev->dev, "cannot obtain fifo-almost-full\n");
		priv->fifo_almost_full = 0x4000;
	}

	if (of_property_read_u32(dmanp, "fifo-almost-empty", &priv->fifo_almost_empty)) {
		dev_info(&pdev->dev, "cannot obtain fifo-almost-empty\n");
		priv->fifo_almost_empty = 0x3000;
	}

	if (of_property_read_u32(dmanp, "poll-freq", &priv->chan_poll_freq)) {
		dev_info(&pdev->dev, "Defaulting Poll Frequency to 128\n");
		priv->chan_poll_freq = 128;
	}

	ret = altera_request_and_map(pdev, "fifo_info", &dma_res,
				     (void __iomem **)(&priv->fifo_info));

	if (ret)
		return ret;

	dma_write(priv->fifo_almost_full, priv->fifo_info,
		  fifo_csroffs(almost_full_threshold));

	dma_write(priv->fifo_almost_empty, priv->fifo_info,
		  fifo_csroffs(almost_empty_threshold));

	if (of_property_read_u32(dmanp, "prefetch-capability",
				 &priv->prefetch_capability)) {
		dev_info(&pdev->dev, "cannot obtain pref capability defaulting\n");
		priv->prefetch_capability = 0x10;
	}

	if (!of_property_read_string(dmanp, "channel-name", &chan_name))
		priv->dma_chan.name = devm_kstrdup(&pdev->dev, chan_name, GFP_KERNEL);
	else
		priv->dma_chan.name = devm_kstrdup(&pdev->dev,
						   dev_name(&pdev->dev), GFP_KERNEL);

	return 0;
}

static int altera_msgdma_probe(struct platform_device *pdev)
{
	struct altera_msgdma_private *priv;
	const char *chan_name = NULL;
	int ret = -ENOMEM;

	priv = devm_kzalloc(&pdev->dev, sizeof(struct altera_msgdma_private),
			    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	platform_set_drvdata(pdev, priv);

	priv->msg_enable = msgdma_debug_level;
	if (!msgdma_debug_level)
		priv->msg_enable = dma_msg_init(DMA_MSG_DEFAULT);

	spin_lock_init(&priv->dma_lock);

	/*
	 * we need to allocate more pref descriptors than ringsize to
	 * prevent all of the descriptors being owned by hw.  To do this
	 * we just allocate twice ring_size descriptors.
	 */
	priv->chan_ring_size = DMA_RING_SIZE;

	ret = altera_msgdma_dts_config(pdev);
	if (ret) {
		dev_err(&pdev->dev, "DMA basic DTS entry are missing\n");
		return ret;
	}

	ret = altera_msgdma_registration(pdev);
	if (ret) {
		dev_err(&pdev->dev, "DMA engine registration failed\n");
		return ret;
	}

	ret = devm_request_irq(priv->dma_dev.dev, priv->irq,
			       altera_msgdma_isr_handler,
			       IRQF_SHARED,  priv->dma_chan.name,
			       &priv->dma_chan);

	if (ret) {
		if (pdev->dev.of_node)
			of_dma_controller_free(pdev->dev.of_node);
		dma_async_device_unregister(&priv->dma_dev);
		dev_err(&pdev->dev, "Unable to register interrupt %d\n", priv->irq);
		return ret;
	}

	disable_irq_nosync(priv->irq);

	chan_name = dev_name(priv->dma_dev.dev);

	tasklet_setup(&priv->tasklet_on_irq, msgdma_tasklet_cb);
	tasklet_disable(&priv->tasklet_on_irq);

	ret = msgdma_pref_initialize(priv);
	if (ret) {
		if (pdev->dev.of_node)
			of_dma_controller_free(pdev->dev.of_node);
		dma_async_device_unregister(&priv->dma_dev);
		dev_err(&pdev->dev, "Failure in pref initialization err(%x)\n", ret);
		return ret;
	}

	if (dma_msg_probe(priv))
		dev_info(&pdev->dev, "%s channel ready to operate", chan_name);

	return 0;
}

static const struct of_device_id altera_msgdma_match[] = {
	{ .compatible = "altr,socfpga-pref-msgdma",
	},
	{ }
};

MODULE_DEVICE_TABLE(of, altera_msgdma_match);

static struct platform_driver msgdma_driver = {
	.driver = {
		.name = "altera-msgdma",
		.of_match_table = of_match_ptr(altera_msgdma_match),
	},
	.probe = altera_msgdma_probe,
	.remove = altera_msgdma_remove,
};

module_platform_driver(msgdma_driver);

MODULE_ALIAS("altera-msgdma");
MODULE_AUTHOR("SED-TEAM: psse-ba-sed@altera.com");
MODULE_DESCRIPTION("Altera mSGDMA pref driver");
MODULE_LICENSE("GPL");
