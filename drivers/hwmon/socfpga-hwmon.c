// SPDX-License-Identifier: GPL-2.0-only
/*
 * SoCFPGA hardware monitoring features
 *
 * Copyright (c) 2023 Intel Corporation. All rights reserved
 */
#include <linux/arm-smccc.h>
#include <linux/hwmon.h>
#include <linux/firmware/intel/stratix10-svc-client.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/units.h>

#define HWMON_TIMEOUT	msecs_to_jiffies(SVC_HWMON_REQUEST_TIMEOUT_MS)

/*
 * Selected temperature sensor channel is currently inactive.
 * Ensure that the tile where the TSD is located is actively in use.
 */
#define ETEMP_INACTIVE		0
/*
 * Selected temperature sensor channel returned a value that is not the
 * latest reading. Try retrieve the temperature reading again.
 */
#define ETEMP_TOO_OLD		1
/*
 * Selected temperature sensor channel is invalid for the device. Ignore
 * the returned data because the temperature sensor channel location is
 * invalid.
 */
#define ETEMP_NOT_PRESENT	2
/*
 * System is corrupted or failed to respond.
 */
#define ETEMP_TIMEOUT		3
#define ETEMP_CORRUPT		4
/*
 * Communication mechanism is busy.
 */
#define ETEMP_BUSY		5
/*
 * System is corrupted or failed to respond.
 */
#define ETEMP_NOT_INITIALIZED	255

#define SOCFPGA_HWMON_ERR_MAX	-2147483648

#define SOCFPGA_HWMON_MAXSENSORS	16

/**
 * struct socfpga_hwmon_chan - channel input parameters.
 * @n : Number of channels.
 * @value: value read from the chip.
 * @names: names array from DTS labels.
 * @chan: channel array.
 *
 * The structure represents either the voltage or temperature information
 * for the hwmon channels.
 */
struct socfpga_hwmon_chan {
	unsigned int n;
	int value;
	const char *names[SOCFPGA_HWMON_MAXSENSORS];
	u32 chan[SOCFPGA_HWMON_MAXSENSORS];
};

struct socfpga_hwmon_priv {
	struct device *hwmon_dev;
	struct stratix10_svc_client client;
	struct stratix10_svc_client_msg msg;
	struct stratix10_svc_chan *chan;
	struct completion completion;
	struct mutex lock; /* lock for reading the hardware volts/temps */
	struct socfpga_hwmon_chan temperature;
	struct socfpga_hwmon_chan voltage;
};

enum hwmon_type_op {
	SOCFPGA_HWMON_TYPE_TEMP,
	SOCFPGA_HWMON_TYPE_VOLT
};

static const char *const hwmon_types_str[] = { "temperature", "voltage" };

static umode_t socfpga_is_visible(const void *dev,
				  enum hwmon_sensor_types type,
				  u32 attr, int chan)
{
	switch (type) {
	case hwmon_temp:
	case hwmon_in:
		return 0444;
	default:
		return 0;
	}
}

static void socfpga_smc_callback(struct stratix10_svc_client *client,
				 struct stratix10_svc_cb_data *data)
{
	struct socfpga_hwmon_priv *priv = client->priv;
	struct arm_smccc_res *res = data->kaddr1;

	if (data->status == BIT(SVC_STATUS_OK))	{
		if (priv->msg.command == COMMAND_HWMON_READTEMP)
			priv->temperature.value = res->a0;
		else
			priv->voltage.value = res->a0;
	} else {
		dev_err(client->dev, "%s returned 0x%lX\n", __func__, res->a0);
	}

	complete(&priv->completion);
}

static int socfpga_hwmon_send(struct socfpga_hwmon_priv *priv)
{
	int ret;

	priv->client.receive_cb = socfpga_smc_callback;

	ret = stratix10_svc_send(priv->chan, &priv->msg);
	if (ret < 0)
		return ret;

	if (!wait_for_completion_timeout(&priv->completion, HWMON_TIMEOUT)) {
		dev_err(priv->client.dev, "SMC call timeout!\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int socfpga_hwmon_err_to_errno(struct socfpga_hwmon_priv *priv)
{
	int value = priv->temperature.value;
	int err;

	if (value >= SOCFPGA_HWMON_ERR_MAX)
		return 0;

	err = abs(SOCFPGA_HWMON_ERR_MAX - value);
	switch (err) {
	case ETEMP_NOT_PRESENT:
		return -ENOENT;
	case ETEMP_CORRUPT:
	case ETEMP_NOT_INITIALIZED:
		return -ENODATA;
	case ETEMP_BUSY:
		return -EBUSY;
	case ETEMP_INACTIVE:
	case ETEMP_TIMEOUT:
	case ETEMP_TOO_OLD:
		return -EAGAIN;
	default:
		/* Unknown error */
		return -EIO;
	}
}

static int socfpga_read(struct device *dev, enum hwmon_sensor_types type,
			u32 attr, int chan, long *val)
{
	struct socfpga_hwmon_priv *priv = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&priv->lock);
	reinit_completion(&priv->completion);

	switch (type) {
	case hwmon_temp:
		priv->msg.arg[0] = BIT_ULL(priv->temperature.chan[chan]);
		priv->msg.command = COMMAND_HWMON_READTEMP;
		ret = socfpga_hwmon_send(priv);
		if (ret)
			goto status_done;

		ret = socfpga_hwmon_err_to_errno(priv);
		if (ret)
			break;
		/*
		 * The Temperature Sensor IP core returns the Celsius
		 * temperature value in signed 32-bit fixed point binary
		 * format, with eight bits below binary point.
		 */
		*val = (priv->temperature.value * MILLIDEGREE_PER_DEGREE) / 256;
		break;
	case hwmon_in:
		priv->msg.arg[0] = BIT_ULL(priv->voltage.chan[chan]);
		priv->msg.command = COMMAND_HWMON_READVOLT;
		ret = socfpga_hwmon_send(priv);
		if (ret)
			goto status_done;

		/*
		 * The Voltage Sensor IP core returns the sampled voltage
		 * in unsigned 32-bit fixed point binary format, with 16 bits
		 * below binary point.
		 */
		*val = (priv->voltage.value * MILLIVOLT_PER_VOLT) / 65536;
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

status_done:
	stratix10_svc_done(priv->chan);
	mutex_unlock(&priv->lock);
	return ret;
}

static int socfpga_read_string(struct device *dev,
			       enum hwmon_sensor_types type, u32 attr,
			       int chan, const char **str)
{
	struct socfpga_hwmon_priv *priv = dev_get_drvdata(dev);

	switch (type) {
	case hwmon_in:
		*str = priv->voltage.names[chan];
		return 0;
	case hwmon_temp:
		*str = priv->temperature.names[chan];
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct hwmon_ops socfpga_ops = {
	.is_visible = socfpga_is_visible,
	.read = socfpga_read,
	.read_string = socfpga_read_string,
};

static const struct hwmon_channel_info *socfpga_info[] = {
	HWMON_CHANNEL_INFO(temp,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL,
			   HWMON_T_INPUT | HWMON_T_LABEL, HWMON_T_INPUT | HWMON_T_LABEL),
	HWMON_CHANNEL_INFO(in,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL,
			   HWMON_I_INPUT | HWMON_I_LABEL, HWMON_I_INPUT | HWMON_I_LABEL),
	NULL
};

static const struct hwmon_chip_info socfpga_chip_info = {
	.ops = &socfpga_ops,
	.info = socfpga_info,
};

static int socfpga_add_channel(struct device *dev,  const char *type,
			       u32 val, const char *label,
			       struct socfpga_hwmon_priv *priv)
{
	int type_index;
	struct socfpga_hwmon_chan *p;

	type_index = match_string(hwmon_types_str, ARRAY_SIZE(hwmon_types_str), type);
	switch (type_index) {
	case SOCFPGA_HWMON_TYPE_TEMP:
		p = &priv->temperature;
		break;
	case SOCFPGA_HWMON_TYPE_VOLT:
		p = &priv->voltage;
		break;
	default:
		return -ENODATA;
	}
	if (p->n >= SOCFPGA_HWMON_MAXSENSORS)
		return -ENOSPC;

	p->names[p->n] = label;
	p->chan[p->n] = val;
	p->n++;

	return 0;
}

static int socfpga_probe_child_from_dt(struct device *dev,
				       struct device_node *child,
				       struct socfpga_hwmon_priv *priv)
{
	struct device_node *grandchild;
	const char *label;
	const char *type;
	u32 val;
	int ret;

	if (of_property_read_string(child, "name", &type))
		return dev_err_probe(dev, -EINVAL, "No type for %pOF\n", child);

	for_each_child_of_node(child, grandchild) {
		ret = of_property_read_u32(grandchild, "reg", &val);
		if (ret)
			return dev_err_probe(dev, ret, "missing reg property of %pOF\n",
					     grandchild);

		ret = of_property_read_string(grandchild, "label", &label);
		if (ret)
			return dev_err_probe(dev, ret, "missing label propoerty of %pOF\n",
					     grandchild);
		ret = socfpga_add_channel(dev, type, val, label, priv);
		if (ret == -ENOSPC)
			return dev_err_probe(dev, ret, "too many channels, only %d supported\n",
					     SOCFPGA_HWMON_MAXSENSORS);
	}
	return 0;
}

static int socfpga_probe_from_dt(struct device *dev,
				 struct socfpga_hwmon_priv *priv)
{
	const struct device_node *np = dev->of_node;
	struct device_node *child;
	int ret = 0;

	for_each_child_of_node(np, child) {
		ret = socfpga_probe_child_from_dt(dev, child, priv);
		if (ret)
			break;
	}
	of_node_put(child);

	return ret;
}

static int socfpga_hwmon_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct socfpga_hwmon_priv *priv;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->client.dev = dev;
	priv->client.priv = priv;

	ret = socfpga_probe_from_dt(dev, priv);
	if (ret)
		return dev_err_probe(dev, ret, "Unable to probe from device tree\n");

	mutex_init(&priv->lock);
	init_completion(&priv->completion);
	priv->chan = stratix10_svc_request_channel_byname(&priv->client,
							  SVC_CLIENT_HWMON);
	if (IS_ERR(priv->chan))
		return dev_err_probe(dev, PTR_ERR(priv->chan),
				     "couldn't get service channel %s\n",
				     SVC_CLIENT_RSU);

	priv->hwmon_dev = devm_hwmon_device_register_with_info(dev, "socfpgahwmon",
							       priv,
							       &socfpga_chip_info,
							       NULL);
	if (IS_ERR(priv->hwmon_dev))
		return PTR_ERR(priv->hwmon_dev);

	platform_set_drvdata(pdev, priv);

	return 0;
}

static int socfpga_hwmon_remove(struct platform_device *pdev)
{
	struct socfpga_hwmon_priv *priv = platform_get_drvdata(pdev);

	hwmon_device_unregister(priv->hwmon_dev);
	stratix10_svc_free_channel(priv->chan);
	return 0;
}

static const struct of_device_id socfpga_of_match[] = {
	{ .compatible = "intel,socfpga-hwmon" },
	{ .compatible = "intel,socfpga-agilex-hwmon" },
	{ .compatible = "intel,socfpga-n5x-hwmon" },
	{ .compatible = "intel,socfpga-stratix10-hwmon" },
	{}
};
MODULE_DEVICE_TABLE(of, socfpga_of_match);

static struct platform_driver socfpga_hwmon_driver = {
	.driver = {
		.name = "socfpga-hwmon",
		.of_match_table = socfpga_of_match,
	},
	.probe = socfpga_hwmon_probe,
	.remove = socfpga_hwmon_remove,
};
module_platform_driver(socfpga_hwmon_driver);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("SoCFPGA hardware monitoring features");
MODULE_LICENSE("GPL");
