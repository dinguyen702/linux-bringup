// SPDX-License-Identifier: GPL-2.0
/*
 * SoCFPGA hardware monitoring features
 *
 * Copyright (c) 2023 Intel Corporation. All rights reserved
 */
#include <linux/arm-smccc.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/firmware/intel/stratix10-svc-client.h>
#include <linux/of.h>
#include <linux/platform_device.h>

#define HWMON_TIMEOUT	msecs_to_jiffies(SVC_HWMON_REQUEST_TIMEOUT_MS)

#define ETEMP_INACTIVE			0x80000000
#define ETEMP_TOO_OLD			0x80000001
#define ETEMP_NOT_PRESENT		0x80000002
#define ETEMP_TIMEOUT			0x80000003
#define ETEMP_CORRUPT			0x80000004
#define ETEMP_BUSY			0x80000005
#define ETEMP_NOT_INITIALIZED		0x800000FF

#define SOCFPGA_HWMON_MAXSENSORS	16

struct socfpga_hwmon_priv {
	struct stratix10_svc_client client;
	struct stratix10_svc_chan *chan;
	struct completion completion;
	struct mutex lock;
	int temperature;
	int voltage;
	int temperature_channels;
	int voltage_channels;
	const char *socfpga_volt_chan_names[SOCFPGA_HWMON_MAXSENSORS];
	const char *socfpga_temp_chan_names[SOCFPGA_HWMON_MAXSENSORS];
	u32 socfpga_volt_chan[SOCFPGA_HWMON_MAXSENSORS];
	u32 socfpga_temp_chan[SOCFPGA_HWMON_MAXSENSORS];
};

enum hwmon_type_op {
	SOCFPGA_HWMON_TEMPERATURE,
	SOCFPGA_HWMON_VOLTAGE,
	SOCFPGA_HWMON_TYPE_MAX
};

static const char *const hwmon_types_str[] = { "temperature", "voltage" };

static umode_t socfpga_is_visible(const void *dev,
				  enum hwmon_sensor_types type,
				  u32 attr, int chan)
{
	const struct socfpga_hwmon_priv *priv = dev;

	switch (type) {
	case hwmon_temp:
		if (chan < priv->temperature_channels)
			break;
		return 0444;
	case hwmon_in:
		if (chan < priv->voltage_channels)
			break;
		return 0444;
	default:
		break;
	}
	return 0;
}

static void socfpga_readtemp_smc_callback(struct stratix10_svc_client *client,
					  struct stratix10_svc_cb_data *data)
{
	struct socfpga_hwmon_priv *priv = client->priv;
	struct arm_smccc_res *res = data->kaddr1;

	if (data->status == BIT(SVC_STATUS_OK))
		priv->temperature = res->a0;
	else
		dev_err(client->dev, "%s returned 0x%lX\n", __func__, res->a0);

	complete(&priv->completion);
}

static void socfpga_readvolt_smc_callback(struct stratix10_svc_client *client,
					  struct stratix10_svc_cb_data *data)
{
	struct socfpga_hwmon_priv *priv = client->priv;
	struct arm_smccc_res *res = data->kaddr1;

	if (data->status == BIT(SVC_STATUS_OK))
		priv->voltage = res->a0;
	else
		dev_err(client->dev, "%s returned 0x%lX\n", __func__, res->a0);

	complete(&priv->completion);
}

static int socfpga_read(struct device *dev, enum hwmon_sensor_types type,
			u32 attr, int chan, long *val)
{
	struct socfpga_hwmon_priv *priv = dev_get_drvdata(dev);
	struct stratix10_svc_client_msg msg;
	int ret;

	mutex_lock(&priv->lock);
	reinit_completion(&priv->completion);

	switch (type) {
	case hwmon_temp:
		if (chan > 15)
			return -EOPNOTSUPP;

		msg.arg[0] = BIT_ULL(priv->socfpga_temp_chan[chan]);
		priv->client.receive_cb = socfpga_readtemp_smc_callback;
		msg.command = COMMAND_HWMON_READTEMP;

		ret = stratix10_svc_send(priv->chan, &msg);
		if (ret < 0)
			goto status_done;

		ret = wait_for_completion_interruptible_timeout(
			&priv->completion, HWMON_TIMEOUT);
		if (ret < 0) {
			dev_err(priv->client.dev, "error %d waiting for SMC call\n", ret);
			goto status_done;
		} else if (!ret) {
			dev_err(priv->client.dev, "timeout waiting for SMC call\n");
			ret = -ETIMEDOUT;
			goto status_done;
		}

		*val = (priv->temperature * 1000) / 256;
		switch (priv->temperature) {
		case ETEMP_INACTIVE:
		case ETEMP_NOT_PRESENT:
		case ETEMP_CORRUPT:
		case ETEMP_NOT_INITIALIZED:
			ret = -EOPNOTSUPP;
			break;
		case ETEMP_TIMEOUT:
		case ETEMP_BUSY:
		case ETEMP_TOO_OLD:
			ret = -EAGAIN;
			break;
		default:
			ret = 0;
			break;
		}
		break;
	case hwmon_in: /* Read voltage */
		if (chan > 15)
			return -EOPNOTSUPP;

		msg.arg[0] = BIT_ULL(priv->socfpga_volt_chan[chan]);
		priv->client.receive_cb = socfpga_readvolt_smc_callback;
		msg.command = COMMAND_HWMON_READVOLT;

		ret = stratix10_svc_send(priv->chan, &msg);
		if (ret < 0)
			goto status_done;

		ret = wait_for_completion_interruptible_timeout(
			&priv->completion, HWMON_TIMEOUT);
		if (ret < 0) {
			dev_err(priv->client.dev, "error %d waiting for SMC call\n", ret);
			goto status_done;
		} else if (!ret) {
			dev_err(priv->client.dev, "timeout waiting for SMC call\n");
			ret = -ETIMEDOUT;
			goto status_done;
		}

		*val = (priv->voltage * 1000) / 65536;
		ret = 0;
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
		*str = priv->socfpga_volt_chan_names[chan];
		return 0;
	case hwmon_temp:
		*str = priv->socfpga_temp_chan_names[chan];
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

static void socfpga_add_channel(struct device *dev,  const char *type,
				u32 val, const char *label,
				struct socfpga_hwmon_priv *priv)
{
	int type_index;

	type_index = match_string(hwmon_types_str, ARRAY_SIZE(hwmon_types_str),
				  type);
	switch(type_index) {
	case SOCFPGA_HWMON_TEMPERATURE:
		if (priv->temperature_channels >= SOCFPGA_HWMON_MAXSENSORS) {
			dev_warn(dev,
				"Cannot add temp node %s, too many channels",
				label);
			break;
		}
		priv->socfpga_temp_chan_names[priv->temperature_channels] = label;
		priv->socfpga_temp_chan[priv->temperature_channels] = val;
		priv->temperature_channels++;
		break;
	case SOCFPGA_HWMON_VOLTAGE:
		if (priv->voltage_channels >= SOCFPGA_HWMON_MAXSENSORS) {
			dev_warn(dev,
				"Cannot add voltage node %s, too many channels",
				label);
			break;
		}
		priv->socfpga_volt_chan_names[priv->voltage_channels] = label;
		priv->socfpga_volt_chan[priv->voltage_channels] = val;
		priv->voltage_channels++;
		break;
	default:
		dev_warn(dev, "unsupported sensor type %s", type);
		break;
	}
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

	of_property_read_string(child, "name", &type);
	for_each_child_of_node(child, grandchild) {
		ret = of_property_read_u32(grandchild, "reg", &val);
		if (ret) {
			dev_err(dev, "missing reg property of %pOFn\n",
				grandchild);
			return ret;
		}
		ret = of_property_read_string(grandchild, "label",
				&label);
		if (ret) {
			dev_err(dev, "missing label propoerty of %pOFn\n",
				grandchild);
			return ret;
		}
		socfpga_add_channel(dev, type, val, label, priv);
	}
	return 0;
}

static int socfpga_probe_from_dt(struct device *dev,
				 struct socfpga_hwmon_priv *priv)
{
	const struct device_node *np = dev->of_node;
	struct device_node *child;
	int ret;

	for_each_child_of_node(np, child) {
		ret = socfpga_probe_child_from_dt(dev, child, priv);
		if (ret) {
			of_node_put(child);
			return ret;
		}
	}
	return 0;
}

static int socfpga_hwmon_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device *hwmon_dev;
	struct socfpga_hwmon_priv *priv;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->client.dev = dev;
	priv->client.receive_cb = NULL;
	priv->client.priv = priv;

	ret = socfpga_probe_from_dt(dev, priv);
	if (ret)
		return dev_err_probe(dev, ret, "Unable to probe from device tree\n");

	mutex_init(&priv->lock);
	init_completion(&priv->completion);
	hwmon_dev = devm_hwmon_device_register_with_info(dev, "socfpgahwmon",
							 priv,
							 &socfpga_chip_info,
							 NULL);
	if (IS_ERR(hwmon_dev))
		return PTR_ERR(hwmon_dev);

	priv->chan = stratix10_svc_request_channel_byname(&priv->client,
					SVC_CLIENT_HWMON);
	if (IS_ERR(priv->chan))
		return dev_err_probe(dev, PTR_ERR(priv->chan), "couldn't get service channel %s\n", SVC_CLIENT_RSU);

	platform_set_drvdata(pdev, priv);

	return 0;
}

static int socfpga_hwmon_remove(struct platform_device *pdev)
{
	struct socfpga_hwmon_priv *priv = platform_get_drvdata(pdev);

	devm_hwmon_device_unregister(priv->client.dev);
	stratix10_svc_free_channel(priv->chan);
	return 0;
}

static const struct of_device_id socfpga_of_match[] = {
	{ .compatible = "intel,socfpga-hwmon" },
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
