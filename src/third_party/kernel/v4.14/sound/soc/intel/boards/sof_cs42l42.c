// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2021 Intel Corporation.

/*
 * Intel SOF Machine Driver with Cirrus Logic CS42L42 Codec
 * and speaker codec MAX98357A
 */
#include <asm/cpu_device_id.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/dmi.h>
#include <sound/core.h>
#include <sound/jack.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <dt-bindings/sound/cs42l42.h>
#include "../../codecs/hdac_hdmi.h"

#define NAME_SIZE 32

#define SOF_CS42L42_SSP_CODEC(quirk)		((quirk) & GENMASK(2, 0))
#define SOF_CS42L42_SSP_CODEC_MASK		(GENMASK(2, 0))
#define SOF_SPEAKER_AMP_PRESENT			BIT(3)
#define SOF_CS42L42_SSP_AMP_SHIFT		4
#define SOF_CS42L42_SSP_AMP_MASK		(GENMASK(6, 4))
#define SOF_CS42L42_SSP_AMP(quirk)	\
	(((quirk) << SOF_CS42L42_SSP_AMP_SHIFT) & SOF_CS42L42_SSP_AMP_MASK)
#define SOF_CS42L42_NUM_HDMIDEV_SHIFT		7
#define SOF_CS42L42_NUM_HDMIDEV_MASK		(GENMASK(9, 7))
#define SOF_CS42L42_NUM_HDMIDEV(quirk)	\
	(((quirk) << SOF_CS42L42_NUM_HDMIDEV_SHIFT) & SOF_CS42L42_NUM_HDMIDEV_MASK)
#define SOF_MAX98357A_SPEAKER_AMP_PRESENT	BIT(10)

/* Default: SSP2 */
static unsigned long sof_cs42l42_quirk = SOF_CS42L42_SSP_CODEC(2);

struct sof_hdmi_pcm {
	struct list_head head;
	struct snd_soc_dai *codec_dai;
	struct snd_soc_jack hdmi_jack;
	int device;
};

struct sof_card_private {
	struct snd_soc_jack headset_jack;
	struct list_head hdmi_pcm_list;
};

static int sof_hdmi_init(struct snd_soc_pcm_runtime *rtd)
{
	struct sof_card_private *ctx = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_dai *dai = rtd->codec_dai;
	struct snd_soc_dai_link *dai_link;
	struct sof_hdmi_pcm *pcm;
	int hdmi_id;
	char hdmi_name[16];

	pcm = devm_kzalloc(rtd->card->dev, sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return -ENOMEM;

	if (sscanf(rtd->dai_link->name, "iDisp%d", &hdmi_id) != 1) {
		dev_err(rtd->dev, "failed to get hdmi id\n");
		return -ENODEV;
	}

	/* dai_link id is 1:1 mapped to the PCM device */
	snprintf(hdmi_name, sizeof(hdmi_name), "HDMI%d", hdmi_id);

	for_each_card_links(rtd->card, dai_link) {
		if (dai_link->name && !strcmp(hdmi_name, dai_link->name)) {
			pcm->device = dai_link->id;
			pcm->codec_dai = dai;

			list_add_tail(&pcm->head, &ctx->hdmi_pcm_list);
			return 0;
		}
	}

	dev_err(rtd->dev, "failed to find dai link of HDMI%d\n", hdmi_id);
	return -ENODEV;
}

static int sof_cs42l42_init(struct snd_soc_pcm_runtime *rtd)
{
	struct sof_card_private *ctx = snd_soc_card_get_drvdata(rtd->card);
	struct snd_soc_component *component = rtd->codec_dai->component;
	struct snd_soc_jack *jack = &ctx->headset_jack;
	int ret;

	/*
	 * Headset buttons map to the google Reference headset.
	 * These can be configured by userspace.
	 */
	ret = snd_soc_card_jack_new(rtd->card, "Headset Jack",
				    SND_JACK_HEADSET | SND_JACK_BTN_0 |
				    SND_JACK_BTN_1 | SND_JACK_BTN_2 |
				    SND_JACK_BTN_3,
				    jack, NULL, 0);
	if (ret) {
		dev_err(rtd->dev, "Headset Jack creation failed: %d\n", ret);
		return ret;
	}

	snd_jack_set_key(jack->jack, SND_JACK_BTN_0, KEY_PLAYPAUSE);
	snd_jack_set_key(jack->jack, SND_JACK_BTN_1, KEY_VOLUMEUP);
	snd_jack_set_key(jack->jack, SND_JACK_BTN_2, KEY_VOLUMEDOWN);
	snd_jack_set_key(jack->jack, SND_JACK_BTN_3, KEY_VOICECOMMAND);

	ret = snd_soc_component_set_jack(component, jack, NULL);
	if (ret) {
		dev_err(rtd->dev, "Headset Jack call-back failed: %d\n", ret);
		return ret;
	}

	return ret;
};

static int sof_cs42l42_hw_params(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	int clk_freq, ret;

	clk_freq = 3072000; /* BCLK freq */

	/* Configure sysclk for codec */
	ret = snd_soc_dai_set_sysclk(codec_dai, 0,
				     clk_freq, SND_SOC_CLOCK_IN);
	if (ret < 0)
		dev_err(rtd->dev, "snd_soc_dai_set_sysclk err = %d\n", ret);

	return ret;
}

static const struct snd_soc_ops sof_cs42l42_ops = {
	.hw_params = sof_cs42l42_hw_params,
};

static struct snd_soc_dai_link_component platform_component[] = {
	{
		/* name might be overridden during probe */
		.name = "0000:00:1f.3"
	}
};

static int sof_card_late_probe(struct snd_soc_card *card)
{
	struct sof_card_private *ctx = snd_soc_card_get_drvdata(card);
	struct snd_soc_component *component = NULL;
	char jack_name[NAME_SIZE];
	struct sof_hdmi_pcm *pcm;
	int err;

	list_for_each_entry(pcm, &ctx->hdmi_pcm_list, head) {
		component = pcm->codec_dai->component;
		snprintf(jack_name, sizeof(jack_name),
			 "HDMI/DP, pcm=%d Jack", pcm->device);
		err = snd_soc_card_jack_new(card, jack_name,
					    SND_JACK_AVOUT, &pcm->hdmi_jack,
					    NULL, 0);

		if (err)
			return err;

		err = hdac_hdmi_jack_init(pcm->codec_dai, pcm->device,
					  &pcm->hdmi_jack);
		if (err < 0)
			return err;
	}
	if (!component)
		return -EINVAL;

	return hdac_hdmi_jack_port_init(component, &card->dapm);
}

static const struct snd_kcontrol_new sof_controls[] = {
	SOC_DAPM_PIN_SWITCH("Headphone Jack"),
	SOC_DAPM_PIN_SWITCH("Headset Mic"),
	SOC_DAPM_PIN_SWITCH("Spk"),
};

static const struct snd_soc_dapm_widget sof_widgets[] = {
	SND_SOC_DAPM_HP("Headphone Jack", NULL),
	SND_SOC_DAPM_MIC("Headset Mic", NULL),
	SND_SOC_DAPM_SPK("Spk", NULL),
};

static const struct snd_soc_dapm_widget dmic_widgets[] = {
	SND_SOC_DAPM_MIC("SoC DMIC", NULL),
};

static const struct snd_soc_dapm_route sof_map[] = {
	/* HP jack connectors - unknown if we have jack detection */
	{"Headphone Jack", NULL, "HP"},

	/* other jacks */
	{"HS", NULL, "Headset Mic"},
};

static const struct snd_soc_dapm_route speaker_map[] = {
	/* speaker */
	{"Spk", NULL, "Speaker"},
};

static const struct snd_soc_dapm_route dmic_map[] = {
	/* digital mics */
	{"DMic", NULL, "SoC DMIC"},
};

static int speaker_codec_init(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_card *card = rtd->card;
	int ret;

	ret = snd_soc_dapm_add_routes(&card->dapm, speaker_map,
				      ARRAY_SIZE(speaker_map));

	if (ret)
		dev_err(rtd->dev, "Speaker map addition failed: %d\n", ret);
	return ret;
}

static int dmic_init(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_card *card = rtd->card;
	int ret;

	ret = snd_soc_dapm_new_controls(&card->dapm, dmic_widgets,
					ARRAY_SIZE(dmic_widgets));
	if (ret) {
		dev_err(card->dev, "DMic widget addition failed: %d\n", ret);
		/* Don't need to add routes if widget addition failed */
		return ret;
	}

	ret = snd_soc_dapm_add_routes(&card->dapm, dmic_map,
				      ARRAY_SIZE(dmic_map));

	if (ret)
		dev_err(card->dev, "DMic map addition failed: %d\n", ret);

	return ret;
}

/* sof audio machine driver for cs42l42 codec */
static struct snd_soc_card sof_audio_card_cs42l42 = {
	.name = "cs42l42", /* the sof- prefix is added by the core */
	.owner = THIS_MODULE,
	.controls = sof_controls,
	.num_controls = ARRAY_SIZE(sof_controls),
	.dapm_widgets = sof_widgets,
	.num_dapm_widgets = ARRAY_SIZE(sof_widgets),
	.dapm_routes = sof_map,
	.num_dapm_routes = ARRAY_SIZE(sof_map),
	.fully_routed = true,
	.late_probe = sof_card_late_probe,
};

static struct snd_soc_dai_link_component cs42l42_component[] = {
	{
		.name = "i2c-10134242:00",
		.dai_name = "cs42l42",
	}
};

static struct snd_soc_dai_link_component dmic_component[] = {
	{
		.name = "dmic-codec",
		.dai_name = "dmic-hifi",
	}
};

static struct snd_soc_dai_link_component max98357a_component[] = {
	{
		.name = "MX98357A:00",
		.dai_name = "HiFi",
	}
};

static struct snd_soc_dai_link *sof_card_dai_links_create(struct device *dev,
							  int ssp_codec,
							  int ssp_amp,
							  int dmic_be_num,
							  int hdmi_num)
{
	struct snd_soc_dai_link_component *idisp_components;
	struct snd_soc_dai_link *links;
	int i, id = 0;

	links = devm_kzalloc(dev, sizeof(struct snd_soc_dai_link) *
			     sof_audio_card_cs42l42.num_links, GFP_KERNEL);
	if (!links)
		goto devm_err;

	/* speaker amp */
	if (sof_cs42l42_quirk & SOF_SPEAKER_AMP_PRESENT) {
		links[id].name = devm_kasprintf(dev, GFP_KERNEL,
						"SSP%d-Codec", ssp_amp);
		if (!links[id].name)
			goto devm_err;

		links[id].id = id;

		if (sof_cs42l42_quirk & SOF_MAX98357A_SPEAKER_AMP_PRESENT) {
			links[id].codecs = max98357a_component;
			links[id].num_codecs = ARRAY_SIZE(max98357a_component);
			links[id].init = speaker_codec_init;
		} else {
			dev_err(dev, "no amp defined\n");
			goto devm_err;
		}

		links[id].platforms = platform_component;
		links[id].num_platforms = ARRAY_SIZE(platform_component);
		links[id].dpcm_playback = 1;
		links[id].no_pcm = 1;

		links[id].cpu_dai_name = devm_kasprintf(dev, GFP_KERNEL,
							"SSP%d Pin",
							ssp_amp);
		if (!links[id].cpu_dai_name)
			goto devm_err;

		id++;
	}

	/* codec SSP */
	links[id].name = devm_kasprintf(dev, GFP_KERNEL,
					"SSP%d-Codec", ssp_codec);
	if (!links[id].name)
		goto devm_err;

	links[id].id = id;
	links[id].codecs = cs42l42_component;
	links[id].num_codecs = ARRAY_SIZE(cs42l42_component);
	links[id].platforms = platform_component;
	links[id].num_platforms = ARRAY_SIZE(platform_component);
	links[id].init = sof_cs42l42_init;
	links[id].ops = &sof_cs42l42_ops;
	links[id].dpcm_playback = 1;
	links[id].dpcm_capture = 1;
	links[id].no_pcm = 1;

	links[id].cpu_dai_name = devm_kasprintf(dev, GFP_KERNEL,
						"SSP%d Pin",
						ssp_codec);
	if (!links[id].cpu_dai_name)
		goto devm_err;

	id++;

	/* dmic */
	if (dmic_be_num > 0) {
		/* at least we have dmic01 */
		links[id].name = "dmic01";
		links[id].cpu_dai_name = "DMIC01 Pin";
		links[id].init = dmic_init;
		if (dmic_be_num > 1) {
			/* set up 2 BE links at most */
			links[id + 1].name = "dmic16k";
			links[id + 1].cpu_dai_name = "DMIC16k Pin";
			dmic_be_num = 2;
		}
	}

	for (i = 0; i < dmic_be_num; i++) {
		links[id].id = id;
		links[id].codecs = dmic_component;
		links[id].num_codecs = ARRAY_SIZE(dmic_component);
		links[id].platforms = platform_component;
		links[id].num_platforms = ARRAY_SIZE(platform_component);
		links[id].ignore_suspend = 1;
		links[id].dpcm_capture = 1;
		links[id].no_pcm = 1;
		id++;
	}

	/* HDMI */
	if (hdmi_num > 0) {
		idisp_components = devm_kzalloc(dev,
						sizeof(struct snd_soc_dai_link_component) *
						hdmi_num, GFP_KERNEL);
		if (!idisp_components)
			goto devm_err;
	}
	for (i = 1; i <= hdmi_num; i++) {
		links[id].name = devm_kasprintf(dev, GFP_KERNEL,
						"iDisp%d", i);
		if (!links[id].name)
			goto devm_err;

		links[id].id = id;
		links[id].cpu_dai_name = devm_kasprintf(dev, GFP_KERNEL,
							"iDisp%d Pin", i);
		if (!links[id].cpu_dai_name)
			goto devm_err;

		idisp_components[i - 1].name = "ehdaudio0D2";
		idisp_components[i - 1].dai_name = devm_kasprintf(dev,
								  GFP_KERNEL,
								  "intel-hdmi-hifi%d",
								  i);
		if (!idisp_components[i - 1].dai_name)
			goto devm_err;

		links[id].codecs = &idisp_components[i - 1];
		links[id].num_codecs = 1;
		links[id].platforms = platform_component;
		links[id].num_platforms = ARRAY_SIZE(platform_component);
		links[id].init = sof_hdmi_init;
		links[id].dpcm_playback = 1;
		links[id].no_pcm = 1;
		id++;
	}

	return links;
devm_err:
	return NULL;
}

static const struct x86_cpu_id glk_ids[] = {
	{ X86_VENDOR_INTEL, 6, 0x7A }, /* Geminilake CPU_ID */
	{}
};

static int sof_audio_probe(struct platform_device *pdev)
{
	struct snd_soc_dai_link *dai_links;
	struct snd_soc_acpi_mach *mach;
	struct sof_card_private *ctx;
	int dmic_be_num, hdmi_num;
	int ret, ssp_amp, ssp_codec;

	ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	if (pdev->id_entry && pdev->id_entry->driver_data)
		sof_cs42l42_quirk = (unsigned long)pdev->id_entry->driver_data;

	mach = pdev->dev.platform_data;

	if (x86_match_cpu(glk_ids)) {
		dmic_be_num = 1;
		hdmi_num = 3;
	} else {
		dmic_be_num = 2;
		hdmi_num = (sof_cs42l42_quirk & SOF_CS42L42_NUM_HDMIDEV_MASK) >>
			 SOF_CS42L42_NUM_HDMIDEV_SHIFT;
		/* default number of HDMI DAI's */
		if (!hdmi_num)
			hdmi_num = 3;
	}

	dev_dbg(&pdev->dev, "sof_cs42l42_quirk = %lx\n", sof_cs42l42_quirk);

	ssp_amp = (sof_cs42l42_quirk & SOF_CS42L42_SSP_AMP_MASK) >>
			SOF_CS42L42_SSP_AMP_SHIFT;

	ssp_codec = sof_cs42l42_quirk & SOF_CS42L42_SSP_CODEC_MASK;

	/* compute number of dai links */
	sof_audio_card_cs42l42.num_links = 1 + dmic_be_num + hdmi_num;

	if (sof_cs42l42_quirk & SOF_SPEAKER_AMP_PRESENT)
		sof_audio_card_cs42l42.num_links++;

	dai_links = sof_card_dai_links_create(&pdev->dev, ssp_codec, ssp_amp,
					      dmic_be_num, hdmi_num);
	if (!dai_links)
		return -ENOMEM;

	sof_audio_card_cs42l42.dai_link = dai_links;

	INIT_LIST_HEAD(&ctx->hdmi_pcm_list);

	sof_audio_card_cs42l42.dev = &pdev->dev;

	/* set platform name for each dailink */
	ret = snd_soc_fixup_dai_links_platform_name(&sof_audio_card_cs42l42,
						    mach->mach_params.platform);
	if (ret)
		return ret;

	snd_soc_card_set_drvdata(&sof_audio_card_cs42l42, ctx);

	return devm_snd_soc_register_card(&pdev->dev,
					  &sof_audio_card_cs42l42);
}

static int sof_cs42l42_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);
	struct snd_soc_component *component = NULL;

	for_each_card_components(card, component) {
		if (!strcmp(component->name, cs42l42_component[0].name)) {
			snd_soc_component_set_jack(component, NULL, NULL);
			break;
		}
	}

	return 0;
}

static const struct platform_device_id board_ids[] = {
	{
		.name = "glk_cs4242_max98357a",
		.driver_data = (kernel_ulong_t)(SOF_CS42L42_SSP_CODEC(2) |
					SOF_SPEAKER_AMP_PRESENT |
					SOF_MAX98357A_SPEAKER_AMP_PRESENT |
					SOF_CS42L42_SSP_AMP(1)),
	},
	{ }
};

static struct platform_driver sof_audio = {
	.probe = sof_audio_probe,
	.remove = sof_cs42l42_remove,
	.driver = {
		.name = "sof_cs42l42",
		.pm = &snd_soc_pm_ops,
	},
	.id_table = board_ids,
};
module_platform_driver(sof_audio)

/* Module information */
MODULE_DESCRIPTION("SOF Audio Machine driver for CS42L42");
MODULE_AUTHOR("Brent Lu <brent.lu@intel.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:sof_cs42l42");
MODULE_ALIAS("platform:glk_cs4242_max98357a");
