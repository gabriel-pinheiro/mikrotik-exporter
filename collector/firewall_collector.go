package collector

import (
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/routeros.v2/proto"
)

type firewallCollector struct {
	props        []string
	descriptions map[string]*prometheus.Desc
}

func newFirewallCollector() routerOSCollector {
	c := &firewallCollector{}
	c.init()
	return c
}

func (c *firewallCollector) init() {
	c.props = []string{"disabled", "comment", "chain", "action", "bytes", "packets"}
	labelNames := []string{"name", "address", "disabled", "comment", "chain", "action"}
	c.descriptions = make(map[string]*prometheus.Desc)
	for _, p := range c.props[4:] {
		c.descriptions[p] = descriptionForPropertyName("firewall_filter", p, labelNames)
	}
}

func (c *firewallCollector) describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descriptions {
		ch <- d
	}
}

func (c *firewallCollector) collect(ctx *collectorContext) error {
	stats, err := c.fetch(ctx)
	if err != nil {
		return err
	}

	for _, re := range stats {
		c.collectForStat(re, ctx)
	}

	return nil
}

func (c *firewallCollector) fetch(ctx *collectorContext) ([]*proto.Sentence, error) {
	reply, err := ctx.client.Run("/ip/firewall/filter/print", "=.proplist="+strings.Join(c.props, ","))
	if err != nil {
		log.WithFields(log.Fields{
			"device": ctx.device.Name,
			"error":  err,
		}).Error("error fetching firewall filters")
		return nil, err
	}

	return reply.Re, nil
}

func (c *firewallCollector) collectForStat(re *proto.Sentence, ctx *collectorContext) {
	for _, p := range c.props[4:] {
		c.collectMetricForProperty(p, re, ctx)
	}
}

func (c *firewallCollector) collectMetricForProperty(property string, re *proto.Sentence, ctx *collectorContext) {
	var v float64
	var err error

	if re.Map[property] == "" {
		return
	}
	v, err = strconv.ParseFloat(re.Map[property], 64)

	if err != nil {
		log.WithFields(log.Fields{
			"device":   ctx.device.Name,
			"property": property,
			"value":    re.Map[property],
			"error":    err,
		}).Error("error parsing firewall filter value")
		return
	}

	desc := c.descriptions[property]
	ctx.ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, v, ctx.device.Name, ctx.device.Address, re.Map["disabled"], re.Map["comment"], re.Map["chain"], re.Map["action"])
}
