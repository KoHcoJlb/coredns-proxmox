package test_plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/luthermonson/go-proxmox"
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
	"golang.org/x/exp/slices"
	"net"
	"net/http"
	"strings"
)

const PluginName = "proxmox"

var log = clog.NewWithPlugin(PluginName)

type proxmoxHandler struct {
	node   *proxmox.Node
	domain string
	ttl    uint32
	next   plugin.Handler
}

func (p *proxmoxHandler) ServeDNS(ctx context.Context, writer dns.ResponseWriter, req *dns.Msg) (int, error) {
	state := request.Request{Req: req, W: writer}
	if state.QClass() != dns.ClassINET || state.QType() != dns.TypeA {
		return plugin.NextOrFailure(p.Name(), p.next, ctx, writer, req)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)

	vms, err := p.node.VirtualMachines()
	if err != nil {
		log.Errorf("fetch vms: %s", err)
		return dns.RcodeServerFailure, nil
	}

	name := dnsutil.TrimDomainName(state.QName(), p.domain)
	var foundVm *proxmox.VirtualMachine
	for _, vm := range vms {
		if vm.Name == name {
			foundVm = vm
			break
		}
	}
	if foundVm != nil {
		ifaces, err := foundVm.AgentGetNetworkIFaces()
		if err != nil {
			log.Errorf("fetch network interfaces: %s", err)
			return dns.RcodeServerFailure, nil
		}

		for _, iface := range ifaces {
			if !strings.HasPrefix(iface.Name, "enp") {
				continue
			}
			for _, ip := range iface.IPAddresses {
				addr := net.ParseIP(ip.IPAddress)
				if addr == nil {
					continue
				}
				if addr.To4() == nil {
					continue
				}

				r := new(dns.A)
				r.Hdr = dns.RR_Header{
					Name:   state.QName(),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    p.ttl,
				}
				r.A = addr
				resp.Answer = append(resp.Answer, r)
			}
		}
	} else {
		resp.Rcode = dns.RcodeNameError
	}

	err = writer.WriteMsg(resp)
	if err != nil {
		log.Errorf("write msg: %s", err)
		return dns.RcodeServerFailure, nil
	}

	return dns.RcodeSuccess, nil
}

func (p *proxmoxHandler) Name() string {
	return PluginName
}

func setup(c *caddy.Controller) (err error) {
	var (
		host,
		tokenID,
		secret,
		nodeName string
		ttl uint32
	)

	if c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "host":
				host = c.RemainingArgs()[0]
			case "tokenId":
				tokenID = c.RemainingArgs()[0]
			case "secret":
				secret = c.RemainingArgs()[0]
			case "nodeName":
				nodeName = c.RemainingArgs()[0]
			case "ttl":
				_, err = fmt.Sscan(c.RemainingArgs()[0], &ttl)
				if err != nil {
					return fmt.Errorf("invalid ttl: %s", err)
				}
			}
		}
	}

	if host == "" {
		return c.Errf("'host' not provided")
	}
	if tokenID == "" {
		return c.Errf("'tokenId' not provided")
	}
	if secret == "" {
		return c.Errf("'secret' not provided")
	}
	if nodeName == "" {
		return c.Errf("'nodeName' not provided")
	}
	if ttl == 0 {
		ttl = 300
	}

	client := proxmox.NewClient(fmt.Sprintf("https://%s:8006/api2/json", host),
		proxmox.WithAPIToken(tokenID, secret),
		proxmox.WithClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}))
	node, err := client.Node(nodeName)
	if err != nil {
		return c.Errf("node '%s' not found", nodeName)
	}

	dnsserver.GetConfig(c).AddPlugin(func(handler plugin.Handler) plugin.Handler {
		return &proxmoxHandler{
			node:   node,
			domain: nodeName,
			ttl:    ttl,
			next:   handler,
		}
	})

	return nil
}

func init() {
	plugin.Register(PluginName, setup)
	dnsserver.Directives = slices.Insert(dnsserver.Directives, slices.Index(dnsserver.Directives, "kubernetes"), "proxmox")
}
