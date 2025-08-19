package elasticsearch

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/publisher"
)

// syslogClient sends RFC3164 messages to a remote syslog server over UDP/TCP
type syslogClient struct {
	cfg    ClientSettings
	conn   net.Conn
	connMu sync.Mutex
	log    *logp.Logger
}

// Connect implements outputs.NetworkClient.
func (r *syslogClient) Connect() error {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn != nil {
		return nil
	}
	if r.cfg.SyslogHost == "" {
		r.conn = nil
		return nil // no host configured, nothing to do
	}
	network := r.cfg.SyslogProto
	if network == "" {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, r.cfg.SyslogHost, 5*time.Second)
	if err != nil {
		r.log.Errorf("failed to connect to syslog server %s: %v", r.cfg.SyslogHost, err)
		r.conn = nil
		return nil
	}
	r.conn = conn
	return nil
}

func newSyslogClient(c ClientSettings) outputs.NetworkClient {
	log := logp.NewLogger("syslog")
	if strings.TrimSpace(c.SyslogHost) == "" {
		return nil
	}
	// dial remote
	conn, err := net.DialTimeout(c.SyslogProto, c.SyslogHost, 5*time.Second)
	if err != nil {
		log.Errorf("failed to connect to syslog server %s: %v", c.SyslogHost, err)
		// if dial fails, still return client with no conn; Publish will try to reconnect
		return &syslogClient{cfg: c, conn: nil, log: log}
	}
	return &syslogClient{cfg: c, conn: conn, log: log}
}

func (r *syslogClient) Close() error {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	return nil
}

// formatRFC3164 builds a minimal RFC3164 message: "<PRI>TIMESTAMP HOST TAG: MSG"
// TIMESTAMP format: "Mmm dd hh:mm:ss" in local time
func (r *syslogClient) formatRFC3164(facility, severity string, tag string, msg string) string {
	pri := priFromFacilitySeverity(facility, severity)
	ts := time.Now().Format("Jan 2 15:04:05")
	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "localhost"
	}
	safeMsg := strings.ReplaceAll(msg, "\n", "\\n")
	if tag == "" {
		tag = "beats"
	}
	return fmt.Sprintf("<%d>%s %s %s: %s", pri, ts, hostname, tag, safeMsg)
}

// failed and discarded directly, the subject is elasticsearch, which control how to handle failures
func (r *syslogClient) Publish(ctx context.Context, batch publisher.Batch) error {
	evs := batch.Events()
	if r.conn == nil {
		err := r.Connect()
		if err != nil {
			r.log.Errorf("failed to connect to syslog server: %v", err)
			return nil
		}
	}
	writer := bufio.NewWriter(r.conn)
	for _, ev := range evs {
		msg := eventMessage(ev)
		out := r.formatRFC3164(r.cfg.SyslogFacility, r.cfg.SyslogSeverity, r.cfg.SyslogTag, msg)
		if _, err := writer.WriteString(out + "\n"); err != nil {
			r.log.Errorf("failed to write syslog message: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		r.log.Errorf("failed to flush syslog messages: %v", err)
	}
	return nil
}

func eventMessage(ev publisher.Event) string {
	if ev.Content.Fields == nil {
		return ""
	}
	if m, err := ev.Content.Fields.GetValue("message"); err == nil {
		return fmt.Sprintf("%v", m)
	}
	return fmt.Sprintf("%v", ev.Content.Fields)
}

func (r *syslogClient) String() string {
	return fmt.Sprintf("syslog(%s://%s)", r.cfg.SyslogProto, r.cfg.SyslogHost)
}

// priFromFacilitySeverity maps facility and severity to PRI numeric value.
func priFromFacilitySeverity(fac, sev string) int {
	facilityMap := map[string]int{
		"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
		"syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
		"authpriv": 10, "ftp": 11, "ntp": 12,
		// Historical/alternate names
		"audit": 13, "security": 13, "console": 14,
		// local use facilities (RFC3164 local0..local7)
		"local0": 16, "local1": 17, "local2": 18, "local3": 19,
		"local4": 20, "local5": 21, "local6": 22, "local7": 23,
	}
	severityMap := map[string]int{
		"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4,
		"notice": 5, "info": 6, "debug": 7,
	}
	fi := 3
	if v, ok := facilityMap[strings.ToLower(fac)]; ok {
		fi = v
	}
	si := 6
	if v, ok := severityMap[strings.ToLower(sev)]; ok {
		si = v
	}
	return fi*8 + si
}
