package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"os"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

var (
	helpArg        = flag.Bool("help", false, "Print help message")
	verboseArg     = flag.Bool("verbose", false, "Use verbose logging")
	insecureArg    = flag.Bool("insecure", false, "If the unifi host can be accessed insecurely")
	hostArg        = flag.String("host", "", "Unifi host")
	usernameArg    = flag.String("user", "", "Unifi username")
	passwordArg    = flag.String("pass", "", "Unifi password")
	disableRuleArg = flag.String("disable-rule", "", "Disable the rule")
	enableRuleArg  = flag.String("enable-rule", "", "Enable the rule")
)

type Rule struct {
	ID      string `json:"_id"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
}

type UnifiFirewall struct {
	Host string

	csrfToken string
	client    *http.Client
}

func NewUnifiFirewall(host string) (*UnifiFirewall, error) {
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureArg},
	}
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
	}

	return &UnifiFirewall{
		Host:   host,
		client: client,
	}, nil
}

func (uf *UnifiFirewall) Login(username, password string) error {
	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	reqBytes, err := json.Marshal(LoginRequest{username, password})
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", uf.Host+"/api/auth/login", bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	log.WithFields(log.Fields{
		"host":     uf.Host,
		"username": username,
	}).Info("Logging in...")
	resp, err := uf.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"host":        uf.Host,
			"username":    username,
			"status_code": resp.StatusCode,
		}).Error("Failed to login")
		return fmt.Errorf("failed to login: %d", resp.StatusCode)
	}

	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name != "TOKEN" {
			continue
		}

		log.WithFields(log.Fields{
			"host":     uf.Host,
			"username": username,
			"token":    cookie.Value,
		}).Debug("Received token cookie")

		token, _ := jwt.Parse(cookie.Value, nil)
		if token == nil {
			log.WithFields(log.Fields{
				"host":     uf.Host,
				"username": username,
			}).Error("Token is malformed")
			return fmt.Errorf("token is malformed")
		}

		uf.csrfToken = token.Claims.(jwt.MapClaims)["csrfToken"].(string)
	}

	return nil
}

func (uf UnifiFirewall) GetRules() (map[string]Rule, error) {
	type ListRulesResponse struct {
		Meta  map[string]string `json:"meta"`
		Rules []Rule            `json:"data"`
	}

	req, err := http.NewRequest("GET", uf.Host+"/proxy/network/api/s/default/rest/firewallrule", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	log.WithFields(log.Fields{
		"host": uf.Host,
	}).Info("Listing rules...")
	resp, err := uf.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"host":        uf.Host,
			"status_code": resp.StatusCode,
		}).Error("Failed to list rules")
		return nil, fmt.Errorf("failed to list rules: %d", resp.StatusCode)
	}

	listRulesBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var rules ListRulesResponse
	if err := json.Unmarshal(listRulesBytes, &rules); err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"rules": string(listRulesBytes),
	}).Debug("List rules response")

	ruleIdToRule := make(map[string]Rule)
	for _, rule := range rules.Rules {
		ruleIdToRule[rule.ID] = rule
	}

	return ruleIdToRule, nil
}

func (uf UnifiFirewall) SetRuleEnabled(ruleID string, enabled bool) error {
	type EnableRequest struct {
		Enabled bool `json:"enabled"`
	}

	reqBytes, err := json.Marshal(EnableRequest{enabled})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", uf.Host+"/proxy/network/api/s/default/rest/firewallrule/"+ruleID, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-csrf-token", uf.csrfToken)

	log.WithFields(log.Fields{
		"host":    uf.Host,
		"rule_id": ruleID,
	}).Info("Updating rule...")
	resp, err := uf.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"host":        uf.Host,
			"rule_id":     ruleID,
			"status_code": resp.StatusCode,
		}).Error("Failed to update rule")
		return fmt.Errorf("failed to update rule %s: %d", ruleID, resp.StatusCode)
	}

	log.WithFields(log.Fields{
		"enabled": enabled,
		"host":    uf.Host,
		"rule_id": ruleID,
	}).Info("Successfully updated rule")

	return nil
}

func run() error {
	flag.Parse()

	if *helpArg {
		flag.Usage()
		return nil
	}

	if *verboseArg {
		log.SetLevel(log.TraceLevel)
	}

	unifiFirewall, err := NewUnifiFirewall(*hostArg)
	if err != nil {
		return err
	}

	username := *usernameArg
	if username == "" {
		username = os.Getenv("UNIFI_USER")
	}
	password := *passwordArg
	if password == "" {
		password = os.Getenv("UNIFI_PASS")
	}

	if err := unifiFirewall.Login(username, password); err != nil {
		return err
	}

	rules, err := unifiFirewall.GetRules()
	if err != nil {
		return err
	}

	if *disableRuleArg != "" {
		for id, rule := range rules {
			if *disableRuleArg == id || *disableRuleArg == rule.Name {
				if !rule.Enabled {
					fmt.Printf("Rule '%s' is already disabled", rule.Name)
				} else {
					if err := unifiFirewall.SetRuleEnabled(id, false); err != nil {
						return err
					}
					fmt.Printf("Rule '%s' has been disabled", *disableRuleArg)
				}

				return nil
			}
		}
	} else if *enableRuleArg != "" {
		for id, rule := range rules {
			if *enableRuleArg == id || *enableRuleArg == rule.Name {
				if rule.Enabled {
					fmt.Printf("Rule '%s' is already enabled", rule.Name)
				} else {
					if err := unifiFirewall.SetRuleEnabled(id, true); err != nil {
						return err
					}
					fmt.Printf("Rule '%s' has been enabled", *enableRuleArg)
				}

				return nil
			}
		}
	} else {
		rulesBytes, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return err
		}

		fmt.Printf("%s\n", string(rulesBytes))
		return nil
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Failed to run")
	}
}
