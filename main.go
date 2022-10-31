package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
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
	portArg        = flag.Int("port", 0, "Http port to host a proxy server")
	errNeedsLogin  = errors.New("Login required")
)

type Rule struct {
	ID      string `json:"_id"`
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
}

type UnifiFirewall struct {
	Host     string
	Username string
	password string

	csrfToken string
	client    *http.Client
}

func NewUnifiFirewall(host, username, password string) (*UnifiFirewall, error) {
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecureArg},
		},
	}

	return &UnifiFirewall{
		Host:     host,
		Username: username,
		password: password,
		client:   client,
	}, nil
}

func (uf *UnifiFirewall) FindRule(ruleQuery string) (*Rule, error) {
	rules, err := uf.GetRules()
	if err != nil {
		return nil, err
	}

	ruleQuery = strings.TrimSpace(ruleQuery)

	for id, rule := range rules {
		if ruleQuery == id || ruleQuery == rule.Name {
			return &rule, nil
		}
	}

	return nil, nil
}

func (uf *UnifiFirewall) GetRules() (map[string]Rule, error) {
	type ListRulesResponse struct {
		Meta  map[string]string `json:"meta"`
		Rules []Rule            `json:"data"`
	}

	return doAndMaybeLogin(uf.Login, func() (map[string]Rule, error) {
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

		if resp.StatusCode == 401 {
			return nil, errNeedsLogin
		} else if resp.StatusCode != 200 {
			log.WithFields(log.Fields{
				"host":        uf.Host,
				"status_code": resp.StatusCode,
			}).Error("Failed to list rules")
			return nil, fmt.Errorf("failed to list rules: %d", resp.StatusCode)
		}

		listRulesBytes, err := io.ReadAll(resp.Body)
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
	})
}

func (uf *UnifiFirewall) Login() error {
	type LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	uf.client.Jar = jar

	reqBytes, err := json.Marshal(LoginRequest{uf.Username, uf.password})
	if err != nil {
		return err
	}
	path := "/api/auth/login"
	req, err := http.NewRequest("POST", uf.Host+path, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	log.WithFields(log.Fields{
		"host":     uf.Host,
		"username": uf.Username,
	}).Info("Logging in...")
	resp, err := uf.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.WithFields(log.Fields{
			"host":        uf.Host,
			"username":    uf.Username,
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
			"username": uf.Username,
			"token":    cookie.Value,
		}).Debug("Received token cookie")

		token, _ := jwt.Parse(cookie.Value, nil)
		if token == nil {
			log.WithFields(log.Fields{
				"host":     uf.Host,
				"username": uf.Username,
			}).Error("Token is malformed")
			return fmt.Errorf("token is malformed")
		}

		uf.csrfToken = token.Claims.(jwt.MapClaims)["csrfToken"].(string)
	}

	return nil
}

func (uf *UnifiFirewall) SetRuleEnabled(ruleQuery string, enabled bool) error {
	setRuleEnabled := func() error {
		rule, err := uf.FindRule(ruleQuery)
		if err != nil {
			return err
		}

		if rule == nil {
			log.Infof("No rule found for %s", ruleQuery)
			return nil
		}

		if enabled == rule.Enabled {
			log.Infof("Rule %s is already enabled=%s", ruleQuery, enabled)
			return nil
		}

		type EnableRequest struct {
			Enabled bool `json:"enabled"`
		}

		reqBytes, err := json.Marshal(EnableRequest{enabled})
		if err != nil {
			return err
		}

		req, err := http.NewRequest("PUT", uf.Host+"/proxy/network/api/s/default/rest/firewallrule/"+rule.ID, bytes.NewBuffer(reqBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-csrf-token", uf.csrfToken)

		log.WithFields(log.Fields{
			"host":    uf.Host,
			"rule_id": rule.ID,
		}).Info("Updating rule...")
		resp, err := uf.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			return errNeedsLogin
		} else if resp.StatusCode != 200 {
			log.WithFields(log.Fields{
				"host":        uf.Host,
				"rule_id":     rule.ID,
				"status_code": resp.StatusCode,
			}).Error("Failed to update rule")
			return fmt.Errorf("failed to update rule %s: %d", rule.ID, resp.StatusCode)
		}

		log.WithFields(log.Fields{
			"enabled": enabled,
			"host":    uf.Host,
			"rule_id": rule.ID,
		}).Info("Successfully updated rule")

		return nil
	}
	_, err := doAndMaybeLogin(uf.Login, func() (any, error) {
		return nil, setRuleEnabled()
	})
	return err
}

func doAndMaybeLogin[v any](login func() error, f func() (v, error)) (v, error) {
	val, err := f()
	if err == nil {
		return val, nil
	}

	if errors.Is(err, errNeedsLogin) {
		if err := login(); err != nil {
			return val, err
		}
		return f()
	} else {
		return val, err
	}
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

	host := *hostArg
	if host == "" {
		host = os.Getenv("UNIFI_HOST")
	}
	username := *usernameArg
	if username == "" {
		username = os.Getenv("UNIFI_USER")
	}
	password := *passwordArg
	if password == "" {
		password = os.Getenv("UNIFI_PASS")
	}

	unifiFirewall, err := NewUnifiFirewall(host, username, password)
	if err != nil {
		return err
	}

	rules, err := unifiFirewall.GetRules()
	if err != nil {
		return err
	}

	if *portArg > 0 {
		// serve as HTTP proxy
		router := mux.NewRouter()
		router.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
			rules, err := unifiFirewall.GetRules()
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(rules)
		}).Methods(http.MethodGet)

		router.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
			type ChangeRule struct {
				Name    string `json:"name"`
				Enabled bool   `json:"enabled"`
			}

			changeRule := ChangeRule{}

			if err := json.NewDecoder(r.Body).Decode(&changeRule); err != nil {
				log.Errorf("Failed to decode ChangeRule, %v", err)
				http.Error(w, "Error decoding ChangeRule", http.StatusBadRequest)
				return
			}

			rule, err := unifiFirewall.FindRule(changeRule.Name)
			if err != nil {
				log.Errorf("Failed to find rule named %s, %v", changeRule.Name, err)
				http.Error(w, "Error finding rule", http.StatusBadRequest)
				return
			} else if rule == nil {
				log.Errorf("Failed to find rule named %s", changeRule.Name)
				http.Error(w, "Failed to find rule", http.StatusBadRequest)
				return
			}

			if err := unifiFirewall.SetRuleEnabled(rule.ID, changeRule.Enabled); err != nil {
				log.Errorf("Failed to set rule %s enabled to %v, %v", changeRule.Name, changeRule.Enabled, err)
				http.Error(w, "Error setting rule enabled", http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusAccepted)
		}).Methods(http.MethodPost)

		log.Infof("Listening on %d...", *portArg)
		http.ListenAndServe(fmt.Sprintf(":%d", *portArg), router)
	} else if *disableRuleArg != "" {
		unifiFirewall.SetRuleEnabled(*disableRuleArg, false)
	} else if *enableRuleArg != "" {
		unifiFirewall.SetRuleEnabled(*enableRuleArg, true)
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
