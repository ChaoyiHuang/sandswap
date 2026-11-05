// Copyright 2026 Chaoyi Huang. All rights reserved.
//
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE file at the root of this repository.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// httpc builds the shared *http.Client honoring the global TLS settings.
func (g Global) httpc() (*http.Client, error) {
	tr := &http.Transport{}
	if strings.HasPrefix(g.GatewayURL, "https") || strings.HasPrefix(g.HumanURL, "https") || g.TLS {
		tlsCfg := &tls.Config{}
		if g.Insecure {
			tlsCfg.InsecureSkipVerify = true
		} else {
			if g.CA != "" {
				caPath := g.CertPath(g.CA)
				caPEM, err := os.ReadFile(caPath)
				if err != nil {
					return nil, fmt.Errorf("read CA %s: %w", caPath, err)
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(caPEM) {
					return nil, fmt.Errorf("CA %s has no usable certs", caPath)
				}
				tlsCfg.RootCAs = pool
			}
			if (g.ClientCert == "") != (g.ClientKey == "") {
				return nil, fmt.Errorf("--client-cert and --client-key must be set together")
			}
			if g.ClientCert != "" {
				keyPath := g.CertPath(g.ClientKey)
				// The deployment scopes service private keys to the identities
				// that load them; a client key must be caller-owned and 0600.
				if err := checkClientKeyFile(keyPath); err != nil {
					return nil, err
				}
				cert, err := tls.LoadX509KeyPair(g.CertPath(g.ClientCert), keyPath)
				if err != nil {
					return nil, fmt.Errorf("load client cert: %w", err)
				}
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Transport: tr}, nil
}

// request builds and sends an HTTP request, then prints the response. method
// is uppercased; body may be nil. bearer is the optional Authorization token.
// extraHeaders are added as-is. Returns the parsed JSON (or raw bytes) so
// callers (e.g. agent create) can extract fields.
func (g Global) request(baseURL, method, path string, body any, bearer string, extraHeaders map[string]string) ([]byte, int, error) {
	url := strings.TrimRight(baseURL, "/") + path

	var bodyReader io.Reader
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal body: %w", err)
		}
		bodyBytes = b
		bodyReader = bytes.NewReader(b)
	}

	if g.DryRun {
		fmt.Fprintf(os.Stderr, "%s %s\n", strings.ToUpper(method), url)
		if bearer != "" {
			fmt.Fprintf(os.Stderr, "  Authorization: Bearer ***\n")
		}
		for k, v := range extraHeaders {
			fmt.Fprintf(os.Stderr, "  %s: %s\n", k, v)
		}
		if bodyBytes != nil {
			fmt.Fprintf(os.Stderr, "  body: %s\n", string(bodyBytes))
		}
		return nil, 0, nil
	}

	req, err := http.NewRequest(strings.ToUpper(method), url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	client, err := g.httpc()
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return data, resp.StatusCode, nil
}

// printResp pretty-prints the response body (JSON) unless --raw. Non-2xx goes
// to stderr with the status code. Returns the raw bytes for caller use.
func (g Global) printResp(data []byte, status int) []byte {
	if status >= 400 {
		fmt.Fprintf(os.Stderr, "HTTP %d\n", status)
	}
	if len(data) == 0 {
		if status < 400 {
			fmt.Println("(empty body)")
		}
		return data
	}
	if g.Raw {
		fmt.Println(string(data))
		return data
	}
	// Try to pretty-print JSON; fall back to raw.
	var pretty bytes.Buffer
	if json.Indent(&pretty, data, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(data))
	}
	return data
}

// getJSON sends a GET (no body) and prints.
func (g Global) getJSON(baseURL, path, bearer string, headers map[string]string) {
	data, status, err := g.request(baseURL, "GET", path, nil, bearer, headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	g.printResp(data, status)
}

// getPagedJSON fetches a paginated list endpoint (the {items, next_cursor,
// truncated} envelope) and prints the items as one JSON array. Without
// followAll it prints a single page (server default limit) and notes the
// continuation cursor on stderr when truncated; with followAll it chases
// cursors up to a 10k-page safety bound.
func (g Global) getPagedJSON(baseURL, path string, limit int, followAll bool, headers map[string]string) {
	var merged []json.RawMessage
	cursor := ""
	for pages := 0; ; pages++ {
		p := path
		var q []string
		if limit > 0 {
			q = append(q, fmt.Sprintf("limit=%d", limit))
		}
		if cursor != "" {
			q = append(q, "cursor="+url.QueryEscape(cursor))
		}
		if len(q) > 0 {
			p += "?" + strings.Join(q, "&")
		}
		data, status, err := g.request(baseURL, "GET", p, nil, "", headers)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if status >= 400 {
			g.printResp(data, status)
			os.Exit(1)
		}
		var page struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor string            `json:"next_cursor"`
			Truncated  bool              `json:"truncated"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		merged = append(merged, page.Items...)
		if page.NextCursor == "" {
			break
		}
		if !followAll {
			fmt.Fprintf(os.Stderr, "note: result truncated — pass --all to follow cursors (next_cursor=%s)\n", page.NextCursor)
			break
		}
		if pages >= 10000 {
			fmt.Fprintln(os.Stderr, "note: 10000-page safety bound reached; stopping")
			break
		}
		cursor = page.NextCursor
	}
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

// getJSONAny tries GET path against each base URL in order, printing the first
// that connects and returns < 500. Used for /health and /ready, which live on
// different listeners depending on the gateway mode (single-node/exec → agent
// listener; human → human listener). If all fail, prints the last error.
func (g Global) getJSONAny(path string, bases ...string) {
	var lastErr error
	for _, base := range bases {
		if base == "" {
			continue
		}
		data, status, err := g.request(base, "GET", path, nil, "", nil)
		if err == nil && status < 500 {
			g.printResp(data, status)
			return
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		fmt.Fprintln(os.Stderr, lastErr)
	} else {
		fmt.Fprintln(os.Stderr, "no listener responded")
	}
	os.Exit(1)
}

// postJSON sends a JSON POST and prints.
func (g Global) postJSON(baseURL, path string, body any, bearer string, headers map[string]string) []byte {
	data, status, err := g.request(baseURL, "POST", path, body, bearer, headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return g.printResp(data, status)
}

// deleteJSON sends a DELETE and prints.
func (g Global) deleteJSON(baseURL, path, bearer string, headers map[string]string) {
	data, status, err := g.request(baseURL, "DELETE", path, nil, bearer, headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	g.printResp(data, status)
}

// deleteJSONBody sends a DELETE with a JSON body (e.g. the template-delete
// request carrying mode/force options) and prints.
func (g Global) deleteJSONBody(baseURL, path string, body any, headers map[string]string) {
	data, status, err := g.request(baseURL, "DELETE", path, body, "", headers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	g.printResp(data, status)
}
