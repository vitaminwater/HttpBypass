/*
 * Copyright (C) 2019  SuperGreenLab <towelie@supergreenlab.com>
 * Author: Constantin Clauzel <constantin.clauzel@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var forbiddenHeaders = map[string]byte{
	"X-Frame-Options":             1,
	"Access-Control-Allow-Origin": 1,
	"Upgrade-Insecure-Requests":   1,
	"Content-Security-Policy":     1,
}

func main() {
	hn, err := os.Hostname()
	if err != nil {
		log.Fatalf("%v", err)
	}

	config := Config{}
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("%v", err.Error())
	}

	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(&config); err != nil {
		log.Fatalf("%v", err.Error())
	}
	configFile.Close()

	mimes := map[string]string{}
	mimesFile, err := os.Open("mimes.json")
	if err != nil {
		log.Fatalf("%v", err.Error())
	}

	jsonParser = json.NewDecoder(mimesFile)
	if err = jsonParser.Decode(&config); err != nil {
		log.Fatalf("%v", err.Error())
	}
	mimesFile.Close()

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		p := strings.Split(addr, ":")

		c := dns.Client{}
		m := dns.Msg{}
		m.SetQuestion(p[0]+".", dns.TypeA)
		r, _, err := c.Exchange(&m, "8.8.8.8:53")
		if err != nil {
			log.Printf("%s not found", p[0])
			return nil, err
		}
		if len(r.Answer) == 0 {
			log.Fatal("No results")
			return nil, errors.New("Not found")
		}

		newAddr := ""
		if a, ok := r.Answer[0].(*dns.A); ok == true {
			newAddr = fmt.Sprintf("%s:%s", a.A, p[1])
		} else if a, ok := r.Answer[0].(*dns.CNAME); ok == true {
			newAddr = fmt.Sprintf("%s:%s", a.Target, p[1])
		}
		return dialer.DialContext(ctx, network, newAddr)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		log.Println(req.URL.Path)
		if req.Host == "localhost" || req.Host == hn || req.Host == hn+".local" {
			fp := req.URL.Path
			if fp == "" || fp[len(fp)-1:] == "/" {
				fp = fp + "/index.html"
			}
			ext := filepath.Ext(fp)
			w.Header().Set("Content-Type", mimes[ext])
			http.ServeFile(w, req, "/var/www/html"+fp)
			return
		}
		redir, ok := config.Redirects[req.Host]
		if ok == false {
			log.Printf("Unknown %s", req.Host)
			w.WriteHeader(404)
			return
		}

		url := fmt.Sprintf("%s://%s%s", redir.Scheme, req.Host, req.URL.String())

		proxyReq, err := http.NewRequest(req.Method, url, req.Body)
		if err != nil {
			log.Printf("%v", err)
			w.WriteHeader(500)
			return
		}

		for header, values := range req.Header {
			for _, value := range values {
				if _, ok := forbiddenHeaders[header]; ok == true {
					continue
				}
				proxyReq.Header.Add(header, value)
			}
		}

		if redir.Auth.Username != "" && redir.Auth.Password != "" {
			proxyReq.SetBasicAuth(redir.Auth.Username, redir.Auth.Password)
		}

		client := &http.Client{}
		proxyRes, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("%v", err)
			w.WriteHeader(500)
			return
		}
		log.Println(proxyRes.Header.Get("Cookie"))

		for header, values := range proxyRes.Header {
			for _, value := range values {
				if _, ok := forbiddenHeaders[header]; ok == true {
					continue
				}
				w.Header().Add(header, value)
			}
		}
		w.Header().Add("Clear-Site-Data", "*")
		io.Copy(w, proxyRes.Body)
	})

	go func() {
		log.Fatal(http.ListenAndServe(":80", nil))
	}()
	go func() {
		log.Fatal(http.ListenAndServeTLS(":443", "certs/server.crt", "certs/server.key", nil))
	}()
	select {}
}
