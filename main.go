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
	"strings"
	"time"

	"github.com/miekg/dns"
)

var forbiddenHeaders = map[string]byte{
	"X-Frame-Options":             1,
	"Access-Control-Allow-Origin": 1,
}

func main() {
	config := Config{}
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("%v", err.Error())
	}
	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(&config); err != nil {
		log.Fatalf("%v", err.Error())
	}

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

		log.Println(r.Answer[0].(*dns.A).A)
		newAddr := fmt.Sprintf("%s:%s", r.Answer[0].(*dns.A).A, p[1])
		log.Println(newAddr)
		return dialer.DialContext(ctx, network, newAddr)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
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

		for header, values := range proxyRes.Header {
			for _, value := range values {
				if _, ok := forbiddenHeaders[header]; ok == true {
					continue
				}
				w.Header().Add(header, value)
			}
		}
		io.Copy(w, proxyRes.Body)
	})

	log.Fatal(http.ListenAndServe(":80", nil))
}
