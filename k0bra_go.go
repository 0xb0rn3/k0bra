package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type Device struct {
	IP  string `json:"IP"`
	MAC string `json:"MAC"`
}

func getMacAddress(ip string) string {
	arp, err := net.LookupAddr(ip)
	if err != nil {
		return "N/A"
	}
	return arp[0]
}

func scanNetwork(ipRange string, wg *sync.WaitGroup, devices *[]Device) {
	defer wg.Done()

	for i := 1; i < 255; i++ {
		ip := fmt.Sprintf(ipRange+".%d", i)
		conn, err := net.DialTimeout("tcp", ip+":80", 1*time.Second)
		if err == nil {
			device := Device{
				IP:  ip,
				MAC: getMacAddress(ip),
			}
			*devices = append(*devices, device)
			conn.Close()
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./k0bra_go <ip_range>")
		return
	}

	ipRange := os.Args[1][:len(os.Args[1])-4] // Stripping off /24
	var wg sync.WaitGroup
	var devices []Device

	wg.Add(1)
	go scanNetwork(ipRange, &wg, &devices)

	wg.Wait()

	// Output devices as JSON
	output, err := json.Marshal(devices)
	if err != nil {
		fmt.Println("Error encoding devices to JSON:", err)
		return
	}

	fmt.Println(string(output))
}
