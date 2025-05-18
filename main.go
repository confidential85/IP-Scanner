package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type DeviceStatus struct {
	IP     string
	DNS    string
	Status string
}

var (
	deviceIPs    []string
	deviceStatus = make(map[string]DeviceStatus)
	mutex        = &sync.Mutex{}
)

func main() {
	// No initial IP range required from user input
	// Initialize Gin router
	r := gin.Default()
	r.SetFuncMap(template.FuncMap{
		"contains": strings.Contains,
	})
	r.LoadHTMLGlob("templates/*")

	// Serve the dashboard
	r.GET("/", func(c *gin.Context) {
		query := c.Query("q")
		var filteredDevices map[string]DeviceStatus
		if query != "" {
			filteredDevices = filterDevices(query)
		} else {
			filteredDevices = deviceStatus
		}

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"devices": filteredDevices,
			"query":   query,
		})
	})

	// Ping a specific device on button click using command prompt
	r.POST("/ping", func(c *gin.Context) {
		ip := c.PostForm("ip")
		go runPing(ip)
		c.Status(http.StatusOK)
	})

	// SSH to a specific device
	r.POST("/ssh", func(c *gin.Context) {
		ip := c.PostForm("ip")
		username := c.PostForm("username")
		if username == "" {
			c.String(http.StatusBadRequest, "Username must be provided.")
			return
		}
		go runSSH(ip, username)
		c.Status(http.StatusOK)
	})

	// RDP to a specific device
	r.POST("/rdp", func(c *gin.Context) {
		ip := c.PostForm("ip")
		go runRDP(ip)
		c.Status(http.StatusOK)
	})

	// Telnet to a specific device
	r.POST("/telnet", func(c *gin.Context) {
		ip := c.PostForm("ip")
		go runTelnet(ip)
		c.Status(http.StatusOK)
	})

	// Add a new IP address
	r.POST("/add", func(c *gin.Context) {
		newIP := c.PostForm("ip")
		if !validateIP(newIP) {
			c.String(http.StatusBadRequest, "Invalid IP address format.")
			return
		}
		mutex.Lock()
		deviceIPs = append(deviceIPs, newIP)
		mutex.Unlock()
		checkDevice(newIP)
		c.JSON(http.StatusOK, gin.H{"message": "IP added successfully"})
	})

	// Add a new range of IP addresses
	r.POST("/add_range", func(c *gin.Context) {
		startIP := c.PostForm("start_ip")
		endIP := c.PostForm("end_ip")

		if !validateIP(startIP) || !validateIP(endIP) {
			c.String(http.StatusBadRequest, "Invalid IP address format for start or end IP.")
			return
		}

		newIPs := generateIPRange(startIP, endIP)
		mutex.Lock()
		deviceIPs = append(deviceIPs, newIPs...)
		mutex.Unlock()
		for _, ip := range newIPs {
			checkDevice(ip)
		}
		c.JSON(http.StatusOK, gin.H{"message": "IP range added successfully"})
	})

	// Remove a range of IP addresses
	r.POST("/remove_range", func(c *gin.Context) {
		startIP := c.PostForm("start_ip")
		endIP := c.PostForm("end_ip")

		if !validateIP(startIP) || !validateIP(endIP) {
			c.String(http.StatusBadRequest, "Invalid IP address format for start or end IP.")
			return
		}

		removeIPs := generateIPRange(startIP, endIP)
		mutex.Lock()
		for _, ip := range removeIPs {
			deviceIPs = removeIP(deviceIPs, ip)
			delete(deviceStatus, ip)
		}
		mutex.Unlock()
		c.JSON(http.StatusOK, gin.H{"message": "IP range removed successfully"})
	})

	// Start the background ping check
	go pingDevices()

	// Run the server
	r.Run(":8080")
}

// pingDevices pings each device every 10 seconds
func pingDevices() {
	for {
		mutex.Lock()
		for _, ip := range deviceIPs {
			go checkDevice(ip)
		}
		mutex.Unlock()
		time.Sleep(10 * time.Second)
	}
}

// checkDevice checks if the device is reachable and updates the status
func checkDevice(ip string) {
	var cmd *exec.Cmd
	if os.Getenv("OS") == "Windows_NT" {
		cmd = exec.Command("ping", "-n", "1", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", ip)
	}

	err := cmd.Run()
	status := "dead"
	if err == nil {
		status = "alive"
	}

	dnsName, _ := net.LookupAddr(ip)
	dns := ""
	if len(dnsName) > 0 {
		dns = strings.TrimSuffix(dnsName[0], ".")
	}

	mutex.Lock()
	deviceStatus[ip] = DeviceStatus{
		IP:     ip,
		DNS:    dns,
		Status: status,
	}
	mutex.Unlock()
}

// runPing runs the ping command with the -t option for continuous pinging
func runPing(ip string) {
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", "ping", ip, "-t")
	cmd.Start()
}

// runSSH runs the SSH command to connect to the given IP
func runSSH(ip, username string) {
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", "ssh", fmt.Sprintf("%s@%s", username, ip))
	cmd.Start()
}

// runRDP runs the RDP command to connect to the given IP
func runRDP(ip string) {
	cmd := exec.Command("cmd", "/c", "start", "mstsc", "/v:"+ip)
	cmd.Start()
}

// runTelnet runs the Telnet command to connect to the given IP
func runTelnet(ip string) {
	cmd := exec.Command("cmd", "/c", "start", "cmd", "/k", "telnet", ip)
	cmd.Start()
}

// generateIPRange generates a list of IP addresses between the start and end IP
func generateIPRange(startIP, endIP string) []string {
	start := net.ParseIP(startIP).To4()
	end := net.ParseIP(endIP).To4()
	if start == nil || end == nil {
		fmt.Println("Invalid IP address provided.")
		os.Exit(1)
	}

	var ips []string
	for ip := start; !ipAfter(ip, end); ip = nextIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// ipAfter checks if ip1 is after ip2
func ipAfter(ip1, ip2 net.IP) bool {
	for i := 0; i < 4; i++ {
		if ip1[i] > ip2[i] {
			return true
		} else if ip1[i] < ip2[i] {
			return false
		}
	}
	return false
}

// nextIP returns the next IP address
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

// filterDevices filters devices based on the query
func filterDevices(query string) map[string]DeviceStatus {
	results := make(map[string]DeviceStatus)
	for ip, device := range deviceStatus {
		if strings.Contains(strings.ToLower(device.IP), strings.ToLower(query)) || strings.Contains(strings.ToLower(device.DNS), strings.ToLower(query)) {
			results[ip] = device
		}
	}
	return results
}

// validateIP checks if the given IP address is valid
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// removeIP removes the specified IP from the list of IPs
func removeIP(ips []string, target string) []string {
	var result []string
	for _, ip := range ips {
		if ip != target {
			result = append(result, ip)
		}
	}
	return result
}
