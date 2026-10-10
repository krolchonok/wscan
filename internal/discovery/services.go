package discovery

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// portFreq pairs a port with its observed-open frequency from nmap-services.
type portFreq struct {
	port int
	freq float64
}

type serviceDatabase struct {
	tcpRanked []int
	udpRanked []int
	names     map[string]map[int]string
}

type serviceCacheEntry struct {
	modified int64
	size     int64
	database *serviceDatabase
}

var serviceCache = struct {
	sync.Mutex
	entries map[string]serviceCacheEntry
}{entries: make(map[string]serviceCacheEntry)}

// loadServices caches an immutable database per file, reloading after updates.
func loadServices(libraryDir string) *serviceDatabase {
	path := filepath.Join(libraryDir, "nmap", "nmap-services")
	if libraryDir == "" {
		for _, candidate := range []string{filepath.Join("library", "nmap", "nmap-services"), "/usr/share/nmap/nmap-services", "/usr/local/share/nmap/nmap-services"} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return &serviceDatabase{}
	}
	info, err := os.Stat(path)
	if err != nil {
		return &serviceDatabase{}
	}
	serviceCache.Lock()
	defer serviceCache.Unlock()
	if cached, ok := serviceCache.entries[path]; ok && cached.modified == info.ModTime().UnixNano() && cached.size == info.Size() {
		return cached.database
	}
	f, err := os.Open(path)
	if err != nil {
		return &serviceDatabase{}
	}
	defer f.Close()
	database := &serviceDatabase{names: map[string]map[int]string{"tcp": {}, "udp": {}}}
	frequencies := map[string][]portFreq{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		portProto := strings.SplitN(fields[1], "/", 2)
		if len(portProto) != 2 || (portProto[1] != "tcp" && portProto[1] != "udp") {
			continue
		}
		port, err := strconv.Atoi(portProto[0])
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		freq := 0.0
		if len(fields) >= 3 {
			freq, _ = strconv.ParseFloat(fields[2], 64)
		}
		proto := portProto[1]
		frequencies[proto] = append(frequencies[proto], portFreq{port: port, freq: freq})
		if knownService(fields[0]) && database.names[proto][port] == "" {
			database.names[proto][port] = fields[0]
		}
	}
	if scanner.Err() != nil {
		return &serviceDatabase{}
	}
	for proto, ports := range frequencies {
		sort.SliceStable(ports, func(i, j int) bool { return ports[i].freq > ports[j].freq })
		seen := make(map[int]bool)
		var ranked []int
		for _, item := range ports {
			if !seen[item.port] {
				ranked = append(ranked, item.port)
				seen[item.port] = true
			}
		}
		if proto == "tcp" {
			database.tcpRanked = ranked
		} else {
			database.udpRanked = ranked
		}
	}
	serviceCache.entries[path] = serviceCacheEntry{modified: info.ModTime().UnixNano(), size: info.Size(), database: database}
	return database
}

// PortServiceName is a port/protocol registry hint, not a detected protocol.
func PortServiceName(libraryDir, proto string, port int) string {
	return loadServices(libraryDir).names[strings.ToLower(proto)][port]
}

// TopPorts returns ports ranked by Nmap's observed-open frequency.
func TopPorts(libraryDir, proto string, n int) []int {
	if n <= 0 {
		return nil
	}
	database := loadServices(libraryDir)
	ranked := database.tcpRanked
	if proto == "udp" {
		ranked = database.udpRanked
	}
	if len(ranked) == 0 {
		fallback := commonPorts
		if proto == "udp" {
			fallback = []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 5353}
		}
		return append([]int(nil), fallback[:min(n, len(fallback))]...)
	}
	out := append([]int(nil), ranked[:min(n, len(ranked))]...)
	sort.Ints(out)
	return out
}

// ParsePortList parses a user port specification such as "22,80,443,8000-8100"
// into a sorted, de-duplicated list, ignoring malformed entries.
func ParsePortList(spec string) []int {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for p := lo; p <= hi; p++ {
				add(p)
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			add(p)
		}
	}
	sort.Ints(out)
	return out
}
