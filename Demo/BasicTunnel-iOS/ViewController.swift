//
//  ViewController.swift
//  BasicTunnel-iOS
//
//  Created by Davide De Rosa on 2/11/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import UIKit
import NetworkExtension
import PIATunnel

class ViewController: UIViewController, URLSessionDataDelegate {
    static let APP_GROUP = "group.com.toh.app.vpn"
    
    static let VPN_BUNDLE = "com.toh.app.vpn.PacketTunnelProvider"

    static let CIPHER: PIATunnelProvider.Cipher = .aes128cbc

    static let DIGEST: PIATunnelProvider.Digest = .sha1

    static let HANDSHAKE: PIATunnelProvider.Handshake = .rsa2048
    
    static let RENEG: Int? = nil
    
    static let DOWNLOAD_COUNT = 5
    
    @IBOutlet var textUsername: UITextField!
    
    @IBOutlet var textPassword: UITextField!
    
    @IBOutlet var textServer: UITextField!
    
    @IBOutlet var textDomain: UITextField!
    
    @IBOutlet var textPort: UITextField!
    
    @IBOutlet var switchTCP: UISwitch!
    
    @IBOutlet var buttonConnection: UIButton!

    @IBOutlet var textLog: UITextView!

    //
    
    @IBOutlet var buttonDownload: UIButton!

    @IBOutlet var labelDownload: UILabel!
    
    var currentManager: NETunnelProviderManager?
    
    var status = NEVPNStatus.invalid
    
    var downloadTask: URLSessionDataTask!
    
    var downloadCount = 0

    var downloadTimes = [TimeInterval]()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        textServer.text = "germany"
        textDomain.text = "privateinternetaccess.com"
//        textServer.text = "159.122.133.238"
//        textDomain.text = ""
        textPort.text = "1198"
        switchTCP.isOn = false
        textUsername.text = "myusername"
        textPassword.text = "mypassword"
        
        NotificationCenter.default.addObserver(self,
                                               selector: #selector(VPNStatusDidChange(notification:)),
                                               name: .NEVPNStatusDidChange,
                                               object: nil)
        
        reloadCurrentManager(nil)

        //
        
        testFetchRef()
    }
    
    @IBAction func connectionClicked(_ sender: Any) {
        let block = {
            switch (self.status) {
            case .invalid, .disconnected:
                self.connect()
                
            case .connected, .connecting:
                self.disconnect()
                
            default:
                break
            }
        }
        
        if (status == .invalid) {
            reloadCurrentManager({ (error) in
                block()
            })
        }
        else {
            block()
        }
    }
    
    @IBAction func tcpClicked(_ sender: Any) {
        if switchTCP.isOn {
            textPort.text = "443"
        } else {
            textPort.text = "8080"
        }
    }
    
    func connect() {
//        let server = textServer.text!
//        let domain = textDomain.text!
        
//        let hostname = ((domain == "") ? server : [server, domain].joined(separator: "."))
//        let port = UInt16(textPort.text!)!
//        let username = textUsername.text!
//        let password = textPassword.text!
        
        guard let configData = readFile(path: "Untitled.ovpn"), let configString = String(data: configData, encoding: .utf8) else {
            print("Failed to read config file.")
            return
        }
        
        let config = OpenVPNConfigParser.parse(from: configString)
        print("=== PARSED CONFIGURATION ===")
        print(config.summary)
        
        print("\n=== DETAILED ANALYSIS ===")
        
        // Server Details
        if let remote = config.remote {
            print("🌐 Server: \(remote.hostname)")
            print("🔌 Port: \(remote.port)")
        }
        
        print("📡 Protocol: \(config.proto.rawValue.uppercased())")
        print("🔧 Device: \(config.dev.rawValue.uppercased())")
        
        // Security Settings
        print("\n🔒 SECURITY:")
        if !config.dataCiphers.isEmpty {
            print("   Data Ciphers: \(config.dataCiphers.joined(separator: ", "))")
        }
        if let auth = config.auth {
            print("   Authentication: \(auth)")
        }
        if let tlsMin = config.tlsVersionMin {
            print("   TLS Version Min: \(tlsMin)")
        }
        
        // Network Settings
        print("\n🌐 NETWORK:")
        if let mtu = config.tunMtu {
            print("   TUN MTU: \(mtu)")
        }
        if let mss = config.mssfix {
            print("   MSS Fix: \(mss)")
        }
        if let keepalive = config.keepalive {
            print("   Keepalive: ping \(keepalive.ping)s, restart \(keepalive.pingRestart)s")
        }
        
        // Buffer Settings
        print("\n📊 BUFFERS:")
        if let sndbuf = config.sndbuf {
            print("   Send Buffer: \(sndbuf)")
        }
        
        configureVPN({ (manager) in
//            manager.isOnDemandEnabled = true
//            manager.onDemandRules = [NEOnDemandRuleConnect()]
            
            let endpoint = PIATunnelProvider.AuthenticatedEndpoint(
                hostname: "vpnfree4.tohapp.com",
                username: "vpnfree4.tohapp.comfree",
                password: "VJ+Q>{|RfE30"
            )

            var builder = PIATunnelProvider.ConfigurationBuilder(appGroup: ViewController.APP_GROUP)
            builder.endpointProtocols = [PIATunnelProvider.EndpointProtocol(.udp, 1194, .vanilla)]
            builder.cipher = PIATunnelProvider.Cipher.aes128cbc
            builder.digest = PIATunnelProvider.Digest.sha1
//            builder.mtu = 1000 //NSNumber(integerLiteral: config.tunMtu ?? 1350)
//            builder.renegotiatesAfterSeconds = config.reneg
            
            if let _ = config.keepalive {
                
            }
            
            builder.shouldDebug = true
            builder.debugLogKey = "Log"
            
            builder.handshake = PIATunnelProvider.Handshake.custom
            builder.ca = """
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""
            
            let configuration = builder.build()
            return try! configuration.generatedTunnelProtocol(withBundleIdentifier: ViewController.VPN_BUNDLE, endpoint: endpoint)
        }, completionHandler: { (error) in
            if let error = error {
                print("configure error: \(error)")
                return
            }
            let session = self.currentManager?.connection as! NETunnelProviderSession
            do {
                try session.startTunnel()
            } catch let e {
                print("error starting tunnel: \(e)")
            }
        })
    }
    
    private func readFile(path: String) -> Data? {
        guard let filePath = Bundle.main.path(forResource: path, ofType: nil) else {
            print("File not found: \(path)")
            return nil
        }
        do {
            return try Data(contentsOf: URL(fileURLWithPath: filePath))
        } catch {
            print("Error reading file at \(path): \(error.localizedDescription)")
            return nil
        }
    }
    
    func disconnect() {
        configureVPN({ (manager) in
//            manager.isOnDemandEnabled = false
            return nil
        }, completionHandler: { (error) in
            self.currentManager?.connection.stopVPNTunnel()
        })
    }

    @IBAction func displayLog() {
        guard let vpn = currentManager?.connection as? NETunnelProviderSession else {
            return
        }
        try? vpn.sendProviderMessage(PIATunnelProvider.Message.requestLog.data) { (data) in
            guard let log = String(data: data!, encoding: .utf8) else {
                return
            }
            self.textLog.text = log
        }
    }

    @IBAction func download() {
        downloadCount = ViewController.DOWNLOAD_COUNT
        downloadTimes.removeAll()
        buttonDownload.isEnabled = false
        labelDownload.text = ""

        doDownload()
    }
    
    func doDownload() {
        let url = URL(string: "https://example.bogus/test/100mb")!
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        let cfg = URLSessionConfiguration.ephemeral
        let sess = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
        
        let start = Date()
        downloadTask = sess.dataTask(with: req) { (data, response, error) in
            if let error = error {
                print("error downloading: \(error)")
                return
            }
            
            let elapsed = -start.timeIntervalSinceNow
            print("download finished: \(elapsed) seconds")
            self.downloadTimes.append(elapsed)
            
            DispatchQueue.main.async {
                self.downloadCount -= 1
                if (self.downloadCount > 0) {
                    self.labelDownload.text = "\(self.labelDownload.text!)\(elapsed) seconds\n"
                    self.doDownload()
                } else {
                    var avg = 0.0
                    for n in self.downloadTimes {
                        avg += n
                    }
                    avg /= Double(ViewController.DOWNLOAD_COUNT)
                    
                    self.labelDownload.text = "\(avg) seconds"
                    self.buttonDownload.isEnabled = true
                }
            }
        }
        downloadTask.resume()
    }
    
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        print("received \(data.count) bytes")
    }
    
    func configureVPN(_ configure: @escaping (NETunnelProviderManager) -> NETunnelProviderProtocol?, completionHandler: @escaping (Error?) -> Void) {
        reloadCurrentManager { (error) in
            if let error = error {
                print("error reloading preferences: \(error)")
                completionHandler(error)
                return
            }
            
            let manager = self.currentManager!
            if let protocolConfiguration = configure(manager) {
                manager.protocolConfiguration = protocolConfiguration
            }
            manager.isEnabled = true
            
            manager.saveToPreferences { (error) in
                if let error = error {
                    print("error saving preferences: \(error)")
                    completionHandler(error)
                    return
                }
                print("saved preferences")
                self.reloadCurrentManager(completionHandler)
            }
        }
    }
    
    func reloadCurrentManager(_ completionHandler: ((Error?) -> Void)?) {
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if let error = error {
                completionHandler?(error)
                return
            }
            
            var manager: NETunnelProviderManager?
            
            for m in managers! {
                if let p = m.protocolConfiguration as? NETunnelProviderProtocol {
                    if (p.providerBundleIdentifier == ViewController.VPN_BUNDLE) {
                        manager = m
                        break
                    }
                }
            }
            
            if (manager == nil) {
                manager = NETunnelProviderManager()
            }
            
            self.currentManager = manager
            self.status = manager!.connection.status
            self.updateButton()
            completionHandler?(nil)
        }
    }
    
    func updateButton() {
        switch status {
        case .connected, .connecting:
            buttonConnection.setTitle("Disconnect", for: .normal)
            
        case .disconnected:
            buttonConnection.setTitle("Connect", for: .normal)
            
        case .disconnecting:
            buttonConnection.setTitle("Disconnecting", for: .normal)
            
        default:
            break
        }
    }
    
    @objc private func VPNStatusDidChange(notification: NSNotification) {
        guard let status = currentManager?.connection.status else {
            print("VPNStatusDidChange")
            return
        }
        
        switch status {
        case .invalid:
            print("VPNStatusDidChange: invalid")
        case .disconnected:
            print("VPNStatusDidChange: disconnected")
        case .connected:
            print("VPNStatusDidChange: connected")
        case .connecting:
            print("VPNStatusDidChange: connecting")
        case .reasserting:
            print("VPNStatusDidChange: reasserting")
        case .disconnecting:
            print("VPNStatusDidChange: disconnecting")
        }
        
        self.status = status
        updateButton()
    }
    
    private func testFetchRef() {
//        let keychain = Keychain(group: ViewController.APP_GROUP)
//        let username = "foo"
//        let password = "bar"
//        
//        guard let _ = try? keychain.set(password: password, for: username) else {
//            print("Couldn't set password")
//            return
//        }
//        guard let passwordReference = try? keychain.passwordReference(for: username) else {
//            print("Couldn't get password reference")
//            return
//        }
//        guard let fetchedPassword = try? Keychain.password(for: username, reference: passwordReference) else {
//            print("Couldn't fetch password")
//            return
//        }
//
//        print("\(username) -> \(password)")
//        print("\(username) -> \(fetchedPassword)")
    }
}

import Foundation

// MARK: - OpenVPN Configuration Model

struct OpenVPNConfig {
    // Connection Settings
    var remote: RemoteServer?
    var proto: Protocol = .udp
    var dev: DeviceType = .tun
    var port: Int?
    
    // Authentication
    var authUserPass: Bool = false
    var clientCertificate: String?
    var privateKey: String?
    
    // Certificates
    var caCertificate: String?
    var remoteCertTls: String?
    
    // Encryption & Security
    var cipher: String?
    var dataCiphers: [String] = []
    var auth: String?
    var tlsVersionMin: String?
    
    // Network Settings
    var tunMtu: Int?
    var mssfix: Int?
    var keepalive: Keepalive?
    
    // Connection Behavior
    var resolvRetry: String?
    var nobind: Bool = false
    var persistKey: Bool = false
    var persistTun: Bool = false
    var client: Bool = false
    var float: Bool = false
    var fastIo: Bool = false
    var explicitExitNotify: Int?
    var authNocache: Bool = false
    
    // Buffer Settings
    var sndbuf: Int?
    var rcvbuf: Int?
    
    // Advanced Settings
    var reneg: Int?
    var verb: Int?
    var pullFilters: [String] = []
    
    // Proxy Settings
    var httpProxy: ProxyServer?
    var httpProxyRetry: Bool = false
    
    // All raw configuration lines for debugging
    var rawLines: [String] = []
    var comments: [String] = []
}

// MARK: - Supporting Types

struct RemoteServer {
    let hostname: String
    let port: Int
    let proto: Protocol?
    
    init(hostname: String, port: Int, proto: Protocol? = nil) {
        self.hostname = hostname
        self.port = port
        self.proto = proto
    }
}

struct ProxyServer {
    let server: String
    let port: Int
}

struct Keepalive {
    let ping: Int
    let pingRestart: Int
}

enum Protocol: String, CaseIterable {
    case tcp = "tcp"
    case udp = "udp"
    case tcpClient = "tcp-client"
    case udpClient = "udp-client"
}

enum DeviceType: String, CaseIterable {
    case tun = "tun"
    case tap = "tap"
}

// MARK: - OpenVPN Parser

class OpenVPNConfigParser {
    
    static func parse(from content: String) -> OpenVPNConfig {
        var config = OpenVPNConfig()
        let lines = content.components(separatedBy: .newlines)
        
        var i = 0
        while i < lines.count {
            let line = lines[i].trimmingCharacters(in: .whitespacesAndNewlines)
            
            // Skip empty lines
            if line.isEmpty {
                i += 1
                continue
            }
            
            // Handle comments
            if line.hasPrefix("#") || line.hasPrefix(";") {
                config.comments.append(line)
                i += 1
                continue
            }
            
            config.rawLines.append(line)
            
            // Parse inline blocks (ca, cert, key)
            if line.hasPrefix("<") && line.hasSuffix(">") {
                let (blockContent, nextIndex) = parseInlineBlock(lines: lines, startIndex: i)
                i = nextIndex
                
                switch line {
                case "<ca>":
                    config.caCertificate = String(blockContent.dropLast())
                case "<cert>":
                    config.clientCertificate = blockContent
                case "<key>":
                    config.privateKey = blockContent
                default:
                    break
                }
                continue
            }
            
            // Parse configuration directives
            let components = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
            if !components.isEmpty {
                parseConfigurationLine(components: components, config: &config)
            }
            
            i += 1
        }
        
        return config
    }
    
    static func parse(from fileURL: URL) throws -> OpenVPNConfig {
        let content = try String(contentsOf: fileURL, encoding: .utf8)
        return parse(from: content)
    }
    
    // MARK: - Private Parsing Methods
    
    private static func parseInlineBlock(lines: [String], startIndex: Int) -> (String, Int) {
        var content = ""
        var i = startIndex + 1
        
        while i < lines.count {
            let line = lines[i].trimmingCharacters(in: .whitespacesAndNewlines)
            
            if line.hasPrefix("</") && line.hasSuffix(">") {
                break
            }
            
            if !content.isEmpty {
                content += "\n"
            }
            content += line
            i += 1
        }
        
        return (content, i + 1)
    }
    
    private static func parseConfigurationLine(components: [String], config: inout OpenVPNConfig) {
        guard !components.isEmpty else { return }
        
        let directive = components[0].lowercased()
        
        switch directive {
        // Connection Settings
        case "remote":
            if components.count >= 3 {
                let hostname = components[1]
                let port = Int(components[2]) ?? 1194
                let proto = components.count >= 4 ? Protocol(rawValue: components[3]) : nil
                config.remote = RemoteServer(hostname: hostname, port: port, proto: proto)
                if config.port == nil {
                    config.port = port
                }
            }
            
        case "proto":
            if components.count >= 2 {
                config.proto = Protocol(rawValue: components[1]) ?? .udp
            }
            
        case "dev":
            if components.count >= 2 {
                config.dev = DeviceType(rawValue: components[1]) ?? .tun
            }
            
        case "port":
            if components.count >= 2 {
                config.port = Int(components[1])
            }
            
        // Authentication
        case "auth-user-pass":
            config.authUserPass = true
            
        case "remote-cert-tls":
            if components.count >= 2 {
                config.remoteCertTls = components[1]
            }
            
        // Encryption & Security
        case "cipher":
            if components.count >= 2 {
                config.cipher = components[1]
            }
            
        case "data-ciphers":
            if components.count >= 2 {
                config.dataCiphers = Array(components[1...])
            }
            
        case "auth":
            if components.count >= 2 {
                config.auth = components[1]
            }
            
        case "tls-version-min":
            if components.count >= 2 {
                config.tlsVersionMin = components[1]
            }
            
        // Network Settings
        case "tun-mtu":
            if components.count >= 2 {
                config.tunMtu = Int(components[1])
            }
            
        case "mssfix":
            if components.count >= 2 {
                config.mssfix = Int(components[1])
            }
            
        case "keepalive":
            if components.count >= 3 {
                let ping = Int(components[1]) ?? 0
                let pingRestart = Int(components[2]) ?? 0
                config.keepalive = Keepalive(ping: ping, pingRestart: pingRestart)
            }
            
        // Connection Behavior
        case "resolv-retry":
            if components.count >= 2 {
                config.resolvRetry = components[1]
            }
            
        case "nobind":
            config.nobind = true
            
        case "persist-key":
            config.persistKey = true
            
        case "persist-tun":
            config.persistTun = true
            
        case "client":
            config.client = true
            
        case "float":
            config.float = true
            
        case "fast-io":
            config.fastIo = true
            
        case "explicit-exit-notify":
            if components.count >= 2 {
                config.explicitExitNotify = Int(components[1])
            } else {
                config.explicitExitNotify = 1
            }
            
        case "auth-nocache":
            config.authNocache = true
            
        // Buffer Settings
        case "sndbuf":
            if components.count >= 2 {
                config.sndbuf = Int(components[1])
            }
            
        case "rcvbuf":
            if components.count >= 2 {
                config.rcvbuf = Int(components[1])
            }
            
        // Advanced Settings
        case "reneg-sec":
            if components.count >= 2 {
                config.reneg = Int(components[1])
            }
            
        case "verb":
            if components.count >= 2 {
                config.verb = Int(components[1])
            }
            
        case "pull-filter":
            if components.count >= 2 {
                config.pullFilters.append(components[1...].joined(separator: " "))
            }
            
        // Proxy Settings
        case "http-proxy":
            if components.count >= 3 {
                let server = components[1]
                let port = Int(components[2]) ?? 8080
                config.httpProxy = ProxyServer(server: server, port: port)
            }
            
        case "http-proxy-retry":
            config.httpProxyRetry = true
            
        default:
            break
        }
    }
}

// MARK: - Configuration Export

extension OpenVPNConfig {
    
    var summary: String {
        var summary = "OpenVPN Configuration Summary:\n"
        summary += "================================\n\n"
        
        // Connection Info
        summary += "Connection Settings:\n"
        if let remote = remote {
            summary += "  Server: \(remote.hostname):\(remote.port)\n"
            if let proto = remote.proto {
                summary += "  Protocol: \(proto.rawValue.uppercased())\n"
            } else {
                summary += "  Protocol: \(proto.rawValue.uppercased())\n"
            }
        }
        summary += "  Device: \(dev.rawValue.uppercased())\n"
        
        // Security
        summary += "\nSecurity Settings:\n"
        if let cipher = cipher {
            summary += "  Cipher: \(cipher)\n"
        }
        if !dataCiphers.isEmpty {
            summary += "  Data Ciphers: \(dataCiphers.joined(separator: ", "))\n"
        }
        if let auth = auth {
            summary += "  Auth: \(auth)\n"
        }
        if let tlsMin = tlsVersionMin {
            summary += "  TLS Version Min: \(tlsMin)\n"
        }
        
        // Authentication
        summary += "\nAuthentication:\n"
        summary += "  Username/Password: \(authUserPass ? "Yes" : "No")\n"
        summary += "  Client Certificate: \(clientCertificate != nil ? "Yes" : "No")\n"
        summary += "  Private Key: \(privateKey != nil ? "Yes" : "No")\n"
        summary += "  CA Certificate: \(caCertificate != nil ? "Yes" : "No")\n"
        
        // Network Settings
        summary += "\nNetwork Settings:\n"
        if let mtu = tunMtu {
            summary += "  TUN MTU: \(mtu)\n"
        }
        if let mss = mssfix {
            summary += "  MSS Fix: \(mss)\n"
        }
        if let ka = keepalive {
            summary += "  Keepalive: \(ka.ping)s / \(ka.pingRestart)s\n"
        }
        
        // Connection Behavior
        summary += "\nConnection Behavior:\n"
        summary += "  Client Mode: \(client ? "Yes" : "No")\n"
        summary += "  Persist Key: \(persistKey ? "Yes" : "No")\n"
        summary += "  Persist Tun: \(persistTun ? "Yes" : "No")\n"
        summary += "  No Bind: \(nobind ? "Yes" : "No")\n"
        summary += "  Float: \(float ? "Yes" : "No")\n"
        
        return summary
    }
    
    var isValid: Bool {
        return remote != nil && caCertificate != nil
    }
    
    var requiresUserAuth: Bool {
        return authUserPass
    }
    
    var usesCertAuth: Bool {
        return clientCertificate != nil && privateKey != nil
    }
}

// MARK: - Usage Example

class OpenVPNConfigManager {
    
    static func loadConfig(from content: String) -> OpenVPNConfig {
        return OpenVPNConfigParser.parse(from: content)
    }
    
    static func loadConfig(from fileURL: URL) throws -> OpenVPNConfig {
        return try OpenVPNConfigParser.parse(from: fileURL)
    }
    
    static func validateConfig(_ config: OpenVPNConfig) -> [String] {
        var issues: [String] = []
        
        if config.remote == nil {
            issues.append("No remote server specified")
        }
        
        if config.caCertificate == nil {
            issues.append("No CA certificate found")
        }
        
        if config.authUserPass && config.usesCertAuth {
            issues.append("Both username/password and certificate authentication are enabled")
        }
        
        if !config.authUserPass && !config.usesCertAuth {
            issues.append("No authentication method specified")
        }
        
        return issues
    }
    
    // Convert config to NEVPNProtocol parameters
    static func convertToVPNParameters(_ config: OpenVPNConfig) -> [String: Any] {
        var parameters: [String: Any] = [:]
        
        if let remote = config.remote {
            parameters["serverAddress"] = remote.hostname
            parameters["serverPort"] = remote.port
        }
        
        parameters["protocol"] = config.proto.rawValue
        parameters["deviceType"] = config.dev.rawValue
        
        if let ca = config.caCertificate {
            parameters["caCertificate"] = ca
        }
        
        if let cert = config.clientCertificate {
            parameters["clientCertificate"] = cert
        }
        
        if let key = config.privateKey {
            parameters["privateKey"] = key
        }
        
        parameters["authUserPass"] = config.authUserPass
        
        if let cipher = config.cipher {
            parameters["cipher"] = cipher
        }
        
        if !config.dataCiphers.isEmpty {
            parameters["dataCiphers"] = config.dataCiphers
        }
        
        if let auth = config.auth {
            parameters["auth"] = auth
        }
        
        if let mtu = config.tunMtu {
            parameters["mtu"] = mtu
        }
        
        parameters["compress"] = false // Default for SoftEther
        parameters["verb"] = config.verb ?? 3
        
        return parameters
    }
}

// MARK: - Test the parser with your config

/*
Example usage:

let ovpnContent = """
// Your .ovpn file content here
"""

let config = OpenVPNConfigParser.parse(from: ovpnContent)
print(config.summary)

// Validate the configuration
let issues = OpenVPNConfigManager.validateConfig(config)
if issues.isEmpty {
    print("Configuration is valid!")
} else {
    print("Configuration issues:")
    issues.forEach { print("- \($0)") }
}

// Convert to VPN parameters
let vpnParams = OpenVPNConfigManager.convertToVPNParameters(config)
print("VPN Parameters: \(vpnParams)")
*/
