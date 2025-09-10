//
//  PacketTunnelProvider.swift
//  BasicTunnelExtension-iOS
//
//  Created by Davide De Rosa on 9/15/17.
//  Copyright © 2018 London Trust Media. All rights reserved.
//

import PIATunnel

class PacketTunnelProvider: PIATunnelProvider {
    
}

import NetworkExtension
import Foundation

// MARK: - OpenVPN Configuration Model
struct OpenVPNConfig {
    let serverAddress: String
    let serverPort: Int
    let connectProtocol: NEVPNProtocol
    let username: String
    let password: String
    let caCertificate: Data?
    let clientCertificate: Data?
    let clientKey: Data?
    let tlsAuthKey: Data?
    let cipher: String?
    let auth: String?
    let compLzo: Bool
    let remoteRandom: Bool
    
    enum NEVPNProtocol {
        case udp
        case tcp
        
        var stringValue: String {
            switch self {
            case .udp: return "udp"
            case .tcp: return "tcp"
            }
        }
    }
}

// MARK: - Custom OpenVPN Manager
class CustomOpenVPNManager: NSObject {
    
    // MARK: - Properties
    private var vpnManager: NEVPNManager
    private var config: OpenVPNConfig?
    
    // Connection state observers
    var onStatusChange: ((NEVPNStatus) -> Void)?
    var onError: ((Error) -> Void)?
    
    // MARK: - Initialization
    override init() {
        self.vpnManager = NEVPNManager.shared()
        super.init()
        setupNotifications()
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    // MARK: - Public Methods
    
    /// Configure the VPN with OpenVPN settings
    func configure(with config: OpenVPNConfig, completion: @escaping (Error?) -> Void) {
        self.config = config
        
        vpnManager.loadFromPreferences { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                completion(error)
                return
            }
            
            self.setupVPNConfiguration(config: config)
            
            self.vpnManager.saveToPreferences { saveError in
                DispatchQueue.main.async {
                    completion(saveError)
                }
            }
        }
    }
    
    /// Connect to the VPN
    func connect() throws {
        guard config != nil else {
            throw VPNError.notConfigured
        }
        
        guard vpnManager.connection.status != .connected &&
              vpnManager.connection.status != .connecting else {
            throw VPNError.alreadyConnected
        }
        
        try vpnManager.connection.startVPNTunnel()
    }
    
    /// Disconnect from the VPN
    func disconnect() {
        vpnManager.connection.stopVPNTunnel()
    }
    
    /// Get current connection status
    var connectionStatus: NEVPNStatus {
        return vpnManager.connection.status
    }
    
    /// Get connection statistics
    var connectionStatistics: [String: NSNumber]? {
        return vpnManager.connection.connectedDate != nil ?
            ["connectedDate": NSNumber(value: vpnManager.connection.connectedDate!.timeIntervalSince1970)] : nil
    }
    
    // MARK: - Private Methods
    
    private func setupNotifications() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(vpnStatusDidChange),
            name: .NEVPNStatusDidChange,
            object: nil
        )
    }
    
    @objc private func vpnStatusDidChange(_ notification: Notification) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.onStatusChange?(self.vpnManager.connection.status)
        }
    }
    
    private func setupVPNConfiguration(config: OpenVPNConfig) {
        // Create OpenVPN protocol configuration
        let protocolConfiguration = NEVPNProtocolIKEv2()
        
        // Basic server configuration
        protocolConfiguration.serverAddress = config.serverAddress
        protocolConfiguration.remoteIdentifier = config.serverAddress
        
        // Authentication
        protocolConfiguration.username = config.username
        protocolConfiguration.passwordReference = storePassword(config.password)
        
        // Certificate configuration
        if let caCertData = config.caCertificate {
            protocolConfiguration.certificateType = .RSA
            // Store CA certificate in keychain and reference it
            protocolConfiguration.identityReference = storeCertificate(caCertData, label: "OpenVPN_CA")
        }
        
        if let clientCertData = config.clientCertificate,
           let clientKeyData = config.clientKey {
            // Create identity from client certificate and key
            if let identity = createIdentity(certificate: clientCertData, privateKey: clientKeyData) {
                protocolConfiguration.identityReference = storeIdentity(identity, label: "OpenVPN_Client")
            }
        }
        
        // Advanced settings
        protocolConfiguration.useExtendedAuthentication = true
        protocolConfiguration.disconnectOnSleep = false
        
        // Custom OpenVPN specific settings via provider configuration
        var providerConfiguration: [String: Any] = [:]
        providerConfiguration["server"] = config.serverAddress
        providerConfiguration["port"] = config.serverPort
        providerConfiguration["protocol"] = config.connectProtocol.stringValue
        
        if let cipher = config.cipher {
            providerConfiguration["cipher"] = cipher
        }
        
        if let auth = config.auth {
            providerConfiguration["auth"] = auth
        }
        
        providerConfiguration["comp-lzo"] = config.compLzo
        providerConfiguration["remote-random"] = config.remoteRandom
        
        if let tlsAuthKey = config.tlsAuthKey {
            providerConfiguration["tls-auth"] = tlsAuthKey.base64EncodedString()
        }
        
        // Custom OpenVPN configuration string
        let openVPNConfig = buildOpenVPNConfig(config: config)
        providerConfiguration["ovpn"] = openVPNConfig
        
        // Note: For actual OpenVPN, you would need a Network Extension
        // This is a simplified example using IKEv2 as base
        vpnManager.protocolConfiguration = protocolConfiguration
        vpnManager.localizedDescription = "Custom OpenVPN Connection"
        vpnManager.isEnabled = true
    }
    
    private func buildOpenVPNConfig(config: OpenVPNConfig) -> String {
        var configString = """
        client
        dev tun
        proto \(config.connectProtocol.stringValue)
        remote \(config.serverAddress) \(config.serverPort)
        resolv-retry infinite
        nobind
        auth-user-pass
        persist-key
        persist-tun
        verb 3
        """
        
        if let cipher = config.cipher {
            configString += "\ncipher \(cipher)"
        }
        
        if let auth = config.auth {
            configString += "\nauth \(auth)"
        }
        
        if config.compLzo {
            configString += "\ncomp-lzo"
        }
        
        if config.remoteRandom {
            configString += "\nremote-random"
        }
        
        if config.caCertificate != nil {
            configString += "\n<ca>\n# CA Certificate will be embedded\n</ca>"
        }
        
        if config.clientCertificate != nil {
            configString += "\n<cert>\n# Client Certificate will be embedded\n</cert>"
        }
        
        if config.clientKey != nil {
            configString += "\n<key>\n# Private Key will be embedded\n</key>"
        }
        
        if config.tlsAuthKey != nil {
            configString += "\n<tls-auth>\n# TLS Auth Key will be embedded\n</tls-auth>\nkey-direction 1"
        }
        
        return configString
    }
    
    // MARK: - Keychain Helpers
    
    private func storePassword(_ password: String) -> Data? {
        let passwordData = password.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "OpenVPN_Password",
            kSecValueData as String: passwordData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecReturnPersistentRef as String: true
        ]
        
        // Delete existing item
        SecItemDelete(query as CFDictionary)
        
        var result: AnyObject?
        let status = SecItemAdd(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as? Data
        }
        return nil
    }
    
    private func storeCertificate(_ certificateData: Data, label: String) -> Data? {
        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
            return nil
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecValueRef as String: certificate,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecReturnPersistentRef as String: true
        ]
        
        // Delete existing item
        SecItemDelete(query as CFDictionary)
        
        var result: AnyObject?
        let status = SecItemAdd(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as? Data
        }
        return nil
    }
    
    private func createIdentity(certificate: Data, privateKey: Data) -> SecIdentity? {
        // This is a simplified version - in reality, you'd need to properly
        // parse and create the identity from certificate and private key
        guard SecCertificateCreateWithData(nil, certificate as CFData) != nil else {
            return nil
        }
        
        // For demo purposes - actual implementation would need proper key parsing
        return nil
    }
    
    private func storeIdentity(_ identity: SecIdentity, label: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecValueRef as String: identity,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
            kSecReturnPersistentRef as String: true
        ]
        
        // Delete existing item
        SecItemDelete(query as CFDictionary)
        
        var result: AnyObject?
        let status = SecItemAdd(query as CFDictionary, &result)
        
        if status == errSecSuccess {
            return result as? Data
        }
        return nil
    }
}

// MARK: - VPN Error Types
enum VPNError: Error, LocalizedError {
    case notConfigured
    case alreadyConnected
    case connectionFailed
    case configurationInvalid
    case authenticationFailed
    
    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "VPN is not configured"
        case .alreadyConnected:
            return "VPN is already connected"
        case .connectionFailed:
            return "Failed to establish VPN connection"
        case .configurationInvalid:
            return "Invalid VPN configuration"
        case .authenticationFailed:
            return "VPN authentication failed"
        }
    }
}

// MARK: - Usage Example
class VPNViewController: UIViewController {
    
    private let vpnManager = CustomOpenVPNManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupVPN()
    }
    
    private func setupVPN() {
        // Configure callbacks
        vpnManager.onStatusChange = { [weak self] status in
            self?.handleStatusChange(status)
        }
        
        vpnManager.onError = { [weak self] error in
            self?.handleError(error)
        }
        
        // Example configuration
        let config = OpenVPNConfig(
            serverAddress: "vpnfree4.tohapp.com",
            serverPort: 1194,
            connectProtocol: .udp,
            username: "vpnfree4.tohapp.comfree",
            password: "VJ+Q>{|RfE30",
            caCertificate: loadCertificateData("ca.crt"),
            clientCertificate: nil,
            clientKey: nil,
            tlsAuthKey: nil,
            cipher: "AES-256-CBC",
            auth: "SHA256",
            compLzo: true,
            remoteRandom: false
        )
        
        // Configure VPN
        vpnManager.configure(with: config) { [weak self] error in
            if let error = error {
                print("Configuration error: \(error)")
                return
            }
            print("VPN configured successfully")
        }
    }
    
    @IBAction func connectButtonTapped(_ sender: UIButton) {
        do {
            try vpnManager.connect()
        } catch {
            handleError(error)
        }
    }
    
    @IBAction func disconnectButtonTapped(_ sender: UIButton) {
        vpnManager.disconnect()
    }
    
    private func handleStatusChange(_ status: NEVPNStatus) {
        DispatchQueue.main.async {
            switch status {
            case .invalid:
                print("VPN Status: Invalid")
            case .disconnected:
                print("VPN Status: Disconnected")
            case .connecting:
                print("VPN Status: Connecting...")
            case .connected:
                print("VPN Status: Connected")
            case .reasserting:
                print("VPN Status: Reasserting")
            case .disconnecting:
                print("VPN Status: Disconnecting...")
            @unknown default:
                print("VPN Status: Unknown")
            }
        }
    }
    
    private func handleError(_ error: Error) {
        DispatchQueue.main.async {
            print("VPN Error: \(error.localizedDescription)")
            // Show error to user
        }
    }
    
    private func loadCertificateData(_ filename: String) -> Data? {
        guard let path = Bundle.main.path(forResource: filename, ofType: nil),
              let data = NSData(contentsOfFile: path) else {
            return nil
        }
        return data as Data
    }
}
