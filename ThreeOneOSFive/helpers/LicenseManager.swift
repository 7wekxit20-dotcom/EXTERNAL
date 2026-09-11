import Combine
import Foundation
import Security

@MainActor
final class LicenseManager: ObservableObject {
    // === CONFIGURE YOUR HOST HERE ===
    static let apiURL = "https://ogios-key-server.onrender.com/api/verify" // e.g. https://ogios-keys.onrender.com/api/verify or http://YOUR_VPS:5000/api/verify
    static let legacyKey = "OGIOS" // kept for offline fallback, remove if you want pure API
    // =================================

    @Published private(set) var expirationDate: Date?
    @Published private(set) var isActive = false
    @Published private(set) var isBusy = false
    @Published private(set) var message: String?
    @Published private(set) var contactOwner: String?
    @Published var rememberKey = true

    private let service = "com.OGIOS.external-ios.activation"
    private let keyAccount = "license-key"
    private var lastAttemptAt: Date?

    init() {
        isActive = hasRememberedKey
    }

    var hasRememberedKey: Bool {
        // any stored key counts as active (after successful API verify). Remove legacy check if pure API.
        if let k = string(for: keyAccount), !k.isEmpty {
            return true // or: return k == Self.legacyKey for old behavior
        }
        return false
    }

    func beginLaunchSession() {
        isActive = hasRememberedKey
        message = isActive ? "Ready to use" : "Key required — enter your access key"
    }

    func activate(key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isBusy else { return }
        if let lastAttemptAt, Date().timeIntervalSince(lastAttemptAt) < 1 {
            message = "Please wait a moment before trying again"
            return
        }
        lastAttemptAt = Date()
        isBusy = true
        message = "Checking access key…"

        // --- API VERIFY ---
        guard let url = URL(string: Self.apiURL) else {
            isBusy = false; isActive = false; message = "Bad API URL"
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.timeoutInterval = 12
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["key": trimmed])
        // also send device identifier as hwid (optional binding)
        // req.httpBody = try? JSONSerialization.data(withJSONObject: ["key": trimmed, "hwid": UIDevice.current.identifierForVendor?.uuidString ?? ""])

        URLSession.shared.dataTask(with: req) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self else { return }
                self.isBusy = false
                if let error = error {
                    // offline fallback: allow legacy OGIOS key without network
                    if trimmed == Self.legacyKey {
                        if self.rememberKey { self.save(trimmed, for: self.keyAccount) }
                        self.isActive = true; self.message = "Activated (offline)"
                        return
                    }
                    self.isActive = false; self.message = "Network error: \(error.localizedDescription)"
                    return
                }
                guard let data, let json = try? JSONSerialization.jsonObject(with: data) as? [String:Any] else {
                    self.isActive = false; self.message = "Invalid server response"
                    return
                }
                let valid = (json["valid"] as? Bool) ?? false
                let reason = (json["reason"] as? String) ?? ""
                if valid {
                    if self.rememberKey { self.save(trimmed, for: self.keyAccount) }
                    self.isActive = true; self.message = "Activated successfully"
                    if let exp = json["expires_at"] as? String {
                        self.message = "Activated — expires \(exp)"
                    }
                } else {
                    self.isActive = false
                    // map reason from server: invalid, expired, revoked, max uses reached
                    switch reason {
                    case "expired": self.message = "Key expired"
                    case "revoked": self.message = "Key revoked"
                    case "max uses reached": self.message = "Key max uses reached"
                    default: self.message = "Invalid access key"
                    }
                }
            }
        }.resume()
    }

    func rememberedKey() -> String? { string(for: keyAccount) }

    func refresh() {
        isActive = hasRememberedKey
        message = isActive ? "Ready to use" : "Key required — enter your access key"
    }

    func deactivate() {
        delete(keyAccount)
        isActive = false
        message = "Activation removed from this device"
    }

    private func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
