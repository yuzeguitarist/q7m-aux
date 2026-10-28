import Foundation
import Security

let account = "synthetic-isolation-smoke"
let payload = Data("synthetic-value-not-a-secret".utf8)
let item: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: account,
    kSecAttrAccount as String: account,
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecValueData as String: payload,
]
SecItemDelete(item as CFDictionary)
guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { exit(10) }
var query = item
query.removeValue(forKey: kSecValueData as String)
query[kSecReturnData as String] = true
query[kSecMatchLimit as String] = kSecMatchLimitOne
var found: CFTypeRef?
guard SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess,
      found as? Data == payload else { exit(11) }
guard SecItemDelete(item as CFDictionary) == errSecSuccess else { exit(12) }

