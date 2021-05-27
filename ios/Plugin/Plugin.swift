import Foundation
import Capacitor
import SwiftKeychainWrapper


private let SecMatchLimit: String! = kSecMatchLimit as String
private let SecReturnData: String! = kSecReturnData as String
private let SecReturnPersistentRef: String! = kSecReturnPersistentRef as String
private let SecValueData: String! = kSecValueData as String
private let SecAttrAccessible: String! = kSecAttrAccessible as String
private let SecClass: String! = kSecClass as String
private let SecAttrService: String! = kSecAttrService as String
private let SecAttrGeneric: String! = kSecAttrGeneric as String
private let SecAttrAccount: String! = kSecAttrAccount as String
private let SecAttrAccessGroup: String! = kSecAttrAccessGroup as String
private let SecReturnAttributes: String = kSecReturnAttributes as String
private let SecAttrAccessControl: String = kSecAttrAccessControl as String
private let SecAttrSynchronizable: String = kSecAttrSynchronizable as String

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitor.ionicframework.com/docs/plugins/ios
 */
@objc(SecureStoragePlugin)
public class SecureStoragePlugin: CAPPlugin {
    var keychainwrapper: KeychainWrapper = KeychainWrapper.init(serviceName: "cap_sec")
    
    @objc func set(_ call: CAPPluginCall) {
        let key = call.getString("key") ?? ""
        let value = call.getString("value") ?? ""
        let mode = call.getString("mode") ?? ""
        
        switch mode {
        case "user_presence":            
            keychainwrapper.removeAllKeys()

            let encodedIdentifier: Data = key.data(using: String.Encoding.utf8)!

            let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlocked, .userPresence, nil)

            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                        SecAttrSynchronizable as String: false ? kCFBooleanTrue : kCFBooleanFalse,
                                        kSecAttrAccount as String: encodedIdentifier,
                                        SecAttrGeneric as String: encodedIdentifier,
                                        SecAttrService as String: keychainwrapper.serviceName,
                                        kSecAttrAccessControl as String: access as Any,
                                        kSecValueData as String: value.data(using: String.Encoding.utf8)!]

            let status = SecItemAdd(query as CFDictionary, nil)

            guard status == errSecSuccess else {
                print("Value could not be set")
                return
            }        
            
            call.resolve([
                "value": true
            ])
            
        default:
            let saveSuccessful: Bool = keychainwrapper.set(value, forKey: key)
            if(saveSuccessful) {
                call.resolve([
                    "value": saveSuccessful
                ])
            }
            else {
                call.reject("error")
            }
        }
        
        
    }
    
    @objc func get(_ call: CAPPluginCall) {
        let mode = call.getString("mode") ?? ""
        switch mode {
            case "user_presence":
                let key = call.getString("key") ?? ""
                call.resolve(["value": keychainwrapper.string(forKey: key) ?? ""])
            default:
                let key = call.getString("key") ?? ""
                let hasValueDedicated = keychainwrapper.hasValue(forKey: key)
                let hasValueStandard = KeychainWrapper.standard.hasValue(forKey: key)
                
                // copy standard value to dedicated and remove standard key
                if (hasValueStandard && !hasValueDedicated) {
                    let syncValueSuccessful: Bool = keychainwrapper.set(
                        KeychainWrapper.standard.string(forKey: key) ?? "",
                        forKey: key
                    )
                    let removeValueSuccessful: Bool = KeychainWrapper.standard.removeObject(forKey: key)
                    if (!syncValueSuccessful || !removeValueSuccessful) {
                        call.reject("error")
                    }
                }
                
                if(hasValueDedicated || hasValueStandard) {
                    call.resolve([
                        "value": keychainwrapper.string(forKey: key) ?? ""
                    ])
                }
                else {
                    call.reject("Item with given key does not exist")
                }
        }
    }
    
    @objc func keys(_ call: CAPPluginCall) {
        let keys = keychainwrapper.allKeys();
        call.resolve([
            "value": keys
        ])
    }
    
    @objc func remove(_ call: CAPPluginCall) {
        let key = call.getString("key") ?? ""
        KeychainWrapper.standard.removeObject(forKey: key);
        let removeDedicatedSuccessful: Bool = keychainwrapper.removeObject(forKey: key)
        if(removeDedicatedSuccessful) {
            call.success([
                "value": removeDedicatedSuccessful
            ])
        }
        else {
            call.error("error")
        }
    }
    
    @objc func clear(_ call: CAPPluginCall) {
        let keys = keychainwrapper.allKeys();
        // cleanup standard keychain wrapper keys
        for key in keys {
            let hasValueStandard = KeychainWrapper.standard.hasValue(forKey: key)
            if (hasValueStandard) {
                let removeStandardSuccessful = KeychainWrapper.standard.removeObject(forKey: key)
                if (!removeStandardSuccessful) {
                    call.error("error")
                }
            }
        }
        
        let clearSuccessful: Bool = keychainwrapper.removeAllKeys()
        if(clearSuccessful) {
            call.success([
                "value": clearSuccessful
            ])
        }
        else {
            call.error("error")
        }
    }
    
    @objc func getPlatform(_ call: CAPPluginCall) {
        call.success([
            "value": "ios"
        ])
    }
}
