import Foundation
import ExpoModulesCore

extension StringProtocol {
    var hexaData: Data { .init(hexa) }
    var hexaBytes: [UInt8] { .init(hexa) }
    private var hexa: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }
}

public class SecureEnclaveModule: Module {

  /// Signing algorithm used by Enclave
  static var algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256

  /// Internal function to get an enclave key handle using key alias
  private func getKeyHandle(_ alias: String) -> SecKey? {
    let tag = alias.data(using: .utf8)!

    // Build query to get security key
    let query: [String: Any] = [
      kSecClass as String               : kSecClassKey,
      kSecAttrApplicationTag as String  : tag,
      kSecAttrKeyType as String         : kSecAttrKeyTypeEC,
      kSecReturnRef as String           : true
    ]
    
    // Get key using the query
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else {
      print("[SecureEnclaveModule] No key found")
      return nil
    }
    
    return (item as! SecKey)
  }

  /// Internal function to sign a message key handle
  private func sign(_ message: String, _ keyHandle: SecKey) throws -> String {

      // print(message)
      // let byteArray:[UInt8] = [UInt8](message.utf8)
      // print(byteArray)
      // let userOpHash = "a4103b178558b8a8f53f17118cae2cb5e14c77d6858d174a3a2030ce5c93ba45"
      let array = message.hexaBytes
      let messageData = CFDataCreate(kCFAllocatorDefault, array, array.count)!//message as! CFData
      print(messageData)
    
    guard SecKeyIsAlgorithmSupported( keyHandle, .sign, SecureEnclaveModule.algorithm ) else {
      throw NSError(domain: "SecureEnclaveModule: Algorithm Not Supported", code: 1, userInfo: nil)
    }
    
    var error: Unmanaged<CFError>?
    
    let signedMessage = SecKeyCreateSignature(
      keyHandle,
      SecureEnclaveModule.algorithm,
      messageData,
      &error
    )
    
    guard signedMessage != nil else {
      print(error!.takeUnretainedValue() as Error)
      throw NSError(domain: "SecureEnclaveModule: Signing Failed", code: 2, userInfo: nil)
    }
    
    return (signedMessage! as Data).hexEncodedString()
  }

  // See https://docs.expo.dev/modules/module-api for more info about Expo Modules
  public func definition() -> ModuleDefinition {
    Name("SecureEnclave")

    AsyncFunction("getPublicKey") { (alias: String, promise: Promise) in
      let keyHandle = getKeyHandle(alias)

      // Check if key handle is not nil
      guard keyHandle != nil else {
        promise.reject("ERR_KEY_HANDLE_GET", "Can't get the key handle")
        return
      }

      // Try to copy public key
      var error: Unmanaged<CFError>?
      guard let pubKey = SecKeyCopyPublicKey(keyHandle!) else {
        promise.reject("ERR_PUB_KEY_COPY", "Can't copy public key")
        return
      }

      // Get the external representation of the public key
      guard let pubExt = SecKeyCopyExternalRepresentation(pubKey, &error) else {
        promise.reject("ERR_PUB_KEY_EXPORT", "Can't export public key")
        print(error!)
        return
      }

      // Add curve header
      // DEV: this might be unnecessary
      let publicKeyDER = prependCurveHeader(pubKeyData: pubExt as Data)

      promise.resolve(publicKeyDER.hexEncodedString())
    }

    AsyncFunction("generateKeyPair") { (alias: String, promise: Promise) in
      let flags: SecAccessControlCreateFlags = .biometryAny;
    
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        nil
      )!
    
      let tag = alias.data(using: .utf8)!
      let attributes: [String: Any] = [
        kSecClass as String             : kSecClassKey,
        kSecAttrKeyType as String       : kSecAttrKeyTypeEC,
        kSecAttrKeySizeInBits as String : 256,
        // DEV: Using this flag causes -25293 key generation error
        // kSecAttrTokenID as String       : kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String   : [
          kSecAttrIsPermanent as String     : true,
          kSecAttrApplicationTag as String  : tag,
          kSecAttrAccessControl as String   : access,
          kSecUseAuthenticationUI as String : kSecUseAuthenticationUIAllow
        ]
      ]
      
      var error: Unmanaged<CFError>?
    
      guard let privateKey = SecKeyCreateRandomKey(
        attributes as CFDictionary,
        &error
      ) else {
        promise.reject("ERR_PAIR_GENERATE", "Can't generate keypair")
        print(error!.takeRetainedValue() as Error)
        return
      }
    
      guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        promise.reject("ERR_PUB_KEY_GET", "Can't get public key")
        return
      }
    
      guard let pubExt = SecKeyCopyExternalRepresentation(
        publicKey,
        &error
      ) else {
        promise.reject("ERR_PUB_KEY_EXPORT", "Can't export public key")
        return
      }
    
      // Add curve header
      // DEV: this might be unnecessary
      let publicKeyDER = prependCurveHeader(pubKeyData: pubExt as Data)
    
      promise.resolve((pubExt as Data).hexEncodedString());
    }

    AsyncFunction("deleteKeyPair") { (alias: String, promise: Promise) in
      let tag = String(alias).data(using: .utf8)!
      
      let query: [String: Any] = [
        kSecClass as String               : kSecClassKey,
        kSecAttrApplicationTag as String  : tag,
        kSecAttrKeyType as String         : kSecAttrKeyTypeEC,
        kSecReturnRef as String           : true
      ]

      let status = SecItemDelete(query as CFDictionary)
      
      guard status == errSecSuccess else {
        promise.reject("ERR_PAIR_DELETE", "Can't delete keypair")
        return;
      }
      
      promise.resolve(true);
    }

    AsyncFunction("signMessage") { (alias: String, message: String, promise: Promise) in
      // Get the key handle
      let keyHandle = getKeyHandle(alias)

      // Check if key handle is not nil
      guard keyHandle != nil else {
        promise.reject("ERR_KEY_HANDLE_GET", "Can't get the key handle")
        return
      }
      
      // Try to sign the message
      do {
        let signature = try sign(message, keyHandle!)
        promise.resolve(signature)
      } catch {
        print(error)
        promise.reject("ERR_UNKNOWN", "Unknown error")
      }
    }
  }
}

/// Adds SECP256R1 curve header to the public key
func prependCurveHeader(pubKeyData: Data) -> Data {
  let secp256R1Header = Data(_: [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07, 0x03, 0x42, 0x00
  ])

  return secp256R1Header + pubKeyData
}
