import Foundation
import ExpoModulesCore

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
    let messageData = message.data(using: .utf8)! as CFData
    
    guard SecKeyIsAlgorithmSupported( keyHandle, .sign, EnclaveModule.algorithm ) else {
      throw NSError(domain: "SecureEnclaveModule: Algorithm Not Supported", code: 1, userInfo: nil)
    }
    
    var error: Unmanaged<CFError>?
    
    let signedMessage = SecKeyCreateSignature(
      keyHandle,
      EnclaveModule.algorithm,
      messageData,
      &error
    )
    
    guard signedMessage != nil else {
      print(error?.takeRetainedValue() as Error)
      throw NSError(domain: "SecureEnclaveModule: Signing Failed", code: 2, userInfo: nil)
    }
    
    return (signedMessage! as Data).base64EncodedString()
  }

  // Each module class must implement the definition function. The definition consists of components
  // that describes the module's functionality and behavior.
  // See https://docs.expo.dev/modules/module-api for more details about available components.
  public func definition() -> ModuleDefinition {
    // Sets the name of the module that JavaScript code will use to refer to the module. Takes a string as an argument.
    // Can be inferred from module's class name, but it's recommended to set it explicitly for clarity.
    // The module will be accessible from `requireNativeModule('SecureEnclave')` in JavaScript.
    Name("SecureEnclave")

    // Sets constant properties on the module. Can take a dictionary or a closure that returns a dictionary.
    Constants([
      "PI": Double.pi
    ])

    // Defines event names that the module can send to JavaScript.
    Events("onChange")

    // Defines a JavaScript synchronous function that runs the native code on the JavaScript thread.
    Function("hello") {
      return "Hello world! 👋"
    }

    // Defines a JavaScript function that always returns a Promise and whose native code
    // is by default dispatched on the different thread than the JavaScript runtime runs on.
    AsyncFunction("setValueAsync") { (value: String) in
      // Send an event to JavaScript.
      self.sendEvent("onChange", [
        "value": value
      ])
    }

    // Enables the module to be used as a native view. Definition components that are accepted as part of the
    // view definition: Prop, Events.
    View(SecureEnclaveView.self) {
      // Defines a setter for the `name` prop.
      Prop("name") { (view: SecureEnclaveView, prop: String) in
        print(prop)
      }
    }

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

      promise.resolve(publicKeyDER.base64EncodedString())
    }

    AsyncFunction("generateKeyPair") { (alias: String, promise: Promise) in
      let flags: SecAccessControlCreateFlags = .biometryAny;
    
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        nil
      )!
    
      let tag = String(alias).data(using: .utf8)!
      let attributes: [String: Any] = [
        kSecClass as String             : kSecClassKey,
        kSecAttrKeyType as String       : kSecAttrKeyTypeEC,
        kSecAttrKeySizeInBits as String : 256,
        kSecAttrTokenID as String       : kSecAttrTokenIDSecureEnclave,
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
        let err = error!.takeRetainedValue() as Error
        promise.reject("ERR_PAIR_GENERATE", "Can't generate keypair")
        print(err)
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
    
      promise.resolve(publicKeyDER.base64EncodedString());
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
      let keyHandle = getKeyHandle(alias)!
      
      // Try to sign the message
      do {
        let signature = try sign(message, keyHandle)
        promise.resolve(signature)
      } catch {
        print(error) 
        promise.reject(nil, "Unknown error", nil)
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
