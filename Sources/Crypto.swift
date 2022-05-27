import Foundation
import Sodium
import Clibsodium

public enum Crypto {
    public static let PADDING: UInt = 32
    
    public enum Error: Swift.Error, Equatable {
        case couldNotDecrypt
        case invalidSize
        case couldNotUnpad
    }
    
    // MARK: - Key Derivation Functions
    public enum Kdf {
        public struct Salt: Equatable {
            public static let SIZE = Sodium().pwHash.SaltBytes
            
            public let value: Bytes
            
            public init(_ value: Bytes) throws {
                guard value.count == Kdf.Salt.SIZE else {
                    throw Error.invalidSize
                }
                
                self.value = value
            }
            
            public init() {
                // swiftlint:disable:next force_try
                try! self.init(Crypto.Misc.random(UInt(Kdf.Salt.SIZE)))
            }
        }
        
        public static func derivate(password: Password, salt: Salt, cpu: Int, ram: Int) -> Symmetric.Key {
            guard let result = Sodium().pwHash.hash(
                outputLength: Symmetric.Key.SIZE,
                passwd: password.trim().normalize().bytes,
                salt: salt.value,
                opsLimit: cpu,
                memLimit: ram,
                alg: .Argon2ID13
            ) else {
                fatalError("Misuse of derivate() function, check yuor CPU, RAM arguments")
            }
            
            // swiftlint:disable:next force_try
            return try! Symmetric.Key(result)
        }
    }
    
    // MARK: - Symmetric functions
    public enum Symmetric {
        public struct Key: Equatable {
            public static let SIZE = Sodium().aead.xchacha20poly1305ietf.KeyBytes
            
            public let value: Bytes
            
            public init(_ value: Bytes) throws {
                guard value.count == Symmetric.Key.SIZE else {
                    throw Error.invalidSize
                }
                
                self.value = value
            }
            
            public init() {
                // swiftlint:disable:next force_try
                try! self.init(Sodium().aead.xchacha20poly1305ietf.key())
            }
        }
        
        public static func encrypt(data: Bytes, key: Key) -> Bytes {
            guard let result: Bytes = Sodium().aead.xchacha20poly1305ietf.encrypt(message: Misc.pad(data), secretKey: key.value) else {
                fatalError("Misuse of encrypt()")
            }
            
            return result
        }
        
        public static func decrypt(data: Bytes, key: Key) throws -> Bytes {
            guard let result = Sodium().aead.xchacha20poly1305ietf.decrypt(nonceAndAuthenticatedCipherText: data, secretKey: key.value) else {
                throw Error.couldNotDecrypt
            }
            
            return try Misc.unpad(result)
        }
    }
    
    // MARK: - Misc functions
    public enum Misc {
        public static func random(_ lenght: UInt) -> Bytes {
            guard let result = Sodium().randomBytes.buf(length: Int(lenght)) else {
                fatalError("Misuse of random() function, lenght can't be 0")
            }
            
            return result
        }
        
        public static func zero(_ bytes: inout Bytes) {
            Sodium().utils.zero(&bytes)
        }
        
        public static func pad(_ bytes: Bytes, size: UInt = Crypto.PADDING) -> Bytes {
            var bytes = bytes
            
            guard Sodium().utils.pad(bytes: &bytes, blockSize: Int(size)) != nil else {
                fatalError("Misuse of pad() function")
            }
            
            return bytes
        }
        
        public static func unpad(_ bytes: Bytes, size: UInt = Crypto.PADDING) throws -> Bytes {
            var bytes = bytes
            
            guard Sodium().utils.unpad(bytes: &bytes, blockSize: Int(size)) != nil else {
                throw Error.couldNotUnpad
            }
            
            return bytes
        }

        public static func hex2bin(_ hex: String, ignore: String? = nil) -> Bytes? {
            return Sodium().utils.hex2bin(hex, ignore: ignore)
        }
        
        public static func bin2hex(_ bin: Bytes) -> String {
            guard let hex = Sodium().utils.bin2hex(bin) else {
                fatalError("Misuse of bin2hex() function")
            }
            
            return hex
        }
    }
    
    // MARK: - Asymmetric functions
    public enum Asymmetric {
        public struct PublicKey: Equatable {
            public static let SIZE = Sodium().box.PublicKeyBytes
            
            public let value: Bytes
            
            public init(_ value: Bytes) throws {
                guard value.count == Asymmetric.PublicKey.SIZE else {
                    throw Error.invalidSize
                }
                
                self.value = value
            }
            
            public init(key: PrivateKey) {
                var result = Bytes(repeating: 0, count: Asymmetric.PublicKey.SIZE)

                guard crypto_scalarmult_base(&result, key.value) == 0 else {
                    fatalError("Misuse of PublicKey.init()")
                }

                // swiftlint:disable:next force_try
                try! self.init(result)
            }
        }
        
        public struct PrivateKey: Equatable {
            public static let SIZE = Sodium().box.SecretKeyBytes
            
            public let value: Bytes
            
            public init(_ value: Bytes) throws {
                guard value.count == Asymmetric.PrivateKey.SIZE else {
                    throw Error.invalidSize
                }
                
                self.value = value
            }
            
            public init() {
                // swiftlint:disable:next force_unwrapping force_try
                try! self.init(Sodium().box.keyPair()!.secretKey)
            }
        }

        // MARK: - Asymmetric Authenticated
        
        public enum Authenticated {
            /// More: https://github.com/jedisct1/swift-sodium#authenticated-encryption
            public static func encrypt(bytes: Bytes, recipientPublicKey: PublicKey, senderPrivateKey: PrivateKey) -> Bytes {
                guard let result: Bytes = Sodium().box.seal(message: bytes, recipientPublicKey: recipientPublicKey.value, senderSecretKey: senderPrivateKey.value) else {
                    fatalError("Function misused!")
                }
                
                return result
            }
            
            /// More: https://github.com/jedisct1/swift-sodium#authenticated-encryption
            public static func decrypt(bytes: Bytes, senderPublicKey: PublicKey, recipientPrivateKey: PrivateKey) throws -> Bytes {
                guard let result = Sodium().box.open(nonceAndAuthenticatedCipherText: bytes, senderPublicKey: senderPublicKey.value, recipientSecretKey: recipientPrivateKey.value) else {
                    throw Error.couldNotDecrypt
                }
                
                return result
            }
        }
        
        // MARK: - Asymmetric Anonymous
        
        public enum Anonymous {
            /// More: https://github.com/jedisct1/swift-sodium#anonymous-encryption-sealed-boxes
            public static func encrypt(bytes: Bytes, recipientPublicKey: PublicKey) -> Bytes {
                guard let result = Sodium().box.seal(message: bytes, recipientPublicKey: recipientPublicKey.value) else {
                    fatalError("Function misused!")
                }
                
                return result
            }
            
            /// More: https://github.com/jedisct1/swift-sodium#anonymous-encryption-sealed-boxes
            public static func decrypt(bytes: Bytes, recipientPublicKey: PublicKey, recipientPrivateKey: PrivateKey) throws -> Bytes {
                guard let result = Sodium().box.open(anonymousCipherText: bytes, recipientPublicKey: recipientPublicKey.value, recipientSecretKey: recipientPrivateKey.value) else {
                    throw Error.couldNotDecrypt
                }
                
                return result
            }
        }
    }
    
    // MARK: - Hash functions
    public enum Hash {
        public enum Short {
            public struct Key: Equatable {
                public static let SIZE = Sodium().shortHash.KeyBytes
                
                public let value: Bytes
                
                public init(_ value: Bytes) throws {
                    guard value.count == Hash.Short.Key.SIZE else {
                        throw Error.invalidSize
                    }
                    
                    self.value = value
                }
                
                public init() {
                    // swiftlint:disable:next force_try
                    try! self.init(Sodium().shortHash.key())
                }
            }
            
            public static func hash(bytes: Bytes, key: Key) -> Bytes {
                let sodium = Sodium()
                
                guard let result = sodium.shortHash.hash(message: bytes, key: key.value) else {
                    fatalError("Misuse of hash() function")
                }
                
                return result
            }
        }
    }
}

public struct SodiumRandomNumberGenerator: RandomNumberGenerator {
    private let sodium = Sodium()
    
    public init() {}
    
    public mutating func next() -> UInt64 {
        guard let bytes = self.sodium.randomBytes.buf(length: MemoryLayout<UInt64>.size) else {
            fatalError("Sodium Random Number Generator is broken.")
        }
        
        return bytes.withUnsafeBytes { pointer in
            return pointer.load(as: UInt64.self)
        }
    }
}
