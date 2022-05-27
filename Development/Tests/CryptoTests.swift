// swiftlint:disable force_try
import XCTest
@testable import KryptoKit

class CryptoTests: XCTestCase {
    override func invokeTest() {
        for _ in 0...Int.random(in: 5..<10) {
            super.invokeTest()
        }
    }
    
    func testKdfSalt() {
        let salt = Crypto.Kdf.Salt()
        
        XCTAssert(try! Crypto.Kdf.Salt(salt.value) == salt)
    }
    
    func testKdfSaltInvalid() {
        let salt = Crypto.Kdf.Salt()
        
        XCTAssertThrowsError(try Crypto.Kdf.Salt(salt.value + [0x1])) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.invalidSize)
        }
    }
    
    func testKdfDerivate() {
        let password = "123"
        let salt = Crypto.Kdf.Salt()
        let cpu = 16
        let ram = 1_024 * 1_024
        
        let result = Crypto.Kdf.derivate(password: .init(password), salt: salt, cpu: cpu, ram: ram)
        
        XCTAssert(Crypto.Kdf.derivate(password: .init(password), salt: salt, cpu: cpu, ram: ram * 5) != result)
        XCTAssert(Crypto.Kdf.derivate(password: .init(password), salt: salt, cpu: cpu + 16, ram: ram) != result)
        XCTAssert(Crypto.Kdf.derivate(password: .init(password), salt: Crypto.Kdf.Salt(), cpu: cpu, ram: ram) != result)
        XCTAssert(Crypto.Kdf.derivate(password: .init("321"), salt: salt, cpu: cpu, ram: ram) != result)
        
        XCTAssert(Crypto.Kdf.derivate(password: .init(password), salt: salt, cpu: cpu, ram: ram) == result)
    }
    
    func testSymmetricKeyInvalid() {
        XCTAssertThrowsError(try Crypto.Symmetric.Key([0x1])) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.invalidSize)
        }
    }
    
    func testEncryptDecrypt() {
        let key = Crypto.Symmetric.Key()
        let data: Bytes = [0x6, 0x6, 0x6]
        
        let encrypted = Crypto.Symmetric.encrypt(data: data, key: key)
        let decrypted = try! Crypto.Symmetric.decrypt(data: encrypted, key: key)
        
        XCTAssert(decrypted == data)
        
        // Invalid Key
        XCTAssertThrowsError(try Crypto.Symmetric.decrypt(data: encrypted, key: Crypto.Symmetric.Key())) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.couldNotDecrypt)
        }
        
        // Invalid Data
        XCTAssertThrowsError(try Crypto.Symmetric.decrypt(data: [0x0, 0x0, 0x0], key: key)) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.couldNotDecrypt)
        }
    }
    
    func testUtilsPadUnpad() {
        let data: Bytes = [0x6, 0x6, 0x6]
        
        let padded = Crypto.Misc.pad(data)
        
        XCTAssert(padded.count == Crypto.PADDING)
        
        let unpadded = try! Crypto.Misc.unpad(padded)
        
        XCTAssert(data == unpadded)
    }
    
    func testUtilsPad0() {
        let initial = Bytes([])
        
        let padded = Crypto.Misc.pad(initial)
        let unpadded = try! Crypto.Misc.unpad(padded)
        
        XCTAssert(initial == unpadded)
    }
    
    func testUtilsPadInvalid() {
        XCTAssertThrowsError(try Crypto.Misc.unpad([0x1, 0x2, 0x3])) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.couldNotUnpad)
        }
    }
    
    func testUtilsZero() {
        var data: Bytes = [0x6, 0x6, 0x6]
        
        Crypto.Misc.zero(&data)
        
        XCTAssert(data == Bytes(Data(repeating: 0, count: data.count)))
    }
    
    func testHex2Bin() {
        XCTAssert(Crypto.Misc.hex2bin("FFFF") == [255, 255])
        XCTAssert(Crypto.Misc.hex2bin("FF FF", ignore: " ") == [255, 255])
        XCTAssert(Crypto.Misc.hex2bin("FF-FF", ignore: "-") == [255, 255])
    }
    
    func testBin2Hex() {
        XCTAssert(Crypto.Misc.bin2hex(Bytes([255, 255])) == "ffff")
        XCTAssert(Crypto.Misc.bin2hex(Bytes([])).isEmpty)
        XCTAssert(Crypto.Misc.bin2hex(Bytes([0x0])) == "00")
    }
    
    func testAsymmetricPrivateKey() {
        let key = Crypto.Asymmetric.PrivateKey()
        
        XCTAssert(try! Crypto.Asymmetric.PrivateKey(key.value) == key)
    }
    
    func testAsymmetricPrivateKeyInvalid() {
        XCTAssertThrowsError(try Crypto.Asymmetric.PrivateKey([0x1, 0x2, 0x3])) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.invalidSize)
        }
    }
    
    func testAsymmetricPublicKey() {
        let privateKey = Crypto.Asymmetric.PrivateKey()
        let publicKey = Crypto.Asymmetric.PublicKey(key: privateKey)
        
        XCTAssert(try! Crypto.Asymmetric.PublicKey(publicKey.value) == publicKey)
    }
    
    func testAsymmetricPublicKeyInvalid() {
        XCTAssertThrowsError(try Crypto.Asymmetric.PublicKey([0x1, 0x2, 0x3])) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.invalidSize)
        }
    }
    
    func testAsymmetricEncryptAndDecryptAuthenticated() {
        let data: Bytes = [0x6, 0x6, 0x6]
        
        let alicePrivateKey = Crypto.Asymmetric.PrivateKey()
        let alicePublicKey = Crypto.Asymmetric.PublicKey(key: alicePrivateKey)
        
        let bobPrivateKey = Crypto.Asymmetric.PrivateKey()
        let bobPublicKey = Crypto.Asymmetric.PublicKey(key: bobPrivateKey)
        
        let encrypted = Crypto.Asymmetric.Authenticated.encrypt(bytes: data, recipientPublicKey: bobPublicKey, senderPrivateKey: alicePrivateKey)
        let decrypted = try! Crypto.Asymmetric.Authenticated.decrypt(bytes: encrypted, senderPublicKey: alicePublicKey, recipientPrivateKey: bobPrivateKey)
        
        XCTAssert(encrypted != data)
        XCTAssert(decrypted == data)
    }
    
    func testAsymmetricEncryptAndDecryptAuthenticatedInvalid() {
        let data: Bytes = [0x6, 0x6, 0x6]
        
        let alicePrivateKey = Crypto.Asymmetric.PrivateKey()
        
        let bobPrivateKey = Crypto.Asymmetric.PrivateKey()
        let bobPublicKey = Crypto.Asymmetric.PublicKey(key: bobPrivateKey)
        
        let fakePrivateKey = Crypto.Asymmetric.PrivateKey()
        let fakePublicKey = Crypto.Asymmetric.PublicKey(key: fakePrivateKey)
        
        // Encrypt with fake
        let encrypted = Crypto.Asymmetric.Authenticated.encrypt(bytes: data, recipientPublicKey: fakePublicKey, senderPrivateKey: alicePrivateKey)
        
        // Decrypt with other PublicKey
        XCTAssertThrowsError(try Crypto.Asymmetric.Authenticated.decrypt(bytes: encrypted, senderPublicKey: bobPublicKey, recipientPrivateKey: alicePrivateKey)) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.couldNotDecrypt)
        }
        
        // Decrypt with other Nonce
        XCTAssertThrowsError(try Crypto.Asymmetric.Authenticated.decrypt(bytes: encrypted, senderPublicKey: bobPublicKey, recipientPrivateKey: alicePrivateKey)) { error in
            XCTAssertEqual(error as? Crypto.Error, Crypto.Error.couldNotDecrypt)
        }
    }
    
    func testAsymmetricEncryptAndDecryptAnonymous() {
        let data: Bytes = [0x6, 0x6, 0x6]
        
        let bobPrivateKey = Crypto.Asymmetric.PrivateKey()
        let bobPublicKey = Crypto.Asymmetric.PublicKey(key: bobPrivateKey)
        
        let encryped = Crypto.Asymmetric.Anonymous.encrypt(bytes: data, recipientPublicKey: bobPublicKey)
        
        XCTAssert(data != encryped)
        
        let decrypted = try! Crypto.Asymmetric.Anonymous.decrypt(bytes: encryped, recipientPublicKey: bobPublicKey, recipientPrivateKey: bobPrivateKey)
        
        XCTAssert(decrypted == data)
    }
    
    func testSodiumRandomNumberGenerator() {
        var c3 = 0
        var rng = SodiumRandomNumberGenerator()
        let ref3 = UInt32.random(in: 0...UInt32.max, using: &rng)
        for _ in (0..<100) {
            if UInt32.random(in: 0...UInt32.max, using: &rng) == ref3 {
                c3 += 1
            }
        }
        XCTAssert(c3 < 10)
    }
    
    func testNormalize() {
        let source1 = "δέκα" // 8 bytes
        let source2 = "δε\u{0301}κα" // 10 bytes
        
        // Before normalization
        XCTAssert(source1.data(using: .utf8) != source2.data(using: .utf8))
        
        // After normalization
        XCTAssert(Password(source1).normalize() == Password(source2).normalize())
    }
}
