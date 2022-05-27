import Foundation

public typealias Bytes = [UInt8]

extension Array where Element == UInt8 {
    init (count bytes: Int) {
        self.init(repeating: 0, count: bytes)
    }
}

extension Bytes {
    var data: Data {
        return Data(self)
    }
}

extension Data {
    var bytes: Bytes {
        return Bytes(self)
    }
}
