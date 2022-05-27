import Foundation

public struct Password {
    private let value: String
    
    public init(_ value: String) {
        self.value = value
    }
    
    func normalize() -> Password {
        // More about NFKD here: https://en.wikipedia.org/wiki/Unicode_equivalence
        return .init(self.value.decomposedStringWithCompatibilityMapping)
    }
    
    func trim() -> Password {
        return .init(self.value.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    
    var data: Data {
        guard let data = self.value.data(using: .utf8) else {
            fatalError("Something when wrong!")
        }
        
        return data
    }
    
    var bytes: Bytes {
        return self.data.bytes
    }
}

extension Password: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.bytes == rhs.bytes
    }
}
