import Security
import Foundation

func addKeychainItem(                
                account: String,
                service: String,
                data: String,
                isservice: String,
                agroup: String) -> OSStatus {

    let accessibleConstant = kSecAttrAccessibleAlways
    var status: OSStatus = -1
    var error: Unmanaged<CFError>?

    guard let addData = data.data(using: String.Encoding.utf8) else {
        NSLog("addKeychainItem() -> Error while unwrapping user-supplied data.Data")
        exit(EXIT_FAILURE)
    }

    if let _ = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlocked, .devicePasscode, &error) {

        var query = [
            kSecClass as String             :   kSecClassGenericPassword as String,
            kSecAttrAccount as String       :   account,
            kSecAttrAccessible as String    :   accessibleConstant,
            kSecAttrAccessGroup as String   :   agroup,
            // Uncomment the following line to add AccessControl. Make sure
            // "acl" is defined above in the if let scope.
            //kSecAttrAccessControl as String :   acl,
            kSecValueData as String         :   addData
            ] as [String : Any]

        if isservice == "Data" {
            guard let addService = service.data(using: String.Encoding.utf8) else {
                NSLog("addKeychainItem() -> Error while unwrapping user-supplied service.Data")
                exit(EXIT_FAILURE)
            }
            query[kSecAttrService as String] = addService
        } else {
            query[kSecAttrService as String] = service
        }

        // if let unwrappedAGroup = agroup {
        //     query[kSecAttrAccessGroup as String] = unwrappedAGroup
        // }

        status = SecItemAdd(query as CFDictionary, nil)
    } else {
        print("[addItem::SecAccessControl] - \(error?.takeUnretainedValue())")
    }
    return status
}

// func addKeychainItem64(                
//                 account: String,
//                 service: String,
//                 data: String,
//                 agroup: String? = nil) -> OSStatus {

//     let accessibleConstant = kSecAttrAccessibleAlways
//     var status: OSStatus = -1
//     var error: Unmanaged<CFError>?

//     guard let addData = data.data(using: String.Encoding.utf8) else {
//         NSLog("addKeychainItem() -> Error while unwrapping user-supplied data.")
//         exit(EXIT_FAILURE)
//     }

//     if let _ = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
//             kSecAttrAccessibleWhenUnlocked, .devicePasscode, &error) {

//         var query = [
//             kSecClass as String             :   kSecClassGenericPassword as String,
//             kSecAttrAccount as String       :   account,
//             kSecAttrService as String       :   decodeIfBase64(for: service),
//             kSecAttrAccessible as String    :   accessibleConstant,
//             Uncomment the following line to add AccessControl. Make sure
//             "acl" is defined above in the if let scope.
//             kSecAttrAccessControl as String :   acl,
//             kSecValueData as String         :   addData
//             ] as [String : Any]

//         if let unwrappedAGroup = agroup {
//             query[kSecAttrAccessGroup as String] = unwrappedAGroup
//         }

//         status = SecItemAdd(query as CFDictionary, nil)
//     } else {
//         print("[addItem::SecAccessControl] - \(error?.takeUnretainedValue())")
//     }
//     return status
// }

func dumpKeychainItems() -> [Dictionary<String, String>] {
    var returnedItemsInGenericArray: AnyObject? = nil
    var finalArrayOfKeychainItems = [Dictionary<String, Any>]()
    var returnedKeychainItems = [Dictionary<String, String>]()
    var status: OSStatus = -1

    let secClasses: [NSString] = [kSecClassGenericPassword]
    let accessiblityConstants: [NSString] = [kSecAttrAccessibleAfterFirstUnlock,
                                             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                             kSecAttrAccessibleAlways,
                                             kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                             kSecAttrAccessibleAlwaysThisDeviceOnly,
                                             kSecAttrAccessibleWhenUnlocked,
                                             kSecAttrAccessibleWhenUnlockedThisDeviceOnly]

    for eachKSecClass in secClasses {
        for eachConstant in accessiblityConstants {
            let query = [
                kSecClass as String             :   eachKSecClass,
                kSecAttrAccessible as String    :   eachConstant,
                kSecMatchLimit as String        :   kSecMatchLimitAll as String,
                kSecReturnAttributes as String  :   kCFBooleanTrue as Bool,
                kSecReturnData as String        :   kCFBooleanTrue as Bool
                ] as [String : Any]

            status = SecItemCopyMatching(query as CFDictionary, &returnedItemsInGenericArray)

            if status == errSecSuccess {
                finalArrayOfKeychainItems =  finalArrayOfKeychainItems
                    + (returnedItemsInGenericArray as! Array)
            }
        }
    }

    // The value of status is not really the actual status that I like to
    // have. The status varies according to constant that I am dumping with.
    // Hence, if the final array contains at least one value, then I will consider
    // it as a success. Or else, just return the last status value.

    if (finalArrayOfKeychainItems.count >= 1) {
        status = errSecSuccess
        returnedKeychainItems = canonicalizeTypesInReturnedDicts(items: finalArrayOfKeychainItems)
    }
    return returnedKeychainItems
}

func updateKeychainItem(at secClass: String = kSecClassGenericPassword as String,
                account: String,
                service: String,
                data: String,
                agroup: String? = nil) -> OSStatus {

    guard let updatedData = data.data(using: String.Encoding.utf8) else {
        NSLog("UpdateKeychainItem() -> Error while unwrapping user-supplied data.")
        exit(EXIT_FAILURE)
    }

    var query = [
        kSecClass as String         :   secClass,
        kSecAttrAccount as String   :   account,
        kSecAttrService as String   :   service
    ]
    if let unwrappedAGroup = agroup {
        query[kSecAttrAccessGroup as String] = unwrappedAGroup
    }

    let dataToUpdate = [kSecValueData as String : updatedData]
    let status: OSStatus = SecItemUpdate(query as CFDictionary, dataToUpdate as CFDictionary)
    return status
}

func deleteKeychainItem(at secClass: String = kSecClassGenericPassword as String,
                account: String,
                service: String,
                agroup: String? = nil) -> OSStatus {

    var query = [
        kSecClass as String         :   secClass,
        kSecAttrAccount as String   :   account,
        kSecAttrService as String   :   service
    ]
    if let unwrappedAGroup = agroup {
        query[kSecAttrAccessGroup as String] = unwrappedAGroup
    }
    let status: OSStatus = SecItemDelete(query as CFDictionary)
    return status
}

func dumpKeychain(num: Int) -> OSStatus {
    var returnedItemsInGenericArray: AnyObject? = nil
    var finalArrayOfKeychainItems = [Dictionary<String, Any>]()
    var status: OSStatus = -1

    let secClasses: [NSString] = [kSecClassGenericPassword]
    let accessiblityConstants: [NSString] = [kSecAttrAccessibleAfterFirstUnlock,
                                             kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                             kSecAttrAccessibleAlways,
                                             kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                             kSecAttrAccessibleAlwaysThisDeviceOnly,
                                             kSecAttrAccessibleWhenUnlocked,
                                             kSecAttrAccessibleWhenUnlockedThisDeviceOnly]

    for eachKSecClass in secClasses {
        for eachConstant in accessiblityConstants {
            let query = [
                kSecClass as String             :   eachKSecClass,
                kSecAttrAccessible as String    :   eachConstant,
                kSecMatchLimit as String        :   kSecMatchLimitAll as String,
                kSecReturnAttributes as String  :   kCFBooleanTrue as Bool,
                kSecReturnData as String        :   kCFBooleanTrue as Bool
                ] as [String : Any]

            status = SecItemCopyMatching(query as CFDictionary, &returnedItemsInGenericArray)

            if status == errSecSuccess {
                finalArrayOfKeychainItems =  finalArrayOfKeychainItems
                    + (returnedItemsInGenericArray as! Array)
            }
        }
    }
    let dict = [
        kSecClass as String : kSecClassGenericPassword as String,
        kSecAttrAccount as String : finalArrayOfKeychainItems[num]["acct"]!,
        kSecAttrService as String : finalArrayOfKeychainItems[num]["svce"]!,
        kSecAttrAccessGroup as String : finalArrayOfKeychainItems[num]["agrp"]!
    ]
    let result: OSStatus = SecItemDelete(dict as CFDictionary)
    return result
}


