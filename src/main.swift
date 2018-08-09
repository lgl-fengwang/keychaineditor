import Foundation

func printUsage() {
    print("USAGE: \(CommandLine.arguments[0]) [commands]")
    print("Commands Description")
    print("  -v     version")
    print("  -f     Search. Requires a query string as the second argument.")
    print("  -e     Edit. Requires --account STRING --service STRING [--agroup STRING] --data STRING")
    print("  -d     Delete. Requires --account STRING --service STRING [--agroup STRING] --isservice StringORData")
    print("  -a     Add. Requires --account STRING --service STRING --agroup STRING --isservice STRING")
    print("  -x     Delete. Requires --number NUMBER") //根据下标删除keychain 慎用
    print("  -g     Search. Requires --agroup STRING")
    print("NOTES:")
    print(" * Account and Service names are used to uniquely identify a item. An optional AccessGroup can also be passed to identify the item.")
    print(" * If there is no Account name pass an empty string.")
    print(" * Search is from the following group {Account, Service, AccessGroup, Protection} and is case in-sensitive.")
    print("EXAMPLES:")
    print(" * To Dump entire keychain: $ keychaineditor")
    print(" * Limit dump by searching: $ keychaineditor -f 'test'")
    print(" * Edit a keychain item:    $ keychaineditor -e --account 'TestAccount' --service 'TestService' --data 'TestData'")
    print(" * Add a keychain item:  $ keychaineditor -a --account 'TestAccount' --service 'TestService' --agroup 'TestAgroup'  --isservice STRING")
    print(" * Delete a keychain item:  $ keychaineditor -d --account 'TestAccount' --service 'TestService' --isservice STRING")
    print(" * Search a keychain item:  $ keychaineditor -g --agroup 'TestAgroup'")
    print(" * Delete a keychain item:  $ keychaineditor -x --number 'Number'") //慎用
    exit(EXIT_FAILURE)
}

func handleSearch(args: UserDefaults) {
    if let query = args.string(forKey: "f") {
        let items = search(for: query, in: dumpKeychainItems())
        print(convertToJSON(for: items))
    } else {
        printUsage()
    }
}

func handleEdit(args: UserDefaults) {
    if let account = args.string(forKey: "-account") , let service = args.string(forKey: "-service") , let data = args.string(forKey: "-data") {
        let status = updateKeychainItem(account: account, service: service, data: decodeIfBase64(for: data), agroup: args.string(forKey: "-agroup"))
        print(errorMessage(for: status))
    } else {
        printUsage()
    }
}

func handleAdd(args: UserDefaults) {
    var status: OSStatus
    if let account = args.string(forKey: "-account") , let service = args.string(forKey: "-service") , let data = args.string(forKey: "-data"), let agroup = args.string(forKey: "-agroup"), let isservice = args.string(forKey: "-isservice") {
        status = addKeychainItem(account: account, service: service, data: data, isservice: isservice, agroup: agroup)
        print(errorMessage(for: status))
    } else {
        printUsage()
    }
}

func handleDelete(args: UserDefaults) {
    var status: OSStatus
    if let account = args.string(forKey: "-account"), let service = args.string(forKey: "-service"), let isservice = args.string(forKey: "-isservice") {
        if isservice == "String" {
            status = deleteKeychainItem(account: account, service: service, agroup: args.string(forKey: "-agroup"))
        } else {
            status = deleteKeychainItem(account: account, service: decodeIfBase64(for: service), agroup: args.string(forKey: "-agroup"))
        }
        print(errorMessage(for: status))
    } else {
        printUsage()
    }
}

func delete(args: UserDefaults) {
    if let items = args.string(forKey: "-number") {
        let n = Int(items)
        let status = dumpKeychain(num: n!)
        print(errorMessage(for: status))
    } else {
        printUsage()
    }
}

func handleGroup(args: UserDefaults) {
    if let items = args.string(forKey: "-agroup") {
        let str = searchGroup(for: items, in: dumpKeychainItems())
        print(convertToJSON(for: str))
    } else {
        printUsage()
    }
}

guard CommandLine.arguments.count >= 2 else {
    print(convertToJSON(for: dumpKeychainItems()))
    exit(EXIT_SUCCESS)
}

switch CommandLine.arguments[1] {
case "-v": print("KeychainEditor Version = 2.6.1")
case "-f": handleSearch(args: UserDefaults.standard)
case "-e": handleEdit(args: UserDefaults.standard)
case "-d": handleDelete(args: UserDefaults.standard)
case "-a": handleAdd(args: UserDefaults.standard)
case "-h": printUsage()
case "-x": delete(args: UserDefaults.standard)
case "-g": handleGroup(args: UserDefaults.standard)
default: printUsage()
}
