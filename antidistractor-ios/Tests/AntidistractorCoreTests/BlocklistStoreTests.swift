import XCTest
@testable import AntidistractorCore

final class BlocklistStoreTests: XCTestCase {

    var store: BlocklistStore!

    override func setUp() {
        super.setUp()
        store = BlocklistStore.shared
        // Clear before each test
        store.save(Blocklist())
        store.blockingEnabled = false
    }

    func testSaveAndLoad() {
        var list = Blocklist()
        list.domains = ["bilibili.com", "tiktok.com"]
        list.bundleIDs = ["com.bilibili.app.iphone"]
        list.categoryIDs = [6016]

        store.save(list)
        let loaded = store.load()

        XCTAssertEqual(loaded.domains, list.domains)
        XCTAssertEqual(loaded.bundleIDs, list.bundleIDs)
        XCTAssertEqual(loaded.categoryIDs, list.categoryIDs)
    }

    func testEmptyBlocklistIsEmpty() {
        let list = Blocklist()
        XCTAssertTrue(list.isEmpty)
    }

    func testNonEmptyBlocklist() {
        var list = Blocklist()
        list.domains = ["example.com"]
        XCTAssertFalse(list.isEmpty)
    }

    func testBlockingEnabledFlag() {
        store.blockingEnabled = true
        XCTAssertTrue(store.blockingEnabled)
        store.blockingEnabled = false
        XCTAssertFalse(store.blockingEnabled)
    }

    func testSaveEmptyBlocklist() {
        // Save something first
        var list = Blocklist()
        list.domains = ["test.com"]
        store.save(list)

        // Then save empty
        store.save(Blocklist())
        let loaded = store.load()
        XCTAssertTrue(loaded.isEmpty)
    }

    func testLoadWithNoData() {
        // Clear underlying storage
        UserDefaults.standard.removeObject(forKey: "antidistractor.blocklist")
        let loaded = store.load()
        XCTAssertTrue(loaded.isEmpty)
    }
}
