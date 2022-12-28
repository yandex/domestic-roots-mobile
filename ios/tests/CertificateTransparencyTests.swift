import Security
import XCTest

import CertificateTransparency

final class CertificateTransparencyTests: XCTestCase {
  func testHasValidTimestamps() {
    let ct = CertificateTransparency()
    let trust = CreateValidTimestamps() as! SecTrust
    let result = ct.verifyTrust(trust)
    XCTAssertTrue(result.trusted)
    XCTAssertTrue(result.hasCustomRoot)
  }

  func testNoTimestamps() {
    let ct = CertificateTransparency()
    let trust = CreateNoTimestamps() as! SecTrust
    let result = ct.verifyTrust(trust)
    XCTAssertFalse(result.trusted)
    XCTAssertTrue(result.hasCustomRoot)
  }
}
