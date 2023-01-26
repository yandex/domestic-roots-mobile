import Security
import XCTest

import CertificateTransparency

final class CertificateTransparencyTests: XCTestCase {
  func testHasValidTimestamps() {
    let ct = makeCertificateTransparency()
    let trust = CreateValidTimestamps() as! SecTrust
    let result = ct.verifyTrust(trust)
    XCTAssertTrue(result.trusted)
    XCTAssertTrue(result.hasCustomRoot)
  }

  func testNoTimestamps() {
    let ct = makeCertificateTransparency()
    let trust = CreateNoTimestamps() as! SecTrust
    let result = ct.verifyTrust(trust)
    XCTAssertFalse(result.trusted)
    XCTAssertTrue(result.hasCustomRoot)
  }
}

private func makeCertificateTransparency() -> CertificateTransparency {
  let configuration = CertificateTransparencyConfiguration()
  configuration.autoUpdate = false
  return CertificateTransparency(configuration: configuration)
}
