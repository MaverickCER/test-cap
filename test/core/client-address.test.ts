// The key a client address counts under (ADR 0009 §2): an IPv4 address as itself, an IPv4-mapped IPv6 address as its
// IPv4 address, any other IPv6 address as its /64, whatever way it is written.
import { describe, expect, it } from "vitest"
import { clientKey } from "../../src/core/client-address.js"

describe("clientKey", () => {
  it.each([
    ["192.0.2.10", "192.0.2.10"],
    ["::ffff:192.0.2.10", "192.0.2.10"],
    ["::FFFF:c000:20a", "192.0.2.10"],
    ["2001:db8:1:2::1", "2001:db8:1:2::/64"],
    ["2001:0DB8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"],
    ["2001:db8::", "2001:db8:0:0::/64"],
    ["::", "0:0:0:0::/64"],
    ["::1", "0:0:0:0::/64"],
    ["fe80::1:2:3:4", "fe80:0:0:0::/64"],
    ["1:2:3:4:5:6:7:8", "1:2:3:4::/64"],
    ["::ffff:0:1", "0.0.0.1"],
    ["0:0:0:0:0:fffe:c000:20a", "0:0:0:0::/64"],
    ["1::ffff:c000:20a", "1:0:0:0::/64"],
    ["::ffff:255.254.1.0", "255.254.1.0"],
    ["1:2:3:4:5:6:7::", "1:2:3:4::/64"],
    ["::2:3:4:5:6:7:8", "0:2:3:4::/64"],
    ["::192.0.2.10", "0:0:0:0::/64"],
    ["1:2:3:4:5:ffff:1.2.3.4", "1:2:3:4::/64"],
    ["::ffff:1.2.3.4", "1.2.3.4"],
  ])("keys %s as %s", (address, key) => {
    expect(clientKey(address)).toBe(key)
  })

  it("keys a value that is no IP address as itself, and no address as null", () => {
    for (const value of [
      "not an address",
      "[::1]",
      "2001:db8::g",
      "1::2::3",
      "1:2:3:4::5:6:7:8::",
      "1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:8:9",
      "1:2:3:4::5:6:7:8",
      "::ffff:192.0.2.300",
      ":1:2:3:4:5:6:7",
      "12345::1",
    ]) {
      expect(clientKey(value), value).toBe(value)
    }
    expect(clientKey(undefined)).toBeNull()
  })
})
