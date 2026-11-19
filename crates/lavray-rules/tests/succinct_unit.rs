// SPDX-License-Identifier: GPL-3.0-only

//! Юнит-тесты succinct set (порт sing/common/domain/set.go).

use lavray_rules::succinct::reverse_domain;

#[test]
fn reverse_by_runes() {
    assert_eq!(reverse_domain("www.google.com"), "moc.elgoog.www");
    assert_eq!(reverse_domain("moc.elgoog.www"), "www.google.com");
    // юникод — руны, не байты (иначе сломалась бы пара реверс→реверс)
    let u = "-testsä.example";
    assert_eq!(reverse_domain(&reverse_domain(u)), u);
}
