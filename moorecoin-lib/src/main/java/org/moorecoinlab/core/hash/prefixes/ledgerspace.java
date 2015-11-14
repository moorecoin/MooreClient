package org.moorecoinlab.core.hash.prefixes;

import org.moorecoinlab.core.uint.uint16;

public enum ledgerspace implements prefix {
    account('a'),
    dirnode('d'),
    generator('g'),

    ripple('r'),
    offer('o'),  // entry for an offer.
    ownerdir('o'),  // directory of things owned by an account.
    bookdir('b'),  // directory of order books.
    contract('c'),
    skiplist('s'),
    amendment('f'),
    fee('e'),
    ticket('t'),

    // no longer used
    nickname('n'),;

    uint16 uint16;
    public byte[] bytes;

    @override
    public byte[] bytes() {
        return bytes;
    }

    ledgerspace(char c) {
        uint16 = new uint16((int) c);
        bytes = uint16.tobytearray();
    }
}
