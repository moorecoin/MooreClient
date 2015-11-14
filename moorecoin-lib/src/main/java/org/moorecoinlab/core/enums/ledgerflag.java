package org.moorecoinlab.core.enums;

// ledger specific flags
public class ledgerflag {
    public static int
    // ltaccount_root
    passwordspent = 0x00010000,   // true, if password set fee is spent.
    requiredesttag = 0x00020000,   // true, to require a destinationtag for payments.
    requireauth = 0x00040000,   // true, to require a authorization to hold ious.
    disallowvrp = 0x00080000,   // true, to disallow sending vrp.
    disablemaster = 0x00100000,   // true, force regular key
    nofreeze         = 0x00200000,   // true, cannot freeze ripple states
    globalfreeze     = 0x00400000,   // true, all assets frozen

    // ltoffer
    passive = 0x00010000,
    sell = 0x00020000,   // true, offer was placed as a sell.

    // ltripple_state
    lowreserve = 0x00010000,   // true, if entry counts toward reserve.
    highreserve = 0x00020000,
    lowauth = 0x00040000,
    highauth = 0x00080000,
    lownoripple = 0x00100000,
    lowfreeze = 0x00400000,   // true, low side has set freeze flag
    highfreeze = 0x00800000;   // true, high side has set freeze flag
}
