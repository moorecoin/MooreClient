package org.moorecoinlab.core.enums;

// transaction specific flags
public class transactionflag {
    public static long
    fullycanonicalsig = 0x80000000l,
    universal = fullycanonicalsig,
    universalmask = ~universal,

    // accountset flags:
    requiredesttag = 0x00010000,
    optionaldesttag = 0x00020000,
    requireauth = 0x00040000,
    optionalauth = 0x00080000,
    disallowvrp = 0x00100000,
    allowvrp = 0x00200000,
    accountsetmask = ~(universal | requiredesttag | optionaldesttag
            | requireauth | optionalauth
            | disallowvrp | allowvrp),

    // accountset setflag/clearflag values
    asfrequiredest   = 1,
    asfrequireauth   = 2,
    asfdisallowvrp = 3,
    asfdisablemaster = 4,
    asfaccounttxnid  = 5,
    asfnofreeze      = 6,
    asfglobalfreeze  = 7,

    // offercreate flags:
    passive = 0x00010000,
    immediateorcancel = 0x00020000,
    fillorkill = 0x00040000,
    sell = 0x00080000,
    offercreatemask = ~(universal | passive | immediateorcancel | fillorkill | sell),

    // payment flags:
    norippledirect = 0x00010000,
    partialpayment = 0x00020000,
    limitquality = 0x00040000,
    paymentmask = ~(universal | partialpayment | limitquality | norippledirect),

    // trustset flags:
    setauth = 0x00010000,
    setnoripple = 0x00020000,
    clearnoripple = 0x00040000,
    setfreeze            = 0x00100000,
    clearfreeze          = 0x00200000,
    trustsetmask = ~(universal | setauth | setnoripple | clearnoripple | setfreeze | clearfreeze);
}
