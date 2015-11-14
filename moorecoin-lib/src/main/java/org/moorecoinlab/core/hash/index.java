package org.moorecoinlab.core.hash;


import org.moorecoinlab.core.accountid;
import org.moorecoinlab.core.currency;
import org.moorecoinlab.core.issue;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.hash.prefixes.ledgerspace;
import org.moorecoinlab.core.serialized.serializedtype;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;

import java.util.arrays;
import java.util.list;

import static java.util.collections.sort;

public class index {
    private static hash256 createbookbase(issue pays, issue gets) {
        halfsha512 hasher = halfsha512.prefixed256(ledgerspace.bookdir);

        pays.currency().tobytessink(hasher);
        gets.currency().tobytessink(hasher);
        pays.issuer().tobytessink(hasher);
        gets.issuer().tobytessink(hasher);

        return hasher.finish();
    }

    public static hash256 quality(hash256 index, uint64 quality) {
        byte[] qi = new byte[32];
        system.arraycopy(index.bytes(), 0, qi, 0, 24);
        if (quality != null) system.arraycopy(quality.tobytes(), 0, qi, 24, 8);
        return new hash256(qi);
    }

    private static hash256 zeroquality(hash256 fullindex) {
        return quality(fullindex, null);
    }
    public static hash256 ripplestate(accountid a1, accountid a2, currency currency) {
        list<accountid> accounts = arrays.aslist(a1, a2);
        sort(accounts);
        return ripplestate(accounts, currency);
    }
    public static hash256 ripplestate(list<accountid> accounts, currency currency) {
        halfsha512 hasher = halfsha512.prefixed256(ledgerspace.ripple);
        // low then high
        for (accountid account : accounts) account.tobytessink(hasher);
        // currency
        currency.tobytessink(hasher);

        return hasher.finish();
    }

    public static hash256 directorynode(hash256 base, uint64 nodeindex) {
        if (nodeindex == null || nodeindex.iszero()) {
            return base;
        }

        halfsha512 hash = halfsha512.prefixed256(ledgerspace.dirnode);

        for (serializedtype component : new serializedtype[]{base, nodeindex})
            component.tobytessink(hash);

        return hash.finish();
    }

    public static hash256 accountroot(accountid accountid) {
        halfsha512 hash = halfsha512.prefixed256(ledgerspace.account);
        accountid.tobytessink(hash);
        return hash.finish();
    }

    public static hash256 ownerdirectory(accountid account) {
        return hash256.prefixedhalfsha512(ledgerspace.ownerdir, account.bytes());
    }

    public static hash256 transactionid(byte[] blob) {
        return hash256.prefixedhalfsha512(hashprefix.transactionid, blob);
    }

    public static hash256 bookstart(issue pays, issue gets) {
        return zeroquality(createbookbase(pays, gets));
    }

    public static hash256 bookstart(hash256 indexfrombookrange) {
        return zeroquality(indexfrombookrange);
    }

    public static hash256 bookend(hash256 base) {
        byte[] end = base.biginteger().add(hash256.bookbasesize).tobytearray();
        return new hash256(end);
    }

    public static hash256 ledgerhashes(long prev) {
        return halfsha512.prefixed256(ledgerspace.skiplist)
                    .add(new uint32(prev >> 16))
                    .finish();
    }
    public static hash256 ledgerhashes() {
        return halfsha512.prefixed256(ledgerspace.skiplist).finish();
    }
}
