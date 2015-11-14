/* do not edit, auto generated */
package org.moorecoinlab.core.fields;

import java.util.map;
import java.util.treemap;

public enum type {
    unknown(-2),
    done(-1),
    notpresent(0),
    uint16(1),
    uint32(2),
    uint64(3),
    hash128(4),
    hash256(5),
    amount(6),
    variablelength(7),
    accountid(8),
    stobject(14),
    starray(15),
    uint8(16),
    hash160(17),
    pathset(18),
    vector256(19),
    transaction(10001),
    ledgerentry(10002),
    validation(10003);

    static private map<integer, type> byint = new treemap<integer, type>();
    static {
        for (object a : type.values()) {
            type t = (type) a;
            byint.put(t.id, t);
        }
    }

    static public type valueof(integer integer) {
        return byint.get(integer);
    }

    final int id;

    type(int type) {
        this.id = type;
    }

    public int getid() {
        return id;
    }
}
