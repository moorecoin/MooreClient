package org.moorecoinlab.core.binary;


import org.moorecoinlab.core.*;
import org.moorecoinlab.core.hash.hash128;
import org.moorecoinlab.core.hash.hash160;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.hash.prefixes.hashprefix;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.uint.uint16;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;
import org.moorecoinlab.core.uint.uint8;

import java.util.arrays;
import java.util.date;

public class streader {
    protected binaryparser parser;
    public streader(binaryparser parser) {
        this.parser = parser;
    }
    public streader(string hex) {
        this.parser = new binaryparser(hex);
    }
    public uint8 uint8() {
        return uint8.translate.fromparser(parser);
    }
    public uint16 uint16() {
        return uint16.translate.fromparser(parser);
    }
    public uint32 uint32() {
        return uint32.translate.fromparser(parser);
    }
    public uint64 uint64() {
        return uint64.translate.fromparser(parser);
    }
    public hash128 hash128() {
        return hash128.translate.fromparser(parser);
    }
    public hash160 hash160() {
        return hash160.translate.fromparser(parser);
    }
    public currency currency() {
        return currency.translate.fromparser(parser);
    }
    public hash256 hash256() {
        return hash256.translate.fromparser(parser);
    }
    public vector256 vector256() {
        return vector256.translate.fromparser(parser);
    }
    public accountid accountid() {
        return accountid.translate.fromparser(parser);
    }
    public variablelength variablelength() {
        int hint = parser.readvllength();
        return variablelength.translate.fromparser(parser, hint);
    }
    public amount amount() {
        return amount.translate.fromparser(parser);
    }
    public pathset pathset() {
        return pathset.translate.fromparser(parser);
    }

    public stobject stobject() {
        return stobject.translate.fromparser(parser);
    }
    public stobject vlstobject() {
        return stobject.translate.fromparser(parser, parser.readvllength());
    }

    public hashprefix hashprefix() {
        byte[] read = parser.read(4);
        for (hashprefix hashprefix : hashprefix.values()) {
            if (arrays.equals(read, hashprefix.bytes)) {
                return hashprefix;
            }
        }
        return null;
    }

    public starray starray() {
        return starray.translate.fromparser(parser);
    }
    public date rippledate() {
        return rippledate.fromparser(parser);
    }

    public binaryparser parser() {
        return parser;
    }
}
