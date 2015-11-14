package org.moorecoinlab.core.types.ledger;


import org.moorecoinlab.core.rippledate;
import org.moorecoinlab.core.binary.streader;
import org.moorecoinlab.core.hash.hash256;
import org.moorecoinlab.core.serialized.binaryparser;
import org.moorecoinlab.core.uint.uint32;
import org.moorecoinlab.core.uint.uint64;
import org.moorecoinlab.core.uint.uint8;

import java.util.date;

public class ledgerheader {
    public uint32 version;         // always 0x4c475200 (lwr) (secures signed objects)
    public uint32 sequence;        // ledger sequence (0 for genesis ledger)
    public uint64 totalvrp;        //
    public hash256 previousledger;  // the hash of the previous ledger (0 for genesis ledger)
    public hash256 transactionhash; // the hash of the transaction tree's root node.
    public hash256 statehash;       // the hash of the state tree's root node.
    public uint32 parentclosetime; // the time the previous ledger closed
    public uint32 closetime;       // utc minute ledger closed encoded as seconds since 1/1/2000 (or 0 for genesis ledger)
    public uint8   closeresolution; // the resolution (in seconds) of the close time
    public uint8 closeflags;      // flags

    public date closedate;

    public static ledgerheader fromparser(binaryparser parser) {
        return fromreader(new streader(parser));
    }
    public static ledgerheader fromreader(streader reader) {
        ledgerheader ledger = new ledgerheader();

        ledger.version = reader.uint32();
        ledger.sequence = reader.uint32();
        ledger.totalvrp = reader.uint64();
        ledger.previousledger = reader.hash256();
        ledger.transactionhash= reader.hash256();
        ledger.statehash = reader.hash256();
        ledger.parentclosetime = reader.uint32();
        ledger.closetime = reader.uint32();
        ledger.closeresolution = reader.uint8();
        ledger.closeflags = reader.uint8();

        ledger.closedate = rippledate.fromsecondssincerippleepoch(ledger.closetime);

        return ledger;
    }
}
