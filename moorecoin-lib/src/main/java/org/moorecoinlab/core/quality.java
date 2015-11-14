package org.moorecoinlab.core;


import org.moorecoinlab.core.hash.hash256;

import java.math.bigdecimal;
import java.math.biginteger;

public class quality {
    public static bigdecimal frombookdirectory(hash256 bookdirectory, boolean payisnative, boolean getisnative) {
        byte[] value  = bookdirectory.slice(-7);
        int offset = bookdirectory.get(-8) - 100;
        return new bigdecimal(new biginteger(1, value), -( payisnative ? offset - 6 :
                                                           getisnative ? offset + 6 :
                                                           offset ));
    }
}
