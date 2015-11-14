package org.moorecoinlab.client.util;

import org.ripple.bouncycastle.util.encoders.hex;

public class convert {
    public static string bytestohex(byte[] bytes) {
        return hex.tohexstring(bytes);
    }
    public static byte[] hextobytes(string hexstring) {
        return hex.decode(hexstring);
    }
}
