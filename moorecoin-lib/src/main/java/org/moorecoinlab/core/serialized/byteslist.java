package org.moorecoinlab.core.serialized;

import java.security.messagedigest;
import java.util.arraylist;

public class byteslist implements bytessink {
    private arraylist<byte[]> buffer = new arraylist<byte[]>();

    private int len = 0;

    public void add(byteslist bl) {
        for (byte[] bytes : bl.rawlist()) {
            add(bytes);
        }
    }

    @override
    public void add(byte abyte) {
        add(new byte[]{abyte});
    }

    @override
    public void add(byte[] bytes) {
        len += bytes.length;
        buffer.add(bytes);
    }

    public byte[] bytes() {
        int n = byteslength();
        byte[] bytes = new byte[n];
        addbytes(bytes, 0);
        return bytes;
    }

    static public string[] hexlookup = new string[256];
    static {
        for (int i = 0; i < 256; i++) {
            string s = integer.tohexstring(i).touppercase();
            if (s.length() == 1) {
                s = "0" + s;
            }
            hexlookup[i] = s;
        }
    }

    public string byteshex() {
        stringbuilder builder = new stringbuilder(len * 2);
        for (byte[] buf : buffer) {
            for (byte abytes : buf) {
                builder.append(hexlookup[abytes & 0xff]);
            }
        }
        return builder.tostring();
    }

    public int byteslength() {
        return len;
    }

    private int addbytes(byte[] bytes, int destpos) {
        for (byte[] buf : buffer) {
            system.arraycopy(buf, 0, bytes, destpos, buf.length);
            destpos += buf.length;
        }
        return destpos;
    }

    public void updatedigest(messagedigest digest) {
        for (byte[] buf : buffer) {
            digest.update(buf);
        }
    }

    public arraylist<byte[]> rawlist() {
        return buffer;
    }
}
