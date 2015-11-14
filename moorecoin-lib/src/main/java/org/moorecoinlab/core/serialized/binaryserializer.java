package org.moorecoinlab.core.serialized;


import org.moorecoinlab.core.fields.field;
import org.moorecoinlab.core.fields.type;

import java.util.arrays;

public class binaryserializer {
    private final bytessink sink;

    public binaryserializer(bytessink sink) {
        this.sink = sink;
    }

    public void add(byte[] n) {
        sink.add(n);
    }

    public void addlengthencoded(byte[] n) {
        add(encodevl(n.length));
        add(n);
    }

    public static byte[] encodevl(int  length) {
        byte[] lenbytes = new byte[4];

        if (length <= 192)
        {
            lenbytes[0] = (byte) (length);
            return arrays.copyof(lenbytes, 1);
        }
        else if (length <= 12480)
        {
            length -= 193;
            lenbytes[0] = (byte) (193 + (length >>> 8));
            lenbytes[1] = (byte) (length & 0xff);
            return arrays.copyof(lenbytes, 2);
        }
        else if (length <= 918744) {
            length -= 12481;
            lenbytes[0] = (byte) (241 + (length >>> 16));
            lenbytes[1] = (byte) ((length >> 8) & 0xff);
            lenbytes[2] = (byte) (length & 0xff);
            return arrays.copyof(lenbytes, 3);
        } else {
            throw new runtimeexception("overflow error");
        }
    }

    public void add(byteslist bl) {
        for (byte[] bytes : bl.rawlist()) {
            sink.add(bytes);
        }
    }

    public int addfieldheader(field f) {
        if (!f.isserialized()) {
            throw new illegalstateexception(string.format("field %s is a discardable field", f));
        }
        byte[] n = f.getbytes();
        add(n);
        return n.length;
    }

    public void add(byte type) {
        sink.add(type);
    }

    public void addlengthencoded(byteslist bytes) {
        add(encodevl(bytes.byteslength()));
        add(bytes);
    }

    public void add(field field, serializedtype value) {
        addfieldheader(field);
        if (field.isvlencoded()) {
            addlengthencoded(value);
        } else {
            value.tobytessink(sink);
            if (field.gettype() == type.stobject) {
                addfieldheader(field.objectendmarker);
            } else if (field.gettype() == type.starray) {
                addfieldheader(field.arrayendmarker);
            }
        }
    }

    public void addlengthencoded(serializedtype value) {
        byteslist bytes = new byteslist();
        value.tobytessink(bytes);
        addlengthencoded(bytes);
    }
}
