package org.moorecoinlab.core.binary;


import org.moorecoinlab.core.serialized.binaryserializer;
import org.moorecoinlab.core.serialized.bytessink;
import org.moorecoinlab.core.serialized.serializedtype;

public class stwriter {
    bytessink sink;
    binaryserializer serializer;
    public stwriter(bytessink bytessink) {
        serializer = new binaryserializer(bytessink);
        sink = bytessink;
    }
    public void write(serializedtype obj) {
        obj.tobytessink(sink);
    }
    public void writevl(serializedtype obj) {
        serializer.addlengthencoded(obj);
    }
}
