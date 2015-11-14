package org.moorecoinlab.core.serialized;

public class multisink implements bytessink {
    final private bytessink[] sinks;
    public multisink(bytessink... sinks) {
        this.sinks = sinks;
    }
    @override
    public void add(byte b) {
        for (bytessink sink : sinks) sink.add(b);
    }
    @override
    public void add(byte[] b) {
        for (bytessink sink : sinks) sink.add(b);
    }
}
