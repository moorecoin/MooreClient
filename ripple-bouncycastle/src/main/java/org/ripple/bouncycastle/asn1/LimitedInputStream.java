package org.ripple.bouncycastle.asn1;

import java.io.inputstream;

abstract class limitedinputstream
        extends inputstream
{
    protected final inputstream _in;
    private int _limit;

    limitedinputstream(
        inputstream in,
        int         limit)
    {
        this._in = in;
        this._limit = limit;
    }

    int getremaining()
    {
        // todo: maybe one day this can become more accurate
        return _limit;
    }
    
    protected void setparenteofdetect(boolean on)
    {
        if (_in instanceof indefinitelengthinputstream)
        {
            ((indefinitelengthinputstream)_in).seteofon00(on);
        }
    }
}
