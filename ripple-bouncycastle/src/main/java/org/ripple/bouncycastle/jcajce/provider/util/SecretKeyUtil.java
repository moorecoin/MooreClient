package org.ripple.bouncycastle.jcajce.provider.util;

import java.util.hashmap;
import java.util.map;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.nist.nistobjectidentifiers;
import org.ripple.bouncycastle.asn1.ntt.nttobjectidentifiers;
import org.ripple.bouncycastle.asn1.pkcs.pkcsobjectidentifiers;
import org.ripple.bouncycastle.util.integers;

public class secretkeyutil
{
    private static map keysizes = new hashmap();

    static
    {
        keysizes.put(pkcsobjectidentifiers.des_ede3_cbc.getid(), integers.valueof(192));

        keysizes.put(nistobjectidentifiers.id_aes128_cbc, integers.valueof(128));
        keysizes.put(nistobjectidentifiers.id_aes192_cbc, integers.valueof(192));
        keysizes.put(nistobjectidentifiers.id_aes256_cbc, integers.valueof(256));

        keysizes.put(nttobjectidentifiers.id_camellia128_cbc, integers.valueof(128));
        keysizes.put(nttobjectidentifiers.id_camellia192_cbc, integers.valueof(192));
        keysizes.put(nttobjectidentifiers.id_camellia256_cbc, integers.valueof(256));
    }

    public static int getkeysize(asn1objectidentifier oid)
    {
        integer size = (integer)keysizes.get(oid);

        if (size != null)
        {
            return size.intvalue();
        }

        return -1;
    }
}
