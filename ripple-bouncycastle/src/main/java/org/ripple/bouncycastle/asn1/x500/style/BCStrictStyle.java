package org.ripple.bouncycastle.asn1.x500.style;

import org.ripple.bouncycastle.asn1.x500.rdn;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x500.x500namestyle;

/**
 * variation of bcstyle that insists on strict ordering for equality
 * and hashcode comparisons
 */
public class bcstrictstyle
    extends bcstyle
{
    public static final x500namestyle instance = new bcstrictstyle();

    public boolean areequal(x500name name1, x500name name2)
    {
        rdn[] rdns1 = name1.getrdns();
        rdn[] rdns2 = name2.getrdns();

        if (rdns1.length != rdns2.length)
        {
            return false;
        }

        for (int i = 0; i != rdns1.length; i++)
        {
            if (!rdnareequal(rdns1[i], rdns2[i]))
            {
                return false;
            }
        }

        return true;
    }
}
