package org.ripple.bouncycastle.asn1.cmp;

import java.math.biginteger;

import org.ripple.bouncycastle.asn1.asn1integer;
import org.ripple.bouncycastle.asn1.asn1object;
import org.ripple.bouncycastle.asn1.asn1primitive;

public class pkistatus
    extends asn1object
{
    public static final int granted                 = 0;
    public static final int granted_with_mods       = 1;
    public static final int rejection               = 2;
    public static final int waiting                 = 3;
    public static final int revocation_warning      = 4;
    public static final int revocation_notification = 5;
    public static final int key_update_warning      = 6;

    public static final pkistatus granted = new pkistatus(granted);
    public static final pkistatus grantedwithmods = new pkistatus(granted_with_mods);
    public static final pkistatus rejection = new pkistatus(rejection);
    public static final pkistatus waiting = new pkistatus(waiting);
    public static final pkistatus revocationwarning = new pkistatus(revocation_warning);
    public static final pkistatus revocationnotification = new pkistatus(revocation_notification);
    public static final pkistatus keyupdatewaiting = new pkistatus(key_update_warning);

    private asn1integer value;

    private pkistatus(int value)
    {
        this(new asn1integer(value));
    }

    private pkistatus(asn1integer value)
    {
        this.value = value;
    }

    public static pkistatus getinstance(object o)
    {
        if (o instanceof pkistatus)
        {
            return (pkistatus)o;
        }

        if (o != null)
        {
            return new pkistatus(asn1integer.getinstance(o));
        }

        return null;
    }

    public biginteger getvalue()
    {
        return value.getvalue();
    }
    
    public asn1primitive toasn1primitive()
    {
        return value;
    }
}
