package org.ripple.bouncycastle.openpgp;

import org.ripple.bouncycastle.bcpg.userattributesubpacket;
import org.ripple.bouncycastle.bcpg.attr.imageattribute;

import java.util.arraylist;
import java.util.list;

public class pgpuserattributesubpacketvectorgenerator
{
    private list list = new arraylist();

    public void setimageattribute(int imagetype, byte[] imagedata)
    {
        if (imagedata == null)
        {
            throw new illegalargumentexception("attempt to set null image");
        }

        list.add(new imageattribute(imagetype, imagedata));
    }

    public pgpuserattributesubpacketvector generate()
    {
        return new pgpuserattributesubpacketvector((userattributesubpacket[])list.toarray(new userattributesubpacket[list.size()]));
    }
}
