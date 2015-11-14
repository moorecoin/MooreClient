package org.ripple.bouncycastle.x509.extension;

import java.io.ioexception;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collection;
import java.util.collections;
import java.util.enumeration;
import java.util.list;

import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1octetstring;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.dersequence;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.x509extension;
import org.ripple.bouncycastle.util.integers;


public class x509extensionutil
{
    public static asn1primitive fromextensionvalue(
        byte[]  encodedvalue) 
        throws ioexception
    {
        asn1octetstring octs = (asn1octetstring)asn1primitive.frombytearray(encodedvalue);
        
        return asn1primitive.frombytearray(octs.getoctets());
    }

    public static collection getissueralternativenames(x509certificate cert)
            throws certificateparsingexception
    {
        byte[] extval = cert.getextensionvalue(x509extension.issueralternativename.getid());

        return getalternativenames(extval);
    }

    public static collection getsubjectalternativenames(x509certificate cert)
            throws certificateparsingexception
    {        
        byte[] extval = cert.getextensionvalue(x509extension.subjectalternativename.getid());

        return getalternativenames(extval);
    }

    private static collection getalternativenames(byte[] extval)
        throws certificateparsingexception
    {
        if (extval == null)
        {
            return collections.empty_list;
        }
        try
        {
            collection temp = new arraylist();
            enumeration it = dersequence.getinstance(fromextensionvalue(extval)).getobjects();
            while (it.hasmoreelements())
            {
                generalname genname = generalname.getinstance(it.nextelement());
                list list = new arraylist();
                list.add(integers.valueof(genname.gettagno()));
                switch (genname.gettagno())
                {
                case generalname.edipartyname:
                case generalname.x400address:
                case generalname.othername:
                    list.add(genname.getname().toasn1primitive());
                    break;
                case generalname.directoryname:
                    list.add(x500name.getinstance(genname.getname()).tostring());
                    break;
                case generalname.dnsname:
                case generalname.rfc822name:
                case generalname.uniformresourceidentifier:
                    list.add(((asn1string)genname.getname()).getstring());
                    break;
                case generalname.registeredid:
                    list.add(asn1objectidentifier.getinstance(genname.getname()).getid());
                    break;
                case generalname.ipaddress:
                    list.add(deroctetstring.getinstance(genname.getname()).getoctets());
                    break;
                default:
                    throw new ioexception("bad tag number: " + genname.gettagno());
                }

                temp.add(list);
            }
            return collections.unmodifiablecollection(temp);
        }
        catch (exception e)
        {
            throw new certificateparsingexception(e.getmessage());
        }
    }
}
