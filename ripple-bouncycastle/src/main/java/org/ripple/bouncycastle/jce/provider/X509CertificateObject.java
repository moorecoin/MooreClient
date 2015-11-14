package org.ripple.bouncycastle.jce.provider;

import java.io.bytearrayoutputstream;
import java.io.ioexception;
import java.math.biginteger;
import java.net.inetaddress;
import java.net.unknownhostexception;
import java.security.invalidkeyexception;
import java.security.nosuchalgorithmexception;
import java.security.nosuchproviderexception;
import java.security.principal;
import java.security.provider;
import java.security.publickey;
import java.security.security;
import java.security.signature;
import java.security.signatureexception;
import java.security.cert.certificate;
import java.security.cert.certificateencodingexception;
import java.security.cert.certificateexception;
import java.security.cert.certificateexpiredexception;
import java.security.cert.certificatenotyetvalidexception;
import java.security.cert.certificateparsingexception;
import java.security.cert.x509certificate;
import java.util.arraylist;
import java.util.collection;
import java.util.collections;
import java.util.date;
import java.util.enumeration;
import java.util.hashset;
import java.util.list;
import java.util.set;

import javax.security.auth.x500.x500principal;

import org.ripple.bouncycastle.asn1.asn1encodable;
import org.ripple.bouncycastle.asn1.asn1encoding;
import org.ripple.bouncycastle.asn1.asn1inputstream;
import org.ripple.bouncycastle.asn1.asn1objectidentifier;
import org.ripple.bouncycastle.asn1.asn1outputstream;
import org.ripple.bouncycastle.asn1.asn1primitive;
import org.ripple.bouncycastle.asn1.asn1sequence;
import org.ripple.bouncycastle.asn1.asn1string;
import org.ripple.bouncycastle.asn1.derbitstring;
import org.ripple.bouncycastle.asn1.deria5string;
import org.ripple.bouncycastle.asn1.dernull;
import org.ripple.bouncycastle.asn1.deroctetstring;
import org.ripple.bouncycastle.asn1.misc.miscobjectidentifiers;
import org.ripple.bouncycastle.asn1.misc.netscapecerttype;
import org.ripple.bouncycastle.asn1.misc.netscaperevocationurl;
import org.ripple.bouncycastle.asn1.misc.verisignczagextension;
import org.ripple.bouncycastle.asn1.util.asn1dump;
import org.ripple.bouncycastle.asn1.x500.x500name;
import org.ripple.bouncycastle.asn1.x500.style.rfc4519style;
import org.ripple.bouncycastle.asn1.x509.algorithmidentifier;
import org.ripple.bouncycastle.asn1.x509.basicconstraints;
import org.ripple.bouncycastle.asn1.x509.extension;
import org.ripple.bouncycastle.asn1.x509.extensions;
import org.ripple.bouncycastle.asn1.x509.generalname;
import org.ripple.bouncycastle.asn1.x509.keyusage;
import org.ripple.bouncycastle.jcajce.provider.asymmetric.util.pkcs12bagattributecarrierimpl;
import org.ripple.bouncycastle.jce.x509principal;
import org.ripple.bouncycastle.jce.interfaces.pkcs12bagattributecarrier;
import org.ripple.bouncycastle.util.arrays;
import org.ripple.bouncycastle.util.integers;
import org.ripple.bouncycastle.util.encoders.hex;

public class x509certificateobject
    extends x509certificate
    implements pkcs12bagattributecarrier
{
    private org.ripple.bouncycastle.asn1.x509.certificate    c;
    private basicconstraints            basicconstraints;
    private boolean[]                   keyusage;
    private boolean                     hashvalueset;
    private int                         hashvalue;

    private pkcs12bagattributecarrier   attrcarrier = new pkcs12bagattributecarrierimpl();

    public x509certificateobject(
        org.ripple.bouncycastle.asn1.x509.certificate    c)
        throws certificateparsingexception
    {
        this.c = c;

        try
        {
            byte[]  bytes = this.getextensionbytes("2.5.29.19");

            if (bytes != null)
            {
                basicconstraints = basicconstraints.getinstance(asn1primitive.frombytearray(bytes));
            }
        }
        catch (exception e)
        {
            throw new certificateparsingexception("cannot construct basicconstraints: " + e);
        }

        try
        {
            byte[] bytes = this.getextensionbytes("2.5.29.15");
            if (bytes != null)
            {
                derbitstring    bits = derbitstring.getinstance(asn1primitive.frombytearray(bytes));

                bytes = bits.getbytes();
                int length = (bytes.length * 8) - bits.getpadbits();

                keyusage = new boolean[(length < 9) ? 9 : length];

                for (int i = 0; i != length; i++)
                {
                    keyusage[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
                }
            }
            else
            {
                keyusage = null;
            }
        }
        catch (exception e)
        {
            throw new certificateparsingexception("cannot construct keyusage: " + e);
        }
    }

    public void checkvalidity()
        throws certificateexpiredexception, certificatenotyetvalidexception
    {
        this.checkvalidity(new date());
    }

    public void checkvalidity(
        date    date)
        throws certificateexpiredexception, certificatenotyetvalidexception
    {
        if (date.gettime() > this.getnotafter().gettime())  // for other vm compatibility
        {
            throw new certificateexpiredexception("certificate expired on " + c.getenddate().gettime());
        }

        if (date.gettime() < this.getnotbefore().gettime())
        {
            throw new certificatenotyetvalidexception("certificate not valid till " + c.getstartdate().gettime());
        }
    }

    public int getversion()
    {
        return c.getversionnumber();
    }

    public biginteger getserialnumber()
    {
        return c.getserialnumber().getvalue();
    }

    public principal getissuerdn()
    {
        try
        {
            return new x509principal(x500name.getinstance(c.getissuer().getencoded()));
        }
        catch (ioexception e)
        {
            return null;
        }
    }

    public x500principal getissuerx500principal()
    {
        try
        {
            bytearrayoutputstream   bout = new bytearrayoutputstream();
            asn1outputstream        aout = new asn1outputstream(bout);

            aout.writeobject(c.getissuer());

            return new x500principal(bout.tobytearray());
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("can't encode issuer dn");
        }
    }

    public principal getsubjectdn()
    {
        return new x509principal(x500name.getinstance(c.getsubject().toasn1primitive()));
    }

    public x500principal getsubjectx500principal()
    {
        try
        {
            bytearrayoutputstream   bout = new bytearrayoutputstream();
            asn1outputstream        aout = new asn1outputstream(bout);

            aout.writeobject(c.getsubject());

            return new x500principal(bout.tobytearray());
        }
        catch (ioexception e)
        {
            throw new illegalstateexception("can't encode issuer dn");
        }
    }

    public date getnotbefore()
    {
        return c.getstartdate().getdate();
    }

    public date getnotafter()
    {
        return c.getenddate().getdate();
    }

    public byte[] gettbscertificate()
        throws certificateencodingexception
    {
        try
        {
            return c.gettbscertificate().getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new certificateencodingexception(e.tostring());
        }
    }

    public byte[] getsignature()
    {
        return c.getsignature().getbytes();
    }

    /**
     * return a more "meaningful" representation for the signature algorithm used in
     * the certficate.
     */
    public string getsigalgname()
    {
        provider    prov = security.getprovider(bouncycastleprovider.provider_name);

        if (prov != null)
        {
            string      algname = prov.getproperty("alg.alias.signature." + this.getsigalgoid());

            if (algname != null)
            {
                return algname;
            }
        }

        provider[] provs = security.getproviders();

        //
        // search every provider looking for a real algorithm
        //
        for (int i = 0; i != provs.length; i++)
        {
            string algname = provs[i].getproperty("alg.alias.signature." + this.getsigalgoid());
            if (algname != null)
            {
                return algname;
            }
        }

        return this.getsigalgoid();
    }

    /**
     * return the object identifier for the signature.
     */
    public string getsigalgoid()
    {
        return c.getsignaturealgorithm().getalgorithm().getid();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getsigalgparams()
    {
        if (c.getsignaturealgorithm().getparameters() != null)
        {
            try
            {
                return c.getsignaturealgorithm().getparameters().toasn1primitive().getencoded(asn1encoding.der);
            }
            catch (ioexception e)
            {
                return null;
            }
        }
        else
        {
            return null;
        }
    }

    public boolean[] getissueruniqueid()
    {
        derbitstring    id = c.gettbscertificate().getissueruniqueid();

        if (id != null)
        {
            byte[]          bytes = id.getbytes();
            boolean[]       boolid = new boolean[bytes.length * 8 - id.getpadbits()];

            for (int i = 0; i != boolid.length; i++)
            {
                boolid[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolid;
        }
            
        return null;
    }

    public boolean[] getsubjectuniqueid()
    {
        derbitstring    id = c.gettbscertificate().getsubjectuniqueid();

        if (id != null)
        {
            byte[]          bytes = id.getbytes();
            boolean[]       boolid = new boolean[bytes.length * 8 - id.getpadbits()];

            for (int i = 0; i != boolid.length; i++)
            {
                boolid[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolid;
        }
            
        return null;
    }

    public boolean[] getkeyusage()
    {
        return keyusage;
    }

    public list getextendedkeyusage() 
        throws certificateparsingexception
    {
        byte[]  bytes = this.getextensionbytes("2.5.29.37");

        if (bytes != null)
        {
            try
            {
                asn1inputstream din = new asn1inputstream(bytes);
                asn1sequence    seq = (asn1sequence)din.readobject();
                list            list = new arraylist();

                for (int i = 0; i != seq.size(); i++)
                {
                    list.add(((asn1objectidentifier)seq.getobjectat(i)).getid());
                }
                
                return collections.unmodifiablelist(list);
            }
            catch (exception e)
            {
                throw new certificateparsingexception("error processing extended key usage extension");
            }
        }

        return null;
    }
    
    public int getbasicconstraints()
    {
        if (basicconstraints != null)
        {
            if (basicconstraints.isca())
            {
                if (basicconstraints.getpathlenconstraint() == null)
                {
                    return integer.max_value;
                }
                else
                {
                    return basicconstraints.getpathlenconstraint().intvalue();
                }
            }
            else
            {
                return -1;
            }
        }

        return -1;
    }

    public collection getsubjectalternativenames()
        throws certificateparsingexception
    {
        return getalternativenames(getextensionbytes(extension.subjectalternativename.getid()));
    }

    public collection getissueralternativenames()
        throws certificateparsingexception
    {
        return getalternativenames(getextensionbytes(extension.issueralternativename.getid()));
    }

    public set getcriticalextensionoids() 
    {
        if (this.getversion() == 3)
        {
            set             set = new hashset();
            extensions  extensions = c.gettbscertificate().getextensions();

            if (extensions != null)
            {
                enumeration     e = extensions.oids();

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    extension       ext = extensions.getextension(oid);

                    if (ext.iscritical())
                    {
                        set.add(oid.getid());
                    }
                }

                return set;
            }
        }

        return null;
    }

    private byte[] getextensionbytes(string oid)
    {
        extensions exts = c.gettbscertificate().getextensions();

        if (exts != null)
        {
            extension   ext = exts.getextension(new asn1objectidentifier(oid));
            if (ext != null)
            {
                return ext.getextnvalue().getoctets();
            }
        }

        return null;
    }

    public byte[] getextensionvalue(string oid) 
    {
        extensions exts = c.gettbscertificate().getextensions();

        if (exts != null)
        {
            extension   ext = exts.getextension(new asn1objectidentifier(oid));

            if (ext != null)
            {
                try
                {
                    return ext.getextnvalue().getencoded();
                }
                catch (exception e)
                {
                    throw new illegalstateexception("error parsing " + e.tostring());
                }
            }
        }

        return null;
    }

    public set getnoncriticalextensionoids() 
    {
        if (this.getversion() == 3)
        {
            set             set = new hashset();
            extensions  extensions = c.gettbscertificate().getextensions();

            if (extensions != null)
            {
                enumeration     e = extensions.oids();

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    extension       ext = extensions.getextension(oid);

                    if (!ext.iscritical())
                    {
                        set.add(oid.getid());
                    }
                }

                return set;
            }
        }

        return null;
    }

    public boolean hasunsupportedcriticalextension()
    {
        if (this.getversion() == 3)
        {
            extensions  extensions = c.gettbscertificate().getextensions();

            if (extensions != null)
            {
                enumeration     e = extensions.oids();

                while (e.hasmoreelements())
                {
                    asn1objectidentifier oid = (asn1objectidentifier)e.nextelement();
                    string              oidid = oid.getid();

                    if (oidid.equals(rfc3280certpathutilities.key_usage)
                     || oidid.equals(rfc3280certpathutilities.certificate_policies)
                     || oidid.equals(rfc3280certpathutilities.policy_mappings)
                     || oidid.equals(rfc3280certpathutilities.inhibit_any_policy)
                     || oidid.equals(rfc3280certpathutilities.crl_distribution_points)
                     || oidid.equals(rfc3280certpathutilities.issuing_distribution_point)
                     || oidid.equals(rfc3280certpathutilities.delta_crl_indicator)
                     || oidid.equals(rfc3280certpathutilities.policy_constraints)
                     || oidid.equals(rfc3280certpathutilities.basic_constraints)
                     || oidid.equals(rfc3280certpathutilities.subject_alternative_name)
                     || oidid.equals(rfc3280certpathutilities.name_constraints))
                    {
                        continue;
                    }

                    extension       ext = extensions.getextension(oid);

                    if (ext.iscritical())
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public publickey getpublickey()
    {
        try
        {
            return bouncycastleprovider.getpublickey(c.getsubjectpublickeyinfo());
        }
        catch (ioexception e)
        {
            return null;   // should never happen...
        }
    }

    public byte[] getencoded()
        throws certificateencodingexception
    {
        try
        {
            return c.getencoded(asn1encoding.der);
        }
        catch (ioexception e)
        {
            throw new certificateencodingexception(e.tostring());
        }
    }

    public boolean equals(
        object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof certificate))
        {
            return false;
        }

        certificate other = (certificate)o;

        try
        {
            byte[] b1 = this.getencoded();
            byte[] b2 = other.getencoded();

            return arrays.areequal(b1, b2);
        }
        catch (certificateencodingexception e)
        {
            return false;
        }
    }
    
    public synchronized int hashcode()
    {
        if (!hashvalueset)
        {
            hashvalue = calculatehashcode();
            hashvalueset = true;
        }

        return hashvalue;
    }
    
    private int calculatehashcode()
    {
        try
        {
            int hashcode = 0;
            byte[] certdata = this.getencoded();
            for (int i = 1; i < certdata.length; i++)
            {
                 hashcode += certdata[i] * i;
            }
            return hashcode;
        }
        catch (certificateencodingexception e)
        {
            return 0;
        }
    }

    public void setbagattribute(
        asn1objectidentifier oid,
        asn1encodable        attribute)
    {
        attrcarrier.setbagattribute(oid, attribute);
    }

    public asn1encodable getbagattribute(
        asn1objectidentifier oid)
    {
        return attrcarrier.getbagattribute(oid);
    }

    public enumeration getbagattributekeys()
    {
        return attrcarrier.getbagattributekeys();
    }

    public string tostring()
    {
        stringbuffer    buf = new stringbuffer();
        string          nl = system.getproperty("line.separator");

        buf.append("  [0]         version: ").append(this.getversion()).append(nl);
        buf.append("         serialnumber: ").append(this.getserialnumber()).append(nl);
        buf.append("             issuerdn: ").append(this.getissuerdn()).append(nl);
        buf.append("           start date: ").append(this.getnotbefore()).append(nl);
        buf.append("           final date: ").append(this.getnotafter()).append(nl);
        buf.append("            subjectdn: ").append(this.getsubjectdn()).append(nl);
        buf.append("           public key: ").append(this.getpublickey()).append(nl);
        buf.append("  signature algorithm: ").append(this.getsigalgname()).append(nl);

        byte[]  sig = this.getsignature();

        buf.append("            signature: ").append(new string(hex.encode(sig, 0, 20))).append(nl);
        for (int i = 20; i < sig.length; i += 20)
        {
            if (i < sig.length - 20)
            {
                buf.append("                       ").append(new string(hex.encode(sig, i, 20))).append(nl);
            }
            else
            {
                buf.append("                       ").append(new string(hex.encode(sig, i, sig.length - i))).append(nl);
            }
        }

        extensions extensions = c.gettbscertificate().getextensions();

        if (extensions != null)
        {
            enumeration     e = extensions.oids();

            if (e.hasmoreelements())
            {
                buf.append("       extensions: \n");
            }

            while (e.hasmoreelements())
            {
                asn1objectidentifier     oid = (asn1objectidentifier)e.nextelement();
                extension ext = extensions.getextension(oid);

                if (ext.getextnvalue() != null)
                {
                    byte[]                  octs = ext.getextnvalue().getoctets();
                    asn1inputstream         din = new asn1inputstream(octs);
                    buf.append("                       critical(").append(ext.iscritical()).append(") ");
                    try
                    {
                        if (oid.equals(extension.basicconstraints))
                        {
                            buf.append(basicconstraints.getinstance(din.readobject())).append(nl);
                        }
                        else if (oid.equals(extension.keyusage))
                        {
                            buf.append(keyusage.getinstance(din.readobject())).append(nl);
                        }
                        else if (oid.equals(miscobjectidentifiers.netscapecerttype))
                        {
                            buf.append(new netscapecerttype((derbitstring)din.readobject())).append(nl);
                        }
                        else if (oid.equals(miscobjectidentifiers.netscaperevocationurl))
                        {
                            buf.append(new netscaperevocationurl((deria5string)din.readobject())).append(nl);
                        }
                        else if (oid.equals(miscobjectidentifiers.verisignczagextension))
                        {
                            buf.append(new verisignczagextension((deria5string)din.readobject())).append(nl);
                        }
                        else 
                        {
                            buf.append(oid.getid());
                            buf.append(" value = ").append(asn1dump.dumpasstring(din.readobject())).append(nl);
                            //buf.append(" value = ").append("*****").append(nl);
                        }
                    }
                    catch (exception ex)
                    {
                        buf.append(oid.getid());
                   //     buf.append(" value = ").append(new string(hex.encode(ext.getextnvalue().getoctets()))).append(nl);
                        buf.append(" value = ").append("*****").append(nl);
                    }
                }
                else
                {
                    buf.append(nl);
                }
            }
        }

        return buf.tostring();
    }

    public final void verify(
        publickey   key)
        throws certificateexception, nosuchalgorithmexception,
        invalidkeyexception, nosuchproviderexception, signatureexception
    {
        signature   signature;
        string      signame = x509signatureutil.getsignaturename(c.getsignaturealgorithm());
        
        try
        {
            signature = signature.getinstance(signame, bouncycastleprovider.provider_name);
        }
        catch (exception e)
        {
            signature = signature.getinstance(signame);
        }
        
        checksignature(key, signature);
    }
    
    public final void verify(
        publickey   key,
        string      sigprovider)
        throws certificateexception, nosuchalgorithmexception,
        invalidkeyexception, nosuchproviderexception, signatureexception
    {
        string    signame = x509signatureutil.getsignaturename(c.getsignaturealgorithm());
        signature signature = signature.getinstance(signame, sigprovider);
        
        checksignature(key, signature);
    }

    private void checksignature(
        publickey key, 
        signature signature) 
        throws certificateexception, nosuchalgorithmexception, 
            signatureexception, invalidkeyexception
    {
        if (!isalgidequal(c.getsignaturealgorithm(), c.gettbscertificate().getsignature()))
        {
            throw new certificateexception("signature algorithm in tbs cert not same as outer cert");
        }

        asn1encodable params = c.getsignaturealgorithm().getparameters();

        // todo this should go after the initverify?
        x509signatureutil.setsignatureparameters(signature, params);

        signature.initverify(key);

        signature.update(this.gettbscertificate());

        if (!signature.verify(this.getsignature()))
        {
            throw new signatureexception("certificate does not verify with supplied key");
        }
    }

    private boolean isalgidequal(algorithmidentifier id1, algorithmidentifier id2)
    {
        if (!id1.getalgorithm().equals(id2.getalgorithm()))
        {
            return false;
        }

        if (id1.getparameters() == null)
        {
            if (id2.getparameters() != null && !id2.getparameters().equals(dernull.instance))
            {
                return false;
            }

            return true;
        }

        if (id2.getparameters() == null)
        {
            if (id1.getparameters() != null && !id1.getparameters().equals(dernull.instance))
            {
                return false;
            }

            return true;
        }
        
        return id1.getparameters().equals(id2.getparameters());
    }

    private static collection getalternativenames(byte[] extval)
        throws certificateparsingexception
    {
        if (extval == null)
        {
            return null;
        }
        try
        {
            collection temp = new arraylist();
            enumeration it = asn1sequence.getinstance(extval).getobjects();
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
                    list.add(genname.getencoded());
                    break;
                case generalname.directoryname:
                    list.add(x500name.getinstance(rfc4519style.instance, genname.getname()).tostring());
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
                    byte[] addrbytes = deroctetstring.getinstance(genname.getname()).getoctets();
                    final string addr;
                    try
                    {
                        addr = inetaddress.getbyaddress(addrbytes).gethostaddress();
                    }
                    catch (unknownhostexception e)
                    {
                        continue;
                    }
                    list.add(addr);
                    break;
                default:
                    throw new ioexception("bad tag number: " + genname.gettagno());
                }

                temp.add(collections.unmodifiablelist(list));
            }
            if (temp.size() == 0)
            {
                return null;
            }
            return collections.unmodifiablecollection(temp);
        }
        catch (exception e)
        {
            throw new certificateparsingexception(e.getmessage());
        }
    }
}
