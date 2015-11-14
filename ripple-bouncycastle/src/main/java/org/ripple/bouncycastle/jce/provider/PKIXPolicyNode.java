package org.ripple.bouncycastle.jce.provider;

import java.security.cert.policynode;
import java.util.arraylist;
import java.util.hashset;
import java.util.iterator;
import java.util.list;
import java.util.set;

public class pkixpolicynode
    implements policynode
{
    protected list       children;
    protected int        depth;
    protected set        expectedpolicies;
    protected policynode parent;
    protected set        policyqualifiers;
    protected string     validpolicy;
    protected boolean    critical;
    
    /*  
     *  
     *  constructors
     *  
     */ 
    
    public pkixpolicynode(
        list       _children,
        int        _depth,
        set        _expectedpolicies,
        policynode _parent,
        set        _policyqualifiers,
        string     _validpolicy,
        boolean    _critical)
    {
        children         = _children;
        depth            = _depth;
        expectedpolicies = _expectedpolicies;
        parent           = _parent;
        policyqualifiers = _policyqualifiers;
        validpolicy      = _validpolicy;
        critical         = _critical;
    }
    
    public void addchild(
        pkixpolicynode _child)
    {
        children.add(_child);
        _child.setparent(this);
    }
    
    public iterator getchildren()
    {
        return children.iterator();
    }
    
    public int getdepth()
    {
        return depth;
    }
    
    public set getexpectedpolicies()
    {
        return expectedpolicies;
    }
    
    public policynode getparent()
    {
        return parent;
    }
    
    public set getpolicyqualifiers()
    {
        return policyqualifiers;
    }
    
    public string getvalidpolicy()
    {
        return validpolicy;
    }
    
    public boolean haschildren()
    {
        return !children.isempty();
    }
    
    public boolean iscritical()
    {
        return critical;
    }
    
    public void removechild(pkixpolicynode _child)
    {
        children.remove(_child);
    }
    
    public void setcritical(boolean _critical)
    {
        critical = _critical;
    }
    
    public void setparent(pkixpolicynode _parent)
    {
        parent = _parent;
    }
    
    public string tostring()
    {
        return tostring("");
    }
    
    public string tostring(string _indent)
    {
        stringbuffer _buf = new stringbuffer();
        _buf.append(_indent);
        _buf.append(validpolicy);
        _buf.append(" {\n");
        
        for(int i = 0; i < children.size(); i++)
        {
            _buf.append(((pkixpolicynode)children.get(i)).tostring(_indent + "    "));
        }
        
        _buf.append(_indent);
        _buf.append("}\n");
        return _buf.tostring();
    }
    
    public object clone()
    {
        return copy();
    }
    
    public pkixpolicynode copy()
    {
        set     _expectedpolicies = new hashset();
        iterator _iter = expectedpolicies.iterator();
        while (_iter.hasnext())
        {
            _expectedpolicies.add(new string((string)_iter.next()));
        }
        
        set     _policyqualifiers = new hashset();
        _iter = policyqualifiers.iterator();
        while (_iter.hasnext())
        {
            _policyqualifiers.add(new string((string)_iter.next()));
        }
        
        pkixpolicynode _node = new pkixpolicynode(new arraylist(),
                                                  depth,
                                                  _expectedpolicies,
                                                  null,
                                                  _policyqualifiers,
                                                  new string(validpolicy),
                                                  critical);
        
        _iter = children.iterator();
        while (_iter.hasnext())
        {
            pkixpolicynode _child = ((pkixpolicynode)_iter.next()).copy();
            _child.setparent(_node);
            _node.addchild(_child);
        }
        
        return _node;
    }
}
