
package org.ripple.bouncycastle.i18n.filter;

public interface filter
{

    /**
     * runs the filter on the input string and returns the filtered string
     * @param input input string
     * @return filtered string
     */
    public string dofilter(string input);
    
    /**
     * runs the filter on the input url and returns the filtered string
     * @param input input url string
     * @return filtered string
     */
    public string dofilterurl(string input);

}
