package org.ripple.bouncycastle.openpgp;

import java.io.eofexception;
import java.io.ioexception;
import java.io.inputstream;
import java.util.zip.inflater;
import java.util.zip.inflaterinputstream;

import org.ripple.bouncycastle.apache.bzip2.cbzip2inputstream;
import org.ripple.bouncycastle.bcpg.bcpginputstream;
import org.ripple.bouncycastle.bcpg.compresseddatapacket;
import org.ripple.bouncycastle.bcpg.compressionalgorithmtags;

/**
 * compressed data objects.
 */
public class pgpcompresseddata 
    implements compressionalgorithmtags
{
    compresseddatapacket    data;
    
    public pgpcompresseddata(
        bcpginputstream    pin)
        throws ioexception
    {
        data = (compresseddatapacket)pin.readpacket();
    }
    
    /**
     * return the algorithm used for compression
     * 
     * @return algorithm code
     */
    public int getalgorithm()
    {
        return data.getalgorithm();
    }
    
    /**
     * return the raw input stream contained in the object.
     * 
     * @return inputstream
     */
    public inputstream getinputstream()
    {
        return data.getinputstream();
    }
    
    /**
     * return an uncompressed input stream which allows reading of the 
     * compressed data.
     * 
     * @return inputstream
     * @throws pgpexception
     */
    public inputstream getdatastream()
        throws pgpexception
    {
      if (this.getalgorithm() == uncompressed)
      {
          return this.getinputstream();
      }
      if (this.getalgorithm() == zip)
      {
          return new inflaterinputstream(this.getinputstream(), new inflater(true)) 
          {
              // if the "nowrap" inflater option is used the stream can 
              // apparently overread - we override fill() and provide
              // an extra byte for the end of the input stream to get
              // around this.
              //
              // totally weird...
              //
              protected void fill() throws ioexception
              {
                  if (eof)
                  {
                      throw new eofexception("unexpected end of zip input stream");
                  }
                  
                  len = this.in.read(buf, 0, buf.length);
                  
                  if (len == -1)
                  {
                      buf[0] = 0;
                      len = 1;
                      eof = true;
                  }
                  
                  inf.setinput(buf, 0, len);
              }

              private boolean eof = false;
          };
      }
      if (this.getalgorithm() == zlib)
      {
          return new inflaterinputstream(this.getinputstream())
          {
              // if the "nowrap" inflater option is used the stream can 
              // apparently overread - we override fill() and provide
              // an extra byte for the end of the input stream to get
              // around this.
              //
              // totally weird...
              //
              protected void fill() throws ioexception
              {
                  if (eof)
                  {
                      throw new eofexception("unexpected end of zip input stream");
                  }
                  
                  len = this.in.read(buf, 0, buf.length);
                  
                  if (len == -1)
                  {
                      buf[0] = 0;
                      len = 1;
                      eof = true;
                  }

                  inf.setinput(buf, 0, len);
              }

              private boolean eof = false;
          };
      }
      if (this.getalgorithm() == bzip2)
      {
          try
          {
              return new cbzip2inputstream(this.getinputstream());
          }
          catch (ioexception e)
          {
              throw new pgpexception("i/o problem with stream: " + e, e);
          }
      }
        
      throw new pgpexception("can't recognise compression algorithm: " + this.getalgorithm());
    }
}
