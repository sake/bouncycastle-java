package org.bouncycastle.sasn1;

import java.io.InputStream;

public class DerOctetString 
    extends DerObject
    implements Asn1OctetString
{   
    protected DerOctetString(
        int         baseTag,
        byte[]      contentStream)
    {
        super(baseTag, BerTag.OCTET_STRING, contentStream);
    }
    
    public InputStream getOctetStream()
    {
        if (this.isConstructed())
        {
            return new ConstructedOctetStream(this.getRawContentStream());
        }
        else
        {
            return this.getRawContentStream();
        }
    }
}
