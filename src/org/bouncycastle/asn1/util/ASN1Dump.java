package org.bouncycastle.asn1.util;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.BERConstructedSequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.DERConstructedSequence;
import org.bouncycastle.asn1.DERConstructedSet;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUnknownTag;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.BERApplicationSpecific;
import org.bouncycastle.util.encoders.Hex;

import java.util.Enumeration;
import java.io.IOException;

public class ASN1Dump
{
    private static final String  TAB = "    ";

    /**
     * dump a DER object as a formatted string with indentation
     *
     * @param obj the DERObject to be dumped out.
     */
    static String _dumpAsString(
        String      indent,
        DERObject   obj)
    {
        String nl = System.getProperty("line.separator");
        if (obj instanceof ASN1Sequence)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Sequence)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERConstructedSequence)
            {
                buf.append("BER ConstructedSequence");
            }
            else if (obj instanceof DERConstructedSequence)
            {
                buf.append("DER ConstructedSequence");
            }
            else if (obj instanceof BERSequence)
            {
                buf.append("BER Sequence");
            }
            else if (obj instanceof DERSequence)
            {
                buf.append("DER Sequence");
            }
            else
            {
                buf.append("Sequence");
            }

            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null || o.equals(new DERNull()))
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERTaggedObject)
        {
            StringBuffer    buf = new StringBuffer();
            String          tab = indent + TAB;

            buf.append(indent);
            if (obj instanceof BERTaggedObject)
            {
                buf.append("BER Tagged [");
            }
            else
            {
                buf.append("Tagged [");
            }

            DERTaggedObject o = (DERTaggedObject)obj;

            buf.append(Integer.toString(o.getTagNo()));
            buf.append(']');

            if (!o.isExplicit())
            {
                buf.append(" IMPLICIT ");
            }

            buf.append(nl);

            if (o.isEmpty())
            {
                buf.append(tab);
                buf.append("EMPTY");
                buf.append(nl);
            }
            else
            {
                buf.append(_dumpAsString(tab, o.getObject()));
            }

            return buf.toString();
        }
        else if (obj instanceof DERConstructedSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("ConstructedSet");
            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof BERSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("BER Set");
            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERSet)
        {
            StringBuffer    buf = new StringBuffer();
            Enumeration     e = ((ASN1Set)obj).getObjects();
            String          tab = indent + TAB;

            buf.append(indent);
            buf.append("DER Set");
            buf.append(nl);

            while (e.hasMoreElements())
            {
                Object  o = e.nextElement();

                if (o == null)
                {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                }
                else if (o instanceof DERObject)
                {
                    buf.append(_dumpAsString(tab, (DERObject)o));
                }
                else
                {
                    buf.append(_dumpAsString(tab, ((DEREncodable)o).getDERObject()));
                }
            }
            return buf.toString();
        }
        else if (obj instanceof DERObjectIdentifier)
        {
            return indent + "ObjectIdentifier(" + ((DERObjectIdentifier)obj).getId() + ")" + nl;
        }
        else if (obj instanceof DERBoolean)
        {
            return indent + "Boolean(" + ((DERBoolean)obj).isTrue() + ")" + nl;
        }
        else if (obj instanceof DERInteger)
        {
            return indent + "Integer(" + ((DERInteger)obj).getValue() + ")" + nl;
        }
        else if (obj instanceof BERConstructedOctetString)
        {
            return indent + "BER Constructed Octet String" + "[" + ((ASN1OctetString)obj).getOctets().length + "] " + nl;
        }
        else if (obj instanceof DEROctetString)
        {
            return indent + "DER Octet String" + "[" + ((ASN1OctetString)obj).getOctets().length + "] " + nl;
        }
        else if (obj instanceof DERBitString)
        {
            return indent + "DER Bit String" + "[" + ((DERBitString)obj).getBytes().length + ", " + ((DERBitString)obj).getPadBits() + "] " + nl;
        }
        else if (obj instanceof DERIA5String)
        {
            return indent + "IA5String(" + ((DERIA5String)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERUTF8String)
        {
            return indent + "UTF8String(" + ((DERUTF8String)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERPrintableString)
        {
            return indent + "PrintableString(" + ((DERPrintableString)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERVisibleString)
        {
            return indent + "VisibleString(" + ((DERVisibleString)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERBMPString)
        {
            return indent + "BMPString(" + ((DERBMPString)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERT61String)
        {
            return indent + "T61String(" + ((DERT61String)obj).getString() + ") " + nl;
        }
        else if (obj instanceof DERUTCTime)
        {
            return indent + "UTCTime(" + ((DERUTCTime)obj).getTime() + ") " + nl;
        }
        else if (obj instanceof DERGeneralizedTime)
        {
            return indent + "GeneralizedTime(" + ((DERGeneralizedTime)obj).getTime() + ") " + nl;
        }
        else if (obj instanceof DERUnknownTag)
        {
            return indent + "Unknown " + Integer.toString(((DERUnknownTag)obj).getTag(), 16) + " " + new String(Hex.encode(((DERUnknownTag)obj).getData())) + nl;
        }
        else if (obj instanceof BERApplicationSpecific)
        {
            return outputApplicationSpecific("BER", indent, obj, nl);
        }
        else if (obj instanceof DERApplicationSpecific)
        {
            return outputApplicationSpecific("DER", indent, obj, nl);
        }
        else
        {
            return indent + obj.toString() + nl;
        }
    }

    private static String outputApplicationSpecific(String type, String indent, DERObject obj, String nl)
    {
        DERApplicationSpecific app = (DERApplicationSpecific)obj;
        StringBuffer buf = new StringBuffer();

        if (app.isConstructed())
        {
            try
            {
                ASN1Sequence s = ASN1Sequence.getInstance(app.getObject(DERTags.SEQUENCE));
                buf.append(indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "]" + nl);
                for (Enumeration e = s.getObjects(); e.hasMoreElements();)
                {
                    buf.append(_dumpAsString(indent + TAB, (DERObject)e.nextElement()));
                }
            }
            catch (IOException e)
            {
                buf.append(e);
            }
            return buf.toString();
        }

        return indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "] (" + new String(Hex.encode(app.getContents())) + ")" + nl;
    }

    /**
     * dump out a DER object as a formatted string
     *
     * @param obj the DERObject to be dumped out.
     */
    public static String dumpAsString(
        Object   obj)
    {
        if (obj instanceof DERObject)
        {
            return _dumpAsString("", (DERObject)obj);
        }
        else if (obj instanceof DEREncodable)
        {
            return _dumpAsString("", ((DEREncodable)obj).getDERObject());
        }

        return "unknown object type " + obj.toString();
    }
}
