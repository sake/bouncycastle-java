package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.ProviderUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    String algorithm;

    KeyFactorySpi(
        String algorithm)
    {
        this.algorithm = algorithm;
    }

    protected Key engineTranslateKey(
        Key    key)
        throws InvalidKeyException
    {
        if (key instanceof ECPublicKey)
        {
            return new BCECPublicKey((ECPublicKey)key);
        }
        else if (key instanceof ECPrivateKey)
        {
            return new BCECPrivateKey((ECPrivateKey)key);
        }

        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(
        Key    key,
        Class    spec)
    throws InvalidKeySpecException
    {
       if (spec.isAssignableFrom(org.bouncycastle.jce.spec.ECPublicKeySpec.class) && key instanceof ECPublicKey)
       {
           ECPublicKey k = (ECPublicKey)key;
           if (k.getParams() != null)
           {
               return new org.bouncycastle.jce.spec.ECPublicKeySpec(k.getQ(), k.getParameters());
           }
           else
           {
               ECParameterSpec implicitSpec = ProviderUtil.getEcImplicitlyCa();

               return new org.bouncycastle.jce.spec.ECPublicKeySpec(k.getQ(), implicitSpec);
           }
       }
       else if (spec.isAssignableFrom(org.bouncycastle.jce.spec.ECPrivateKeySpec.class) && key instanceof ECPrivateKey)
       {
           ECPrivateKey k = (ECPrivateKey)key;

           if (k.getParams() != null)
           {
               return new org.bouncycastle.jce.spec.ECPrivateKeySpec(k.getD(), k.getParameters());
           }
           else
           {
               ECParameterSpec implicitSpec = ProviderUtil.getEcImplicitlyCa();

               return new org.bouncycastle.jce.spec.ECPrivateKeySpec(k.getD(), implicitSpec);
           }
       }
       return super.engineGetKeySpec(key, spec);
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof ECPrivateKeySpec)
        {
            return new BCECPrivateKey(algorithm, (ECPrivateKeySpec)keySpec);
        }

        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof ECPublicKeySpec)
        {
            return new BCECPublicKey(algorithm, (ECPublicKeySpec)keySpec);
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            return new BCECPrivateKey(algorithm, keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (algOid.equals(X9ObjectIdentifiers.id_ecPublicKey))
        {
            return new BCECPublicKey(algorithm, keyInfo);
        }
        else
        {
            throw new IOException("algorithm identifier " + algOid + " in key not recognised");
        }
    }

    public static class EC
        extends KeyFactorySpi
    {
        public EC()
        {
            super("EC");
        }
    }

    public static class ECDSA
        extends KeyFactorySpi
    {
        public ECDSA()
        {
            super("ECDSA");
        }
    }

    public static class ECGOST3410
        extends KeyFactorySpi
    {
        public ECGOST3410()
        {
            super("ECGOST3410");
        }
    }

    public static class ECDH
        extends KeyFactorySpi
    {
        public ECDH()
        {
            super("ECDH");
        }
    }

    public static class ECDHC
        extends KeyFactorySpi
    {
        public ECDHC()
        {
            super("ECDHC");
        }
    }

    public static class ECMQV
        extends KeyFactorySpi
    {
        public ECMQV()
        {
            super("ECMQV");
        }
    }
}
