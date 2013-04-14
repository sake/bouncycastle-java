package org.bouncycastle.crypto.ec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

/**
 * this does your basic Elgamal encryption algorithm using EC
 */
public class ECElGamalEncryptor
{
    private ECPublicKeyParameters key;
    private SecureRandom          random;

    /**
     * initialise the EC Elgamal engine.
     *
     * @param param the necessary ElGamal key parameters.
     */
    public void init(
        CipherParameters    param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            if (!(p.getParameters() instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
            }
            this.key = (ECPublicKeyParameters)p.getParameters();
            this.random = p.getRandom();
        }
        else
        {
            if (!(param instanceof ECPublicKeyParameters))
            {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for encryption.");
            }

            this.key = (ECPublicKeyParameters)param;
            this.random = new SecureRandom();
        }
    }

    /**
     * Process a single EC point using the basic Elgamal algorithm.
     *
     * @param point the EC point to process.
     * @return the result of the Elgamal process.
     */
    public ECPair encrypt(ECPoint point)
    {
        if (key == null)
        {
            throw new IllegalStateException("ECElGamalEncryptor not initialised");
        }

        BigInteger             n = key.getParameters().getN();
        int                    nBitLength = n.bitLength();
        BigInteger             k = new BigInteger(nBitLength, random);

        while (k.equals(ECConstants.ZERO) || (k.compareTo(key.getParameters().getN()) >= 0))
        {
            k = new BigInteger(nBitLength, random);
        }

        ECPoint  g = key.getParameters().getG();
        ECPoint  gamma = g.multiply(k);
        ECPoint  phi = key.getQ().multiply(k).add(point);

        return new ECPair(gamma, phi);
    }
}
