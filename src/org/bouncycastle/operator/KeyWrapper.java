package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KeyWrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    byte[] generateWrappedKey(byte[] encryptionKey)
        throws OperatorException;
}
