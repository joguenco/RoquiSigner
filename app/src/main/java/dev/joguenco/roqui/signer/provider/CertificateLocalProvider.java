package dev.joguenco.roqui.signer.provider;

import dev.joguenco.roqui.signer.exception.InvalidCertificateException;
import xades4j.providers.impl.KeyStoreKeyingDataProvider;

import java.security.cert.X509Certificate;
import java.util.List;

public class CertificateLocalProvider implements KeyStoreKeyingDataProvider.SigningCertSelector {

    /**
     * This method is used for return the local certificate provider,
     * this method no validate the local provider
     */
    public X509Certificate selectCertificate(List<X509Certificate> availableCertificates) {
        if (availableCertificates != null)
            for (X509Certificate x509Certificate : availableCertificates) {
                var keyUsage = x509Certificate.getKeyUsage();
                if (keyUsage == null) {
                    System.out.println("No es un certificado emitido por una entidad certificadora oficial");
                    return x509Certificate;
                }
                if (x509Certificate.getKeyUsage()[0])
                    return x509Certificate;
            }
        throw new InvalidCertificateException("No existe un proveedor local del certificado");
    }
}