package dev.joguenco.roqui.signer.provider;

import dev.joguenco.roqui.signer.xml.DefinitionSignedObject;
import dev.joguenco.roqui.signer.xml.ResourcesForSign;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.providers.KeyingDataProvider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public final class KeyStoreManager {
    private static KeyingDataProvider createKeyingDataProvider(DirectPasswordProvider directPasswordProvider, KeyStore keyStore) {
        return new KeyStoreDataProvider(keyStore,
                new CertificateLocalProvider(),
                directPasswordProvider,
                directPasswordProvider,
                false);
    }

    private static KeyStore createKeyStore(DirectPasswordProvider directPasswordProvider,
                                           ByteArrayInputStream certificateInputStream) throws KeyStoreException {
        KeyStore keyStore;

        try {
            keyStore = KeyStore.getInstance("pkcs12");
            keyStore.load(certificateInputStream, directPasswordProvider.getPassword());
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }

        return keyStore;
    }

    public static XadesSignatureResult createSign(ResourcesForSign resourcesForSign, ByteArrayInputStream certificadoInputStream, Element elem) throws KeyStoreException, XAdES4jException {
        KeyingDataProvider keyingProvider = createProvider(certificadoInputStream, resourcesForSign);
        SignedDataObjects signedDataObjects = DefinitionSignedObject.defineSignedObject(elem, resourcesForSign.getIdToSign());
        XadesSigner signer = new XadesBesSigningProfile(keyingProvider).newSigner();
        return signer.sign(signedDataObjects, elem);
    }

    private static KeyingDataProvider createProvider(ByteArrayInputStream certificateInputStream,
                                                     ResourcesForSign resourcesForSign) throws KeyStoreException {
        DirectPasswordProvider directPasswordProvider = new DirectPasswordProvider(resourcesForSign.getPassword());
        KeyStore keyStore = createKeyStore(directPasswordProvider, certificateInputStream);
        return createKeyingDataProvider(directPasswordProvider, keyStore);
    }
}
