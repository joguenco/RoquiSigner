package dev.joguenco.roqui.signer.provider;

import xades4j.providers.impl.KeyStoreKeyingDataProvider;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class KeyStoreDataProvider extends KeyStoreKeyingDataProvider {

    protected KeyStoreDataProvider(KeyStore keyStore,
                                   SigningCertSelector certificateSelector,
                                   KeyStorePasswordProvider storePasswordProvider,
                                   KeyEntryPasswordProvider entryPasswordProvider,
                                   boolean returnFullChain) {
        super(loadProtection -> KeyStore.Builder.newInstance(keyStore, loadProtection),
                certificateSelector,
                storePasswordProvider,
                entryPasswordProvider,
                returnFullChain);
    }

    @Override
    protected KeyStore.ProtectionParameter getKeyProtection(String entryAlias, X509Certificate entryCert, KeyEntryPasswordProvider entryPasswordProvider) {
        return new KeyStore.PasswordProtection(entryPasswordProvider.getPassword(entryAlias, entryCert));
    }
}