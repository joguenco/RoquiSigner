package dev.joguenco.roqui.signer.xml;

import dev.joguenco.roqui.signer.provider.KeyStoreManager;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.XAdES4jException;
import xades4j.production.XadesSignatureResult;
import java.io.ByteArrayInputStream;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

public class SignerXAdESXml {

    public Document sign(ResourcesForSign resourcesForSign) throws KeyStoreException, XAdES4jException, KeyResolverException {
        ByteArrayInputStream certificateInputStream = new ByteArrayInputStream(resourcesForSign.getCertificate());
        Document document = resourcesForSign.getDocumentXmlToSign();
        Element elementToSign = loadIdentifierToSign(document, resourcesForSign.getIdToSign());
        signXml(resourcesForSign, certificateInputStream, elementToSign);

        return document;
    }

    public static Element loadIdentifierToSign(Document document, String id) {
        Element element = document.getDocumentElement();
        useIdAsXmlId(element, id);
        return element;
    }

    public static void useIdAsXmlId(Element e, String id) {
        if (e.hasAttributeNS(null, id))
            e.setIdAttributeNS(null, id, true);
    }

    private X509Certificate getCertificateToSign(XadesSignatureResult xadesSignatureResult) throws KeyResolverException {
        XMLSignature signature = xadesSignatureResult.getSignature();
        KeyInfo keyInfo = signature.getKeyInfo();
        return keyInfo.getX509Certificate();
    }

    protected X509Certificate signXml(ResourcesForSign parametroFirma, ByteArrayInputStream certificadoInputStream, Element elem) throws KeyStoreException, KeyResolverException, XAdES4jException {
        XadesSignatureResult signatureResult = KeyStoreManager.createSign(parametroFirma, certificadoInputStream, elem);
        return getCertificateToSign(signatureResult);
    }
}
