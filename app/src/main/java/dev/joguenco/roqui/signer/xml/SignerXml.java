package dev.joguenco.roqui.signer.xml;


import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import xades4j.XAdES4jException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;

public class SignerXml {

    public Document sign(byte[] certificate, String password, byte[] archivoXML) {
        var signerXAdESXml = new SignerXAdESXml();
        var resourcesForSign = new ResourcesForSign();

        InputStream xmlInputStream = new ByteArrayInputStream(archivoXML);

        resourcesForSign.setDocumentXmlToSign(parseXmlDocument(xmlInputStream));
        resourcesForSign.setCertificate(certificate);
        resourcesForSign.setPassword(password);
        resourcesForSign.setIdToSign("id");

        try {
            return signerXAdESXml.sign(resourcesForSign);
        } catch (KeyStoreException | XAdES4jException | KeyResolverException e) {
            throw new RuntimeException(e);
        }
    }

    Document parseXmlDocument(InputStream inputStream) {

        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db;
        try {
            db = dbf.newDocumentBuilder();
            return db.parse(inputStream);
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
