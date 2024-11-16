package dev.joguenco.roqui.signer.xml;

import org.w3c.dom.Element;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.properties.DataObjectDesc;
import xades4j.properties.DataObjectFormatProperty;

public final class DefinitionSignedObject {
    public static SignedDataObjects defineSignedObject(Element elem, String id) {
        DataObjectDesc obj = (
                new DataObjectReference("#" + elem.getAttribute(id)))
                .withTransform(new EnvelopedSignatureTransform())
                .withDataObjectFormat((new DataObjectFormatProperty("text/xml", "UTF-8"))
                        .withDescription("Comprobante firmado para el SRI"));
        return (new SignedDataObjects()).withSignedDataObject(obj);
    }
}