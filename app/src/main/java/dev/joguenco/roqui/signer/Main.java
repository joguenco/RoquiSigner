package dev.joguenco.roqui.signer;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

public class Main {

    public static void main(String[] args) throws RuntimeException {
        Logger logger = LoggerFactory.getLogger(Main.class);
        logger.info("Roqui Signer");

        System.out.println(new Main().SignXmlFile());
    }

    public String SignXmlFile() {
        ClassLoader classLoader = Main.class.getClassLoader();

        var pathDigitalCertificate = classLoader.getResource("Hacker.p12").getPath();
        var password = "No_Piratear";
        var pathXmlFile = classLoader
                .getResource("0301202301123456789000110010030000000071234567811.xml").getPath();

        var fileXml = new File(pathXmlFile);

        var signer = new Signer();

        try {
            var pathOutPutFile = fileXml.getParent() + File.separator +
                    getNameFileWithOutExtension(fileXml.getName()) +"-signed" + ".xml";

            signer.sign(pathDigitalCertificate,
                    password,
                    pathXmlFile,
                    pathOutPutFile);

            return "Document signed saved in " + pathOutPutFile;

        } catch (IOException e) {
            return "Document no signed ";
        }
    }

    String getNameFileWithOutExtension(String fileName) {
        int indexOf = fileName.indexOf(".");
        if (indexOf == -1)
            return fileName;
        return fileName.substring(0, indexOf);
    }
}
