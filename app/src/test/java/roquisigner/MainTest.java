/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package roquisigner;

import dev.joguenco.roqui.signer.Main;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MainTest {
    @Test public void appSignXmlFile() {
        Main classUnderTest = new Main();
        assertTrue(classUnderTest.SignXmlFile().contains("Document signed"));
    }
}