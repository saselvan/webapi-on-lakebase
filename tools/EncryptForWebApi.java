import java.nio.file.Files;
import java.nio.file.Paths;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

/**
 * Encrypt a value exactly as WebAPI's EncryptorUtils does (jasypt 1.9.2 + BouncyCastle), so the plaintext
 * never lands in webapi.source. Reads key + value from files (never argv), writes "ENC(...)" to a file.
 * Usage: java -cp jasypt-1.9.2.jar:bcprov-jdk15on-1.69.jar:. EncryptForWebApi <algorithm> <keyFile> <valueFile> <outFile>
 * Self-check: decrypts the result and fails if it does not round-trip.
 */
public class EncryptForWebApi {
    public static void main(String[] a) throws Exception {
        StandardPBEStringEncryptor e = new StandardPBEStringEncryptor();
        e.setProvider(new BouncyCastleProvider());
        e.setProviderName("BC");
        e.setAlgorithm(a[0]);
        e.setPassword(new String(Files.readAllBytes(Paths.get(a[1]))).trim());
        String value = new String(Files.readAllBytes(Paths.get(a[2]))).trim();
        String cipher = e.encrypt(value);
        if (!value.equals(e.decrypt(cipher))) throw new IllegalStateException("round-trip failed");
        Files.write(Paths.get(a[3]), ("ENC(" + cipher + ")").getBytes());
        System.out.println("encrypted ok (" + cipher.length() + " chars), round-trip verified");
    }
}
