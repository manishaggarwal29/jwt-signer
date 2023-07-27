import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class Application {

    public static void main(String[] args) throws Exception {
        System.out.println("Application Running!!");

        Map<String, Object> rsaKeys = JWTSigner.getRSAKeys();

        RSAPublicKey publicKey = (RSAPublicKey) rsaKeys.get("public");
        PrivateKey privateKey = (PrivateKey) rsaKeys.get("private");

        JWTSigner jwtSigner = new JWTSigner();
        jwtSigner.signJWT(privateKey, publicKey);
    }
}
