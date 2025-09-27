// JavaNativeSSL.java - JNI를 통해 OpenSSL을 직접 호출하는 Java 프로그램
public class JavaNativeSSL {
    
    // 네이티브 메서드 선언
    public native byte[] nativeAESEncrypt(byte[] key, byte[] data);
    
    static {
        // 네이티브 라이브러리 로드
        try {
            System.loadLibrary("javanativessl");
            System.out.println("Successfully loaded native SSL library");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load native library: " + e.getMessage());
            System.err.println("Create the shared library with:");
            System.err.println("gcc -shared -fPIC -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JavaNativeSSL.c -lssl -lcrypto -o libjavanativessl.so");
        }
    }
    
    public static void main(String[] args) {
        try {
            JavaNativeSSL ssl = new JavaNativeSSL();
            
            System.out.println("Java Native OpenSSL Test Starting...");
            
            // 32바이트 AES-256 키 생성
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) {
                key[i] = (byte)(i * 7 + 13); // 간단한 테스트 키
            }
            
            String plaintext = "Hello, this is a test message for native OpenSSL encryption!";
            byte[] data = plaintext.getBytes();
            
            System.out.println("Original data: " + plaintext);
            System.out.println("Key length: " + key.length + " bytes");
            
            // 네이티브 OpenSSL 암호화 호출 - 여기서 후킹될 것임!
            byte[] encrypted = ssl.nativeAESEncrypt(key, data);
            
            if (encrypted != null) {
                System.out.println("Encryption successful!");
                System.out.println("Encrypted length: " + encrypted.length + " bytes");
                
                // 16진수로 출력
                System.out.print("Encrypted data (hex): ");
                for (byte b : encrypted) {
                    System.out.printf("%02x", b & 0xff);
                }
                System.out.println();
                
                // 여러 번 암호화하여 더 많은 후킹 이벤트 생성
                for (int i = 0; i < 5; i++) {
                    key[0] = (byte)(key[0] + 1); // 키를 약간 변경
                    encrypted = ssl.nativeAESEncrypt(key, ("Test round " + i).getBytes());
                    System.out.println("Round " + i + " encryption completed, length: " + encrypted.length);
                }
                
            } else {
                System.out.println("Encryption failed!");
            }
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}