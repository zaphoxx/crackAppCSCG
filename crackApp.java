package crackApp;
//import java.util.Base64;
import org.bouncycastle.crypto.PBEParametersGenerator;
//import org.bouncycastle.crypto.generators.*; //p000a.p001a.p002a.p006c.*
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator; //p000a.p001a.p002a.p006c.C0010a;
//import org.bouncycastle.crypto.Mac; // import p000a.p001a.p002a.C0012i;
import org.bouncycastle.crypto.digests.SHA256Digest;
//import org.bouncycastle.crypto.BufferedBlockCipher;
//import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
//import org.bouncycastle.util.StreamParser;
//import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.crypto.params.ParametersWithIV;
//import org.bouncycastle.crypto.params.ParametersWithSalt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.engines.AESEngine;
//import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

public class SafeKeepCrack {
	private static final String CHARSET = "UTF-8";
	byte[] decoded;
	static String twitter="7Mag57i4xNJfkiLSpd+i47tFlmfYQAbutUTC3kzIwHw=";
	static String facebook="InUBCT0t5V3u/s5j7ihjHD7/Hy7pYV4sn3QV3yQdqdU=";
	static String CC="trdIdIb4MSYNH6sYfyr1EkhjCvTLeRHeb8yKPlcXkGTcPY5Is2jIRrjTO8RST06h";
	// loop to check for all pin possibilities 4 pin number --> only 10000 checks - that should be quick
	// result will give me the missing ByteArray for the actual note decryption
	public static void main(String[] args) throws Exception{
		char[] pin=new char[4];
		for (int a=0;a<10;a++){
			for (int b=0;b<10;b++){
				for(int c=0;c<10;c++){
					for(int d=0;d<10;d++){
						// once the pin has been found the loops are actually obsolete
						pin[0]=(char) (a+48);
						pin[1]=(char) (b+48);
						pin[2]=(char) (c+48);
						pin[3]=(char) (d+48);
						try{
							//System.out.println("[+] SUCCESS");
							System.out.println("[+] KEY: "+java.util.Base64.getEncoder().encodeToString(getSecretArray(new String(pin))));
							System.out.print("[+] PIN: ");
							System.out.print(new String(pin));
							System.out.println();
							System.out.println("[+] NOTES:");
							// try to decrypt the notes
							System.out.println("\t[+] twitter: \t"+ new String(decryptCipher(twitter,getSecretArray(new String(pin)))));
							System.out.println("\t[+] facebook: \t"+ new String(decryptCipher(facebook,getSecretArray(new String(pin)))));
							System.out.println("\t[+] CC : \t"+ new String(decryptCipher(CC,getSecretArray(new String(pin)))));
							System.out.println("---");
							System.exit(0);
						}catch(Exception e){
							System.out.println("[-] "+ (new String(pin)) + " | FAILED");
						}
					}
				}
			}
		}
	}
	
	public static byte[] getSecretArray(String str) throws Exception{
		String xmlString="Kec1leNIw8qTjrvaCgyhgnoho6YtxVc0/hVrHme0CeFQD+WqvG8HvnXHUYoTEgdQlXSG+c4KA9Zi3B3r/bl7eg==";
		byte[] pinByteArr=SafeKeepCrack.getKeyFromPin(str); // this is actually the key to decrypt the xmlString
		byte[] secretArr=decryptCipher(xmlString,pinByteArr); // this is the where the 32byte key is derived from
		if(secretArr[32]==97 && secretArr[33]==-109){
			byte[] outArr=new byte[secretArr.length-2];
			System.arraycopy(secretArr, 0,outArr, 0, secretArr.length - 2); // b copied into this.f2194a as 32byte array
			return outArr;
		}else{
			throw new Exception("[-] Wrong code | "+str);
		}	
	}
	static final byte[] decryptCipher(String str, byte[] key) throws Exception{
		byte[] base64decoded=Base64.decode(str.getBytes(CHARSET));
		byte[] iv=new byte[16];
		byte[] encodedData=new byte[base64decoded.length-16];
		System.arraycopy(base64decoded, 0, encodedData, 0, encodedData.length);
		System.arraycopy(base64decoded, encodedData.length, iv, 0, iv.length);
		return createSecretArr(encodedData, key, iv);
	}

	static final byte[] createSecretArr(byte[] bArr, byte[] bArr2, byte[] bArr3) throws Exception{
		PaddedBufferedBlockCipher pbbCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
		pbbCipher.init(false,new ParametersWithIV(new KeyParameter(bArr2), bArr3));
		return mangle(pbbCipher, bArr);
	}
	static final byte[] mangle(PaddedBufferedBlockCipher cipher,byte[] bArr) throws Exception{
		int outputSize=cipher.getOutputSize(bArr.length);
		int blockSize=cipher.getBlockSize();
		int c=bArr[blockSize-1] & 0xff;
		byte[] bArr2=new byte[cipher.getOutputSize(bArr.length)];
		int a = cipher.processBytes(bArr,0,bArr.length,bArr2,0);
		// pad block corrupted ??? --> using the wrong key causes that error !!! use try-catch in main
		a+=cipher.doFinal(bArr2, a);
		
		byte[] outArr=new byte[a];
		System.arraycopy(bArr2,0,outArr,0,a);
		return outArr;
	}
	
	static final byte[] getKeyFromPin(String str) throws Exception { // str == pin value
      Integer valueOf = Integer.valueOf(4096); // 512
      Integer valueOf2 = Integer.valueOf(256); // 32
      byte[] bytes = "7s1SZS*fX)7J6_5,3ksf|cdTC8W~{r~T<NME[Q2:|q`X*%|L(pid0v:':*O7y=ve".getBytes();
      char[] toCharArray = str.toCharArray();
      PKCS5S2ParametersGenerator PPG = new PKCS5S2ParametersGenerator(new SHA256Digest());
      PPG.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(toCharArray), bytes, valueOf.intValue());
      return ((KeyParameter) PPG.generateDerivedParameters(valueOf2.intValue())).getKey();
  }
  
}
