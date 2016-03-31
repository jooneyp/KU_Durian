package ebdcrypto;

public class Main {
	public static void main(String[] args) {
		byte[] qx = new byte[32];
		byte[] qy = new byte[32];
		byte[] d = new byte[32];
		
		ECDSA ecdsa = new ECDSA();
		ecdsa.gen_keypair();
		
		int len = ecdsa.get_public_qx(qx, 0);
//		Log.e("Print", "Qx : " + BytesUtils.HextoString(qx) + " // len : " + len);
		System.out.println("Qx : " + BytesUtils.HextoString(qx) + " // len : " + len);
		
		len = ecdsa.get_public_qy(qy, 0);
//		Log.e("Print", "Qy : " + BytesUtils.HextoString(qy) + " // len : " + len);
		System.out.println("Qy : " + BytesUtils.HextoString(qy) + " // len : " + len);
		
		len = ecdsa.get_private_d(d, 0);
//		Log.e("Print", "d : " + BytesUtils.HextoString(d) + " // len : " + len);
		System.out.println("d : " + BytesUtils.HextoString(d) + " // len : " + len);
		
		ecdsa.clear();
		
		byte[] signature = new byte [64];
		len = ecdsa.generate_signature(ECDSA.SHA256, d, 0, 32, "Hi there!".getBytes(), 0, "Hi there!".getBytes().length, signature, 0);
//		Log.e("Print", "Sign : " + BytesUtils.HextoString(signature) + " // len : " + len);
		System.out.println("Sign : " + BytesUtils.HextoString(signature) + " // len : " + len);
		
		int result = ecdsa.verify_signature(ECDSA.SHA256, qx, 0, 32, qy, 0, 32, "Hi there!".getBytes(), 0, "Hi there!".getBytes().length, signature, 0, len);
		if(result == 1)
		{
//			Log.e("Print", "Verify Success");
			System.out.println("Verify Success");
		}
		else
		{
//			Log.e("Print", "Verify Fail");
			System.out.println("Verify Fail");
		}

		
		String a = "";
		byte[] out = new byte[50];
		
		qx = "pubKey_xpubKpubKey_xpubKpubKey_x".getBytes();
		qy = "pubKey_ypubKpubKey_ypubKpubKey_y".getBytes();
		
		GenerateCertCSR genCSR = new GenerateCertCSR();
		out = genCSR.generateCertCSR("JoonYoung".getBytes(), 0, 9, "900104".getBytes(), 0, 6, "01097662526".getBytes(), 0, 11
				, "usimusimusimusim".getBytes(), 0, 16, "parkjy1917".getBytes(), 0, 10, "SHA1".getBytes(), 0, 4, qx, 0, 32, qy, 0, 32);
		a = new String(out);
		System.out.println("------CertCSR start------");
		System.out.println(a);
		System.out.println("------CertCSR end------");
	}
}
