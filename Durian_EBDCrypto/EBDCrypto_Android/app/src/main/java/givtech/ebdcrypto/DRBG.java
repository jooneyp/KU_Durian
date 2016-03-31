package givtech.ebdcrypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class DRBG {
	
	static {
		System.loadLibrary("EBDCrypto_JNI_android");
	}
	
	private DRBG()
	{
		
	}
	
	private native static int nativeDRBGRandomGen(byte[] output, int output_offset, int request_num_of_bits);
	
	public static int RandomGen(byte[] output, int output_offset, int request_num_of_bytes)
	{
		if( (output == null) || (output_offset < 0) || ((output_offset + request_num_of_bytes) > output.length))
			return -1;
		
		if(nativeDRBGRandomGen(output, output_offset, request_num_of_bytes*8) == 1)
			return 1;
		else
			return -1;
	}

}
