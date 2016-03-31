package givtech.ebdcrypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class SHA2 {
	
	static {
		System.loadLibrary("EBDCrypto_JNI_android");
	}

	public static final int SHA224 = 0x21;
	public static final int SHA256 = 0x22;
	public static final int SHA384 = 0x23;
	public static final int SHA512 = 0x24;
	
	public static final int SHA224_DIGEST_LENGTH = 28;
	public static final int SHA256_DIGEST_LENGTH = 32;
	public static final int SHA384_DIGEST_LENGTH = 48;
	public static final int SHA512_DIGEST_LENGTH = 64;
	
	private int mode;
	
	private native int nativesha224(byte[] input, int input_offset, int input_length, byte[] Digest, int output_offset);
	private native int nativesha256(byte[] input, int input_offset, int input_length, byte[] Digest, int output_offset);
	private native int nativesha384(byte[] input, int input_offset, int input_length, byte[] Digest, int output_offset);
	private native int nativesha512(byte[] input, int input_offset, int input_length, byte[] Digest, int output_offset);
	
	private SHA2()
	{

	}
	
	public SHA2(int alg)
	{
		mode = alg;
	}
	
	public int digest(byte[] input, int input_offset, int inlen, byte[] output, int output_offset)
	{
		if( (input == null) || (inlen < 0) || (input_offset < 0) || (output_offset < 0) || (output == null) || ((input_offset + inlen) > input.length) || (output_offset + getDigestSize() > output.length) )
			return -1;	
		
		switch(mode)
		{
		 case SHA224:
			 if(nativesha224(input, input_offset, inlen, output, output_offset) == 1)
				 return 1;
			 else
				 return -1;
		 case SHA256:
			 if(nativesha256(input, input_offset, inlen, output, output_offset) == 1)
				 return 1;
			 else
				 return -1;
		 case SHA384:
			 if(nativesha384(input, input_offset, inlen, output, output_offset) == 1)
				 return 1;
			 else
				 return -1;
		 case SHA512:
			 if(nativesha512(input, input_offset, inlen, output, output_offset) == 1)
				 return 1;
			 else
				 return -1;
		 default:
			 return -1;
		}
	}
	
	public int getDigestSize() {
		switch(mode)
		{
		 case SHA224:
			 return SHA224_DIGEST_LENGTH;
		 case SHA256:
			 return SHA256_DIGEST_LENGTH;
		 case SHA384:
			 return SHA384_DIGEST_LENGTH;
		 case SHA512:
			 return SHA512_DIGEST_LENGTH;
		 default:
			 return -1;
		}
	}
}