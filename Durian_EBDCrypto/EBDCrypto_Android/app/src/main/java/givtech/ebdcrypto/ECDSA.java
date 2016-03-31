package givtech.ebdcrypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class ECDSA {
	
	static {
		System.loadLibrary("EBDCrypto_JNI_android");
	}
	
	public static final int SIGN = 1;
	public static final int VERIFY = 0;
	
	public static final int SHA224 = 0x21;
	public static final int SHA256 = 0x22;
	public static final int SHA384 = 0x23;
	public static final int SHA512 = 0x24;
	
	private byte[] qx_buf;
	private int qxlen;
	private byte[] qy_buf;
	private int qylen;
	private byte[] d_buf;
	private int dlen;
	
	private native int nativeECDSAgenkeypair(byte[] qx, int qx_offset, int[] qx_len,
											 byte[] qy, int qy_offset, int[] qy_len,
											 byte[] d, int d_offset, int[] d_len); 
	
	private native int nativeECDSAgeneratesignature(int hash_alg,
												    byte[] d, int d_offset, int d_len,
												    byte[] msg, int msg_offset, int msg_len,
												    byte[] r, int r_offset, int[] r_len,
												    byte[] s, int s_offset, int[] s_len);
	
	private native int nativeECDSAverifysignature(int hash_alg,
												  byte[] qx, int qx_offset, int qx_len,
												  byte[] qy, int qy_offset, int qy_len,
												  byte[] msg, int msg_offset, int msg_len,
												  byte[] r, int r_offset, int r_len,
												  byte[] s, int s_offset, int s_len);
	
	public void clear()
	{
		qx_buf = new byte[32];
		qy_buf = new byte[32];
		d_buf = new byte[32];
		qxlen = 0;
		qylen = 0;
		dlen = 0;
	}
	
	public ECDSA()
	{
		clear();
	}
	
	public int gen_keypair()
	{
		clear();
		int [] gen_qx_len = new int[1];
		int [] gen_qy_len = new int[1];
		int [] gen_d_len = new int[1];
		
		if(nativeECDSAgenkeypair(qx_buf, 0, gen_qx_len, qy_buf, 0, gen_qy_len, d_buf, 0, gen_d_len) == 1)
		{
			qxlen = gen_qx_len[0];
			qylen = gen_qy_len[0];
			dlen = gen_d_len[0];
			
			return 1;
		}		
		
		return -1; 		
	}
	
	public int get_public_qx(byte[] qx, int qx_offset)
	{
		if( (qx == null) || (qx_offset < 0) || ((qx_offset + 32) > qx.length) )
			return -1;
		
		if(qxlen != 0)
		{
			System.arraycopy(qx_buf, 0, qx, qx_offset, qxlen);
			return qxlen;
		}
		
		return -1;
	}
	
	public int get_public_qy(byte[] qy, int qy_offset)
	{
		if( (qy == null) || (qy_offset < 0) || ((qy_offset + 32) > qy.length) )
			return -1;
		
		if(qylen != 0)
		{
			System.arraycopy(qy_buf, 0, qy, qy_offset, qylen);
			return qylen;
		}
		
		return -1;
	}
	
	public int get_private_d(byte[] d, int d_offset)
	{
		if( (d == null) || (d_offset < 0) || ((d_offset + 32) > d.length) )
			return -1;
		
		if(dlen != 0)
		{
			System.arraycopy(d_buf, 0, d, d_offset, dlen);
			return dlen;
		}
		
		return -1;
	}
	
	public int generate_signature(int hash_alg, byte[] d, int d_offset, int d_len, byte[] msg, int msg_offset, int msg_len, byte[] signature, int signature_offset)
	{
		if( ((hash_alg != SHA224) && (hash_alg != SHA256) && (hash_alg != SHA384) && (hash_alg != SHA512)) ||
			(d == null) || (d_offset < 0) || ((d_offset + d_len) > d.length) ||
			(msg == null) || (msg_offset < 0) || ((msg_offset + msg_len) > msg.length) ||
			(signature == null) || (signature_offset < 0) || ((signature_offset + 64) > signature.length) )
			return -1;
		
		byte[] rbuf = new byte[32];
		int[] rlen = new int[1];
		byte[] sbuf = new byte[32];
		int[] slen = new int[1];		
		
		if(nativeECDSAgeneratesignature(hash_alg, d, d_offset, d_len, msg, msg_offset, msg_len, rbuf, 0, rlen, sbuf, 0, slen) == 1)
		{
			System.arraycopy(rbuf, 0, signature, signature_offset, rlen[0]);
			System.arraycopy(sbuf, 0, signature, signature_offset + rlen[0], slen[0]);
			
			return rlen[0] + slen[0];
		}

		return -1;
	}
	
	public int verify_signature(int hash_alg, byte[] qx, int qx_offset, int qx_len, byte[] qy, int qy_offset, int qy_len, byte[] msg, int msg_offset, int msg_len, byte[] signature, int signature_offset, int signature_len)
	{
		if( ((hash_alg != SHA224) && (hash_alg != SHA256) && (hash_alg != SHA384) && (hash_alg != SHA512)) ||
			(qx == null) || (qx_offset < 0) || ((qx_offset + qx_len) > qx.length) ||
			(qy == null) || (qy_offset < 0) || ((qy_offset + qy_len) > qy.length) ||
			(msg == null) || (msg_offset < 0) || ((msg_offset + msg_len) > msg.length) ||
			(signature == null) || (signature_offset < 0) || ((signature_offset + signature_len) > signature.length) )
			return -1;
		
		if(signature_len != 64)
			return -1;
		
		return nativeECDSAverifysignature(hash_alg, qx, qx_offset, qx_len, qy, qy_offset, qy_len, msg, msg_offset, msg_len, signature, signature_offset, 32, signature, signature_offset + 32, 32);
	}
}