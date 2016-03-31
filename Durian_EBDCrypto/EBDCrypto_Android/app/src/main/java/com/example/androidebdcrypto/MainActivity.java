package com.example.androidebdcrypto;

import givtech.ebdcrypto.ECDSA;
import givtech.ebdcrypto.GenerateCertCSR;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		String a = "";

		byte[] qx = new byte[32];
		byte[] qy = new byte[32];
		byte[] d = new byte[32];

		byte[] out = new byte[50];

		qx = "pubKey_xpubKpubKey_xpubKpubKey_x".getBytes();
		qy = "pubKey_ypubKpubKey_ypubKpubKey_y".getBytes();

		GenerateCertCSR genCSR = new GenerateCertCSR();
		ECDSA ecdsa = new ECDSA();
		out = genCSR.generateCertCSR("JoonYoung".getBytes(), 0, 9, "900104".getBytes(), 0, 6, "01097662526".getBytes(), 0, 11
				, "usimusimusimusim".getBytes(), 0, 16, "parkjy1917".getBytes(), 0, 10, "SHA1".getBytes(), 0, 4, qx, 0, 32, qy, 0, 32);
		a = new String(out);
		System.out.println(a);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
