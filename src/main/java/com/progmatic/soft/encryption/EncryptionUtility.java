package com.progmatic.soft.encryption;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtility {
	private static final String UTF_8 = "UTF-8";
	private static final String AES = "AES";
	private static final String ALGORITHM = "AES/CBC/PKCS5PADDING";
	private String key;
	private String initVector;

	public EncryptionUtility(String key, String initVector) {
		this.key = key;
		this.initVector = initVector;
	}

	public String encrypt(final String value)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final IvParameterSpec iv = new IvParameterSpec(this.initVector.getBytes(UTF_8));
		final SecretKeySpec skeySpec = new SecretKeySpec(this.key.getBytes(UTF_8), AES);

		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		byte[] encrypted = cipher.doFinal(value.getBytes());
		return Base64.getEncoder().encodeToString(encrypted);
	}

	public String decrypt(final String encrypted)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		final IvParameterSpec iv = new IvParameterSpec(this.initVector.getBytes(UTF_8));
		final SecretKeySpec skeySpec = new SecretKeySpec(this.key.getBytes(UTF_8), AES);

		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

		final byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
		return new String(original);
	}

//	public static void main(String[] args)
//			throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
//			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
//		String key = "1234567812345678";
//		String initVector = "Pankaj Singh Sac";
//		final EncryptionUtility utility = new EncryptionUtility(key, initVector);
//		System.out.println(utility.encrypt("I love you motu"));
//		System.out.println(utility.decrypt("l7UN7c4CsWEZwWeKD8wvMQ=="));
//	}
}