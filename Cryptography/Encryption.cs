using System.Security.Cryptography;
using Toolbox;
using Toolbox.IO;

namespace SharedSafe.Encoding.Cryptography
{
	public static class Encryption
	{
		const string AESAlgorithm = "AES";

		// Create a serialized object of type Key.
		// The key data is created with .NET: AesCryptoServiceProvider.GenerateKey.
		public static string createSerializedKey()
		{
			using (var aes = new AesCryptoServiceProvider())
			{

				aes.GenerateKey();
				/* osu change: uncomment
				Log.I("AESKeySize: {0}".format(aes.KeySize));
				*/
					
				return makeKey(aes).serialize();
			}
		}

		// Create an object of type IV from a serialized object of type Key.
		public static IV createRandomIV(string serialized)
		{
			var key = Key.deserialize(serialized);

			return createRandomIV(key);
		}

		// Create an object of type IV from a given object of type Key.
		// Usage of AesCryptoServiceProvider:
		// - create it 
		// - set its key size according the the size of the input Key
		// - use GenerateIV()
		public static IV createRandomIV(Key key)
		{
			using (var aes = new AesCryptoServiceProvider())
			{
				aes.KeySize = key.Format.BitSize.signed();
				// this should not be required?
				// aes.Key = key.Data;

				aes.GenerateIV();
				return new IV(aes.IV);
			}
		}

		// Steps:
		// - create a Salt the size of the default key size of AesCryptoServiceProvider
		// - create an AesCryptoServiceProvider whose key is based on this Salt and the password by using Rfc2898DeriveBytes
		// - the returned SaltKey consists of this Salt and the Key created from the created AesCryptoServiceProvider
		public static SaltyKey createSaltyKeyByPassword(string password)
		{
			using (var aes = new AesCryptoServiceProvider())
			{
				var keyBytes = aes.KeySize/8;

				var salt = Salt.createRandom(keyBytes.unsigned());

				var derive = new Rfc2898DeriveBytes(password, salt.Data);
				aes.Key = derive.GetBytes(keyBytes);

				return new SaltyKey(makeKey(aes), salt);
			}
		}

		// Steps:
		// - create an AesCryptoServiceProvider whose key is based on the passed Salt and the password by using Rfc2898DeriveBytes
		// - the returned Key consists then of this created AesCryptoServiceProvider
		public static Key deriveKey(Salt salt, string password)
		{
			using (var aes = new AesCryptoServiceProvider())
			{
				int keyBytes = aes.KeySize/8;

				var derive = new Rfc2898DeriveBytes(password, salt.Data);
				var key = derive.GetBytes(keyBytes);
	
				return new Key(new KeyFormat(AESAlgorithm, aes.KeySize.unsigned()), key);
			}
		}

		// Create a Key from the given AesCryptoServiceProvider (size and data)
		static Key makeKey(AesCryptoServiceProvider provider)
		{
			return new Key(new KeyFormat(AESAlgorithm, provider.KeySize.unsigned()), provider.Key);
		}

		// Return decrypted data by using DecryptionService and the given serialized Key
		public static BufferReference decrypt(string serializedKey, BufferReference encrypted)
		{
			return decrypt(Key.deserialize(serializedKey), encrypted);
		}

		/**
			Encryption writes the IV in front of the output.
		**/

		public static BufferReference encrypt(string serializedKey, BufferReference content)
		{
			return encrypt(Key.deserialize(serializedKey), null, content);
		}

		public static BufferReference encrypt(string serializedKey, IV? iv_, BufferReference content)
		{
			return encrypt(Key.deserialize(serializedKey), iv_, content);
		}

		public static BufferReference encrypt(Key key, BufferReference content)
		{
			return encrypt(key, null, content);
		}

		public static BufferReference encrypt(Key key, IV? iv_, BufferReference content)
		{
			using (var service = new EncryptionService(key))
			{
				var iv = iv_ ?? service.createRandomIV();
				return service.encrypt(iv, content);
			}
		}

		// Return decrypted data by using DecryptionService and the given Key
		public static BufferReference decrypt(Key key, byte[] content)
		{
			return decrypt(key, content.asBufferReference());
		}

		// Return decrypted data by using DecryptionService and the given Key
		public static BufferReference decrypt(Key key, BufferReference content)
		{
			using (var service = new DecryptionService(key))
			{
				return service.decrypt(content);
			}
		}
	}
}
