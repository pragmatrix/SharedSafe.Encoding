using System.Security.Cryptography;
using Toolbox;

namespace SharedSafe.Encoding.Cryptography
{
	public static class Signing
	{
		const string AlgorithmDSA = "DSA";
		const string AlgorithmSHA1 = "SHA1";
	
		const uint DefaultKeySize = 1024;
		const string DefaultAlgorithm = AlgorithmDSA;
		internal const string DefaultHashAlgorithm = AlgorithmSHA1;

		#region Serialized Key

		public static string createSerializedKeyPair()
		{
			return createKeyPair().serialize();
		}

		public static string removePrivateKey(string keyPair)
		{
			var kp = Key.deserialize(keyPair);

			var removed = removePrivateKey(kp);
			return removed.serialize();
		}

		public static bool hasPrivateKey(string keyPair)
		{
			return hasPrivateKey(Key.deserialize(keyPair));
		}

		public static string sign(string keyPair, byte[] content)
		{
			return sign(Key.deserialize(keyPair), content).serialize();
		}

		public static bool verify(string keyPair, string signature, byte[] content)
		{
			return verify(Key.deserialize(keyPair), Signature.deserialize(signature), content);
		}

		#endregion

		#region Key

		static Key createKeyPair()
		{
			// note: Clear() just calls Dispose() :)
			using (var dsa = new DSACryptoServiceProvider(DefaultKeySize.signed()))
			{
				return new Key(DefaultAlgorithm, DefaultKeySize, System.Text.Encoding.UTF8.GetBytes(dsa.ToXmlString(true)));
			}
		}

		static Key removePrivateKey(Key key)
		{
			using (var dsa = useSigningService(key))
			{
				return dsa.exportKey(false);
			}
		}

		static bool hasPrivateKey(Key key)
		{
			var without = removePrivateKey(key);
			return !without.isSame(key);
		}

		#endregion

		#region Signing

		static Signature sign(Key key, byte[] data)
		{
			using (var dsa = useSigningService(key))
			{
				var signed = dsa.sign(data);
				return new Signature(new SignatureFormat(key.Format, DefaultHashAlgorithm), signed);
			}
		}

		static bool verify(Key key, Signature signature, byte[] data)
		{
			using (var dsa = useSigningService(key))
			{
				return dsa.verify(data, signature);
			}
		}

		#endregion

		#region Helper

		static ISigningService useSigningService(Key key)
		{
			switch (key.Format.Algorithm)
			{
				case DSASigningService.AlgorithmName:
					return new DSASigningService(key);
			}

			throw new InternalError("Unsupported key algorithm {0}".format(key.Format.Algorithm));
		}

		#endregion
	}
}
