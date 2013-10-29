using System.Diagnostics;

namespace SharedSafe.Encoding.Cryptography
{
	struct SignatureFormat
	{
		public SignatureFormat(KeyFormat keyFormat, string hashAlgorithm)
		{
			Debug.Assert(keyFormat.serialize().IndexOf(':') == -1);
			KeyFormat = keyFormat;
			HashAlgorithm = hashAlgorithm;
		}

		public readonly KeyFormat KeyFormat;
		public readonly string HashAlgorithm;

		public string serialize()
		{
			return KeyFormat.serialize() + "~"  + HashAlgorithm;
		}

		public static SignatureFormat deserialize(string serialized)
		{
			var two = serialized.split2('~');
			var format = two.First;
			var hashAlgorithm = two.Second;

			return new SignatureFormat(KeyFormat.deserialize(format), hashAlgorithm);
		}
	}
}