using System;
using System.Diagnostics;

namespace SharedSafe.Encoding.Cryptography
{
	struct Signature
	{
		public readonly SignatureFormat Format;
		public readonly byte[] Data;

		public Signature(SignatureFormat format, byte[] data)
		{
			Debug.Assert(format.serialize().IndexOf(':') == -1);
			Format = format;
			Data = data;
		}

		public string serialize()
		{
			return Format.serialize() + ":"  + Convert.ToBase64String(Data);
		}

		public static Signature deserialize(string serialized)
		{
			var parts = serialized.split2(':');
			return new Signature(
				SignatureFormat.deserialize(parts.First), 
				Convert.FromBase64String(parts.Second));
		}

	}
}
