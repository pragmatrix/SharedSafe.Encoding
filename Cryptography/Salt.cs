using System;
using System.Security.Cryptography;

namespace SharedSafe.Encoding.Cryptography
{
	public struct Salt
	{
		public readonly byte[] Data;

		public Salt(byte[] data)
		{
			Data = data;
		}

		public static Salt createRandom(uint bytes)
		{
			var provider = new RNGCryptoServiceProvider();
			var buf = new byte[bytes];
			provider.GetBytes(buf);
			return new Salt(buf);
		}

		public string serialize()
		{
			return Convert.ToBase64String(Data);
		}

		public static Salt deserialize(string str)
		{
			return new Salt(Convert.FromBase64String(str));
		}
	}
}
