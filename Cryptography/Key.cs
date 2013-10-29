using System;
using System.Diagnostics;
using Toolbox;

namespace SharedSafe.Encoding.Cryptography
{
	public struct Key
	{
		public Key(string format, uint keySize, byte[] data)
			: this(new KeyFormat(format, keySize), data)
		{
		}

		public Key(KeyFormat format, byte[] data)
		{
			Debug.Assert(format.serialize().IndexOf(':') == -1);
			Format = format;
			Data = data;
		}

		public readonly KeyFormat Format;
		public readonly byte[] Data;

		public string serialize()
		{
			return Format.serialize() + ":" + Convert.ToBase64String(Data);
		}

		public static Key deserialize(string serialized)
		{
			try
			{
				var two = serialized.split2(':');
				var format = two.First;
				var content = two.Second;
				return new Key(KeyFormat.deserialize(format), Convert.FromBase64String(content));

			}
			// todo: use structured exception handling.
			catch (Exception e)
			{
				throw new InternalError(e, "Failed to deserialize Key");
			}
		}

		public bool isSame(Key other)
		{
			return Format == other.Format && isSame(Data, other.Data);
		}

		static bool isSame(byte[] l, byte[] r)
		{
			if (l.Length != r.Length)
				return false;

			for (int i =0; i != l.Length; ++i)
				if (l[i] != r[i])
					return false;

			return true;
		}
	}
}
