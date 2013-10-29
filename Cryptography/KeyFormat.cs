using System.Diagnostics;
using Toolbox;

namespace SharedSafe.Encoding.Cryptography
{
	public struct KeyFormat
	{
		public KeyFormat(string algorithm, uint bitSize)
		{
			Debug.Assert(algorithm.IndexOf('.') == -1);
			
			Algorithm = algorithm;
			BitSize = bitSize;
		}
		public readonly string Algorithm;
		public readonly uint BitSize;

		public string serialize()
		{
			return Algorithm + "."  + BitSize;
		}

		public static KeyFormat deserialize(string serialized)
		{
			var two = serialized.split2('.');

			var algorithm = two.First;
			var bitSizeString = two.Second;

			uint bitSize;
			if (!uint.TryParse(bitSizeString, out bitSize))
				throw new InternalError("Failed to deserialize KeyFormat (parsing BitSize failed)");

			return new KeyFormat(algorithm, bitSize);
		}

		#region R# Equality

		public bool Equals(KeyFormat other)
		{
			return Equals(other.Algorithm, Algorithm) && other.BitSize == BitSize;
		}

		public override bool Equals(object obj)
		{
			if (ReferenceEquals(null, obj))
				return false;
			if (obj.GetType() != typeof (KeyFormat))
				return false;
			return Equals((KeyFormat) obj);
		}

		public override int GetHashCode()
		{
			unchecked
			{
				return (Algorithm.GetHashCode()*397) ^ BitSize.GetHashCode();
			}
		}

		public static bool operator ==(KeyFormat left, KeyFormat right)
		{
			return left.Equals(right);
		}

		public static bool operator !=(KeyFormat left, KeyFormat right)
		{
			return !left.Equals(right);
		}

		#endregion
	}
}