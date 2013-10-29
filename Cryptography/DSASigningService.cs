using System.Diagnostics;
using System.Security.Cryptography;
using Toolbox;

namespace SharedSafe.Encoding.Cryptography
{
	sealed class DSASigningService: ISigningService
	{
		public const string AlgorithmName = "DSA";

		readonly DSACryptoServiceProvider _provider;

		public DSASigningService(Key key)
		{
			Debug.Assert(key.Format.Algorithm == AlgorithmName);
			_provider = new DSACryptoServiceProvider(key.Format.BitSize.signed());
			_provider.FromXmlString(System.Text.Encoding.UTF8.GetString(key.Data));
		}

		#region IDisposable Members

		public void Dispose()
		{
			// this sometimes throws a "the requested resource is in use exception" on x64 systems.

			_provider.Clear();
		}

		#endregion

		public byte[] sign(byte[] data)
		{
			return _provider.SignData(data);
		}

		public bool verify(byte[] data, Signature signature)
		{
			return _provider.VerifyData(data, signature.Data);
		}

		public KeyFormat KeyFormat
		{
			get
			{
				return new KeyFormat(AlgorithmName, _provider.KeySize.unsigned());
			}
		}

		public Key exportKey(bool includePrivate)
		{
			return new Key(KeyFormat, System.Text.Encoding.UTF8.GetBytes(_provider.ToXmlString(includePrivate)));
		}
	}
}
