using System;

namespace SharedSafe.Encoding.Cryptography
{
	interface ISigningService : IDisposable
	{
		byte[] sign(byte[] data);
		bool verify(byte[] data, Signature signature);
		Key exportKey(bool includePrivate);
	}
}
