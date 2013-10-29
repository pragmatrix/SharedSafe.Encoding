using System;
using System.IO;
using System.Security.Cryptography;
using Toolbox;
using Toolbox.IO;

namespace SharedSafe.Encoding.Cryptography
{
	public sealed class EncryptionService : IDisposable
	{
		readonly AesCryptoServiceProvider _provider;
		readonly ReusableMemoryStream _outputStream;

		public EncryptionService(Key key)
		{
			_provider = new AesCryptoServiceProvider
			{
				KeySize = key.Format.BitSize.signed(), 
				Key = key.Data
			};

			_outputStream = new ReusableMemoryStream();
		}

		public void Dispose()
		{
			_outputStream.Dispose();
			((IDisposable)_provider).Dispose();
		}

		public IV createRandomIV()
		{
			_provider.GenerateIV();
			return new IV(_provider.IV);
		}

		public BufferReference encrypt(IV iv, BufferReference content)
		{
			_provider.IV = iv.Data;

			// don't see a way how we can reuse MemoryStream / CryptoStream here, need
			// to implement based on TransFormBlock, but even then we need to create the 
			// Encryptor for each instance.

			_outputStream.SetLength(0);
			writeIV(_provider.IV, _outputStream);

			using (var encryptor = _provider.CreateEncryptor())
			{
				// note: cryptostream closes our output stream, which is fine for us!)
				using (var stream = new CryptoStream(_outputStream, encryptor, CryptoStreamMode.Write))
				{
					stream.Write(content.Buffer, content.Offset, content.Length);
					stream.FlushFinalBlock();
					return _outputStream.asBufferReference();
				}
			}
		}

		static void writeIV(byte[] iv, Stream output)
		{
			output.WriteByte((byte)iv.Length);
			output.Write(iv, 0, iv.Length);
		}
	}
}
