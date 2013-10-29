using System;
using System.Security.Cryptography;
using Toolbox;
using Toolbox.IO;

namespace SharedSafe.Encoding.Cryptography
{
	public sealed class DecryptionService : IDisposable
	{
		readonly AesCryptoServiceProvider _provider;
		readonly ReusableMemoryStream _outputStream;

		public DecryptionService(Key key)
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

		public BufferReference decrypt(BufferReference content)
		{
			Pair<IV, int> ivInfo = extractIVFromContent(content);

			var iv = ivInfo.First;
			var ivPrefixLength = ivInfo.Second;

			_provider.IV = iv.Data;

			using (var encryptor = _provider.CreateDecryptor())
			{
				_outputStream.SetLength(0);
				using (var stream = new CryptoStream(_outputStream, encryptor, CryptoStreamMode.Write))
				{
					stream.Write(content.Buffer, content.Offset + ivPrefixLength, content.Length - ivPrefixLength);
					stream.FlushFinalBlock();
					return _outputStream.asBufferReference();
				}
			}
		}

		public static Pair<IV, int> extractIVFromContent(BufferReference content)
		{
			if (content.Length < 1 || content.Length < content[0] + 1)
				throw new InternalError("Failed to extract IV from encrypted block.");

			var ivBytes = content[0];
			var iv = new byte[content[0]];
			content.copy(1, iv, 0, ivBytes);
			return Pair.make(new IV(iv), 1 + ivBytes);
		}
	}
}
