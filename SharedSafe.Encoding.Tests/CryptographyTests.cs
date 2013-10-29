#if DEBUG

using System;
using NUnit.Framework;
using SharedSafe.Encoding.Cryptography;
using Toolbox.IO;

namespace SharedSafe.Encoding.Tests
{
	[TestFixture]
	public class CryptographyTests
	{
		[Test]
		public void createSigningKey()
		{
			Signing.createSerializedKeyPair();
		}

		[Test]
		public void createEncryptionKey()
		{
			Encryption.createSerializedKey();
		}

		[Test]
		public void testNUnitArrayEquality()
		{
			var b1 = new byte[1];
			var b2 = new byte[1];
			b1[0] = 0x1;
			b2[0] = 0x1;

			Assert.That(b1, Is.EqualTo(b2));
		}

		/**
			Result of individual chunks and followup-chunks with the reuse of EncryptionService shall be the same.

			This tests if we can reuse the EncryptionService for different chunks.
		**/

		[Test]
		public void testEncryptionContinuity()
		{
			var serKey = Encryption.createSerializedKey();
			var key = Key.deserialize(serKey);


			var random = new Random(0);

			var buf1 = new byte[438324];
			var buf2 = new byte[437044];

			random.NextBytes(buf1);
			random.NextBytes(buf2);

			var iv = Encryption.createRandomIV(key);

			byte[] r1;
			byte[] r2;

			using (var service = new EncryptionService(key))
			{
				r1 = service.encrypt(iv, buf1.asBufferReference()).toArray();
			}

			using (var service = new EncryptionService(key))
			{
				r2 = service.encrypt(iv, buf2.asBufferReference()).toArray();
			}

			using (var service = new EncryptionService(key))
			{
				var r3 = service.encrypt(iv, buf1.asBufferReference()).toArray();
				Assert.That(r1, Is.EqualTo(r3));

				var r4 = service.encrypt(iv, buf2.asBufferReference()).toArray();
				Assert.That(r2, Is.EqualTo(r4));
			}

			using (var service = new DecryptionService(key))
			{
				var r1d = service.decrypt(r1.asBufferReference()).toArray();
				Assert.That(r1d, Is.EqualTo(buf1));
			}

			using (var service = new DecryptionService(key))
			{
				var r2d = service.decrypt(r2.asBufferReference()).toArray();
				Assert.That(r2d, Is.EqualTo(buf2));
			}

			using (var service = new DecryptionService(key))
			{
				var r1d = service.decrypt(r1.asBufferReference()).toArray();
				Assert.That(r1d, Is.EqualTo(buf1));

				var r2d = service.decrypt(r2.asBufferReference()).toArray();
				Assert.That(r2d, Is.EqualTo(buf2));
			}
		}
	}
}

#endif