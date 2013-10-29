namespace SharedSafe.Encoding.Cryptography
{
	public struct IV
	{
		public readonly byte[] Data;

		public IV(byte[] data)
		{
			Data = data;
		}
	}
}
