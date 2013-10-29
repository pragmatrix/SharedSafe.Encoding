namespace SharedSafe.Encoding.Cryptography
{
	public sealed class SaltyKey
	{
		public readonly Key Key;
		public readonly Salt Salt;

		public SaltyKey(Key key, Salt salt)
		{
			Key = key;
			Salt = salt;
		}
	}
}