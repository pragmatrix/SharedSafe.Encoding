using System;
using Toolbox;

namespace SharedSafe.Encoding.Cryptography
{
	static class SerializationHelper
	{
		public static Two<string> split2(this string str, char separator)
		{
			var i = str.IndexOf(separator);
			if (i == -1)
				throw new Exception("missing separator '{0}'".format(separator));

			return Two.make(str.Substring(0, i), str.Substring(i + 1, str.Length - (i + 1)));
		}
	}
}
