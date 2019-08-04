using Microsoft.VisualStudio.TestTools.UnitTesting;
using sr25519_dotnet.lib;

namespace sr25519_dotnet.test
{
    [TestClass]
    public class SR25519_Tests
    {
        [TestMethod]
        public void ShouldSignAndVerify()
        {
            // Arrange.
            var message1 = "positive test message";
            var message2 = "negative test message";

            // Act.
            var keys = SR25519.GenerateKeypairFromSeed(
                "f6dbe0604959f8d4f53ef58754f44391c69cfc87f1b97872abef63161e18c885");
            var sig = SR25519.Sign(message1, keys);
            var verification1 = SR25519.Verify(message1, sig, keys.Public);
            var verification2 = SR25519.Verify(message2, sig, keys.Public);

            // Assert.
            Assert.IsTrue(verification1);
            Assert.IsFalse(verification2);
        }
    }
}
