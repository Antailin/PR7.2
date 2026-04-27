using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PR7._2;
namespace GostCipherTests
{
        /// <summary>
        /// Покрывают: обратимость, детерминизм, паддинг, граничные значения,
        /// обработку исключений (негативные сценарии).
        /// </summary>
        [TestClass]
        public class GostCipherTests
        {


            /// <summary>Тестовый ключ 256 бит (32 байта), значения 0x01..0x20.</summary>
            private static readonly byte[] ValidKey = new byte[32]
            {
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
            0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
            0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
            };

            /// <summary>Второй тестовый ключ (все байты = 0xFF).</summary>
            private static readonly byte[] AllFFKey = new byte[32];

            [ClassInitialize]
            public static void ClassInit(TestContext _)
            {
                Array.Fill(AllFFKey, (byte)0xFF);
            }



            /// <summary>TC-01: Шифрование и расшифровка ровно одного блока (8 байт).</summary>
            [TestMethod]
            public void TC01_EncryptDecrypt_SingleBlock_ReturnsOriginal()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] original = { 1, 2, 3, 4, 5, 6, 7, 8 };
                byte[] decrypted = cipher.Decrypt(cipher.Encrypt(original));
                CollectionAssert.AreEqual(original, decrypted);
            }

            /// <summary>TC-02: Шифрование и расшифровка нескольких блоков (24 байта).</summary>
            [TestMethod]
            public void TC02_EncryptDecrypt_MultipleBlocks_ReturnsOriginal()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] original = new byte[24];
                for (int i = 0; i < original.Length; i++) original[i] = (byte)i;
                byte[] decrypted = cipher.Decrypt(cipher.Encrypt(original));
                CollectionAssert.AreEqual(original, decrypted);
            }

            /// <summary>TC-03: Зашифрованный текст отличается от открытого.</summary>
            [TestMethod]
            public void TC03_Encrypted_DiffersFromOriginal()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] original = Encoding.UTF8.GetBytes("Hello GOST!");
                byte[] encrypted = cipher.Encrypt(original);
                CollectionAssert.AreNotEqual(original, encrypted);
            }

            /// <summary>TC-04: Обратимость для русского текста через EncryptText/DecryptText.</summary>
            [TestMethod]
            public void TC04_EncryptDecryptText_Russian_ReturnsOriginal()
            {
                var cipher = new GostCipher(ValidKey);
                const string original = "Привет мир ГОСТ!";
                string decrypted = cipher.DecryptText(cipher.EncryptText(original));
                Assert.AreEqual(original, decrypted);
            }

            /// <summary>TC-05: Обратимость для длинного текста (500 символов).</summary>
            [TestMethod]
            public void TC05_EncryptDecryptText_LongText_ReturnsOriginal()
            {
                var cipher = new GostCipher(ValidKey);
                string original = new string('А', 500);
                Assert.AreEqual(original, cipher.DecryptText(cipher.EncryptText(original)));
            }



            /// <summary>TC-06: Разные ключи дают разные шифртексты.</summary>
            [TestMethod]
            public void TC06_DifferentKeys_ProduceDifferentCiphertext()
            {
                var c1 = new GostCipher(ValidKey);
                var c2 = new GostCipher(AllFFKey);
                byte[] data = Encoding.UTF8.GetBytes("TestData12345678");
                CollectionAssert.AreNotEqual(c1.Encrypt(data), c2.Encrypt(data));
            }

            /// <summary>TC-07: Детерминизм — одни данные + ключ дают одинаковый шифртекст.</summary>
            [TestMethod]
            public void TC07_SameInput_SameKey_DeterministicOutput()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] data = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
                CollectionAssert.AreEqual(cipher.Encrypt(data), cipher.Encrypt(data));
            }

            /// <summary>TC-08: Нулевой ключ (все байты = 0) работает без исключений.</summary>
            [TestMethod]
            public void TC08_ZeroKey_WorksCorrectly()
            {
                var cipher = new GostCipher(new byte[32]);
                const string original = "ZeroKeyTest";
                Assert.AreEqual(original, cipher.DecryptText(cipher.EncryptText(original)));
            }



            /// <summary>TC-09: Данные длиной, не кратной 8, корректно обрабатываются (паддинг).</summary>
            [TestMethod]
            public void TC09_NonBlockAlignedData_HandledWithPadding()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] original = { 1, 2, 3 };
                CollectionAssert.AreEqual(original, cipher.Decrypt(cipher.Encrypt(original)));
            }

            /// <summary>TC-10: Длина зашифрованных данных всегда кратна 8.</summary>
            [TestMethod]
            public void TC10_Encrypted_LengthIsMultipleOf8()
            {
                var cipher = new GostCipher(ValidKey);
                for (int len = 1; len <= 20; len++)
                {
                    byte[] data = new byte[len];
                    int encLen = cipher.Encrypt(data).Length;
                    Assert.AreEqual(0, encLen % 8,
                        $"Длина {encLen} не кратна 8 для входа длиной {len}");
                }
            }

            /// <summary>TC-11: Обратимость для одного байта.</summary>
            [TestMethod]
            public void TC11_SingleByte_EncryptDecrypt()
            {
                var cipher = new GostCipher(ValidKey);
                byte[] original = { 42 };
                CollectionAssert.AreEqual(original, cipher.Decrypt(cipher.Encrypt(original)));
            }



            /// <summary>TC-12: Конструктор бросает ArgumentNullException при null-ключе.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public void TC12_Constructor_NullKey_ThrowsArgumentNullException()
            {
                _ = new GostCipher(null!);
            }

            /// <summary>TC-13: Конструктор бросает ArgumentException при ключе неверной длины (16 байт).</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC13_Constructor_WrongKeyLength_ThrowsArgumentException()
            {
                _ = new GostCipher(new byte[16]);
            }

            /// <summary>TC-14: Encrypt бросает ArgumentNullException при null-данных.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public void TC14_Encrypt_NullData_ThrowsArgumentNullException()
            {
                new GostCipher(ValidKey).Encrypt(null!);
            }

            /// <summary>TC-15: Encrypt бросает ArgumentException при пустом массиве.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC15_Encrypt_EmptyData_ThrowsArgumentException()
            {
                new GostCipher(ValidKey).Encrypt(Array.Empty<byte>());
            }

            /// <summary>TC-16: Decrypt бросает ArgumentException при данных, не кратных 8.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC16_Decrypt_NonAlignedData_ThrowsArgumentException()
            {
                new GostCipher(ValidKey).Decrypt(new byte[] { 1, 2, 3 });
            }

            /// <summary>TC-17: EncryptText бросает ArgumentException при пустой строке.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC17_EncryptText_EmptyString_ThrowsArgumentException()
            {
                new GostCipher(ValidKey).EncryptText("");
            }

            /// <summary>TC-18: DecryptText бросает ArgumentException при невалидном Base64.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC18_DecryptText_InvalidBase64_ThrowsArgumentException()
            {
                new GostCipher(ValidKey).DecryptText("это-не-base64!!!");
            }



            /// <summary>TC-19: Ключ из 31 байта (на 1 меньше нормы) вызывает ArgumentException.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC19_Constructor_31ByteKey_ThrowsArgumentException()
            {
                _ = new GostCipher(new byte[31]);
            }

            /// <summary>TC-20: Ключ из 33 байт (на 1 больше нормы) вызывает ArgumentException.</summary>
            [TestMethod]
            [ExpectedException(typeof(ArgumentException))]
            public void TC20_Constructor_33ByteKey_ThrowsArgumentException()
            {
                _ = new GostCipher(new byte[33]);
            }
        }
    }