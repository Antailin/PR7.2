using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PR7._2;
namespace PR7._2
{

        /// <summary>
        /// Реализует упрощённый алгоритм шифрования ГОСТ 28147-89.
        /// Работает с 64-битными блоками, использует S-блоки подстановки
        /// и выполняет 32 раунда преобразования (для учебных целей).
        /// </summary>
        public class GostCipher
        {
            /// <summary>
            /// Стандартные S-блоки (таблицы подстановки) ГОСТ 28147-89.
            /// Каждый S-блок — массив из 16 элементов (4-битная замена).
            /// </summary>
            private static readonly byte[][] SBoxes = new byte[][]
            {
            new byte[] {  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
            new byte[] { 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
            new byte[] {  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
            new byte[] {  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
            new byte[] {  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
            new byte[] {  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
            new byte[] { 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
            new byte[] {  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }
            };

            /// <summary>
            /// 256-битный ключ (32 байта), разбитый на 8 подключей по 32 бита.
            /// </summary>
            private readonly uint[] _subKeys;

            /// <summary>
            /// Инициализирует экземпляр шифра с заданным ключом.
            /// </summary>

            public GostCipher(byte[] key)
            {
                if (key == null)
                    throw new ArgumentNullException(nameof(key), "Ключ не может быть null.");
                if (key.Length != 32)
                    throw new ArgumentException(
                        "Длина ключа должна быть ровно 32 байта (256 бит).", nameof(key));

                _subKeys = new uint[8];
                for (int i = 0; i < 8; i++)
                    _subKeys[i] = BitConverter.ToUInt32(key, i * 4);
            }

            /// <summary>
            /// Шифрует массив байт. Дополняет данные до кратности 8 байтам (PKCS-подобный паддинг).
            /// </summary>

            public byte[] Encrypt(byte[] data)
            {
                if (data == null)
                    throw new ArgumentNullException(nameof(data), "Данные не могут быть null.");
                if (data.Length == 0)
                    throw new ArgumentException("Данные не могут быть пустыми.", nameof(data));

                byte[] padded = PadData(data);
                byte[] result = new byte[padded.Length];

                for (int i = 0; i < padded.Length; i += 8)
                {
                    byte[] block = new byte[8];
                    Array.Copy(padded, i, block, 0, 8);
                    byte[] encBlock = EncryptBlock(block);
                    Array.Copy(encBlock, 0, result, i, 8);
                }

                return result;
            }

            /// <summary>
            /// Расшифровывает массив байт, зашифрованный методом <see cref="Encrypt"/>.
            /// </summary>

            public byte[] Decrypt(byte[] data)
            {
                if (data == null)
                    throw new ArgumentNullException(nameof(data), "Данные не могут быть null.");
                if (data.Length == 0)
                    throw new ArgumentException("Данные не могут быть пустыми.", nameof(data));
                if (data.Length % 8 != 0)
                    throw new ArgumentException(
                        "Длина зашифрованных данных должна быть кратна 8.", nameof(data));

                byte[] result = new byte[data.Length];

                for (int i = 0; i < data.Length; i += 8)
                {
                    byte[] block = new byte[8];
                    Array.Copy(data, i, block, 0, 8);
                    byte[] decBlock = DecryptBlock(block);
                    Array.Copy(decBlock, 0, result, i, 8);
                }

                return UnpadData(result);
            }

            /// <summary>
            /// Шифрует текстовую строку (UTF-8) и возвращает результат в формате Base64.
            /// </summary>

            public string EncryptText(string text)
            {
                if (text == null)
                    throw new ArgumentNullException(nameof(text), "Текст не может быть null.");
                if (string.IsNullOrWhiteSpace(text))
                    throw new ArgumentException(
                        "Текст не может быть пустым или состоять только из пробелов.", nameof(text));

                byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
                byte[] encrypted = Encrypt(bytes);
                return Convert.ToBase64String(encrypted);
            }

            /// <summary>
            /// Расшифровывает строку Base64 и возвращает текст в кодировке UTF-8.
            /// </summary>

            public string DecryptText(string base64)
            {
                if (base64 == null)
                    throw new ArgumentNullException(nameof(base64), "Строка Base64 не может быть null.");
                if (string.IsNullOrWhiteSpace(base64))
                    throw new ArgumentException("Строка Base64 не может быть пустой.", nameof(base64));

                byte[] bytes;
                try
                {
                    bytes = Convert.FromBase64String(base64);
                }
                catch (FormatException ex)
                {
                    throw new ArgumentException("Неверный формат Base64-строки.", nameof(base64), ex);
                }

                byte[] decrypted = Decrypt(bytes);
                return System.Text.Encoding.UTF8.GetString(decrypted);
            }


            /// <summary>
            /// Шифрует один 64-битный блок (32 раунда ГОСТ).
            /// Порядок подключей: K0..K7 × 3 (24 прямых), затем K7..K0 (8 обратных).
            /// </summary>
            private byte[] EncryptBlock(byte[] block)
            {
                uint n1 = BitConverter.ToUInt32(block, 0);
                uint n2 = BitConverter.ToUInt32(block, 4);

                for (int pass = 0; pass < 3; pass++)
                    for (int i = 0; i < 8; i++)
                        Round(ref n1, ref n2, _subKeys[i]);

                for (int i = 7; i >= 0; i--)
                    Round(ref n1, ref n2, _subKeys[i]);

                byte[] result = new byte[8];
                Array.Copy(BitConverter.GetBytes(n1), 0, result, 0, 4);
                Array.Copy(BitConverter.GetBytes(n2), 0, result, 4, 4);
                return result;
            }

        /// <summary>
        /// Расшифровывает один 64-битный блок (32 раунда ГОСТ, порядок ключей обратный).
        /// Порядок подключей: K0..K7 (8 прямых), затем K7..K0 × 3 (24 обратных).
        /// </summary>
        private byte[] DecryptBlock(byte[] block)
        {
            uint n1 = BitConverter.ToUInt32(block, 4);
            uint n2 = BitConverter.ToUInt32(block, 0);

            for (int i = 0; i < 8; i++)
                Round(ref n1, ref n2, _subKeys[i]);

            for (int pass = 0; pass < 3; pass++)
                for (int i = 7; i >= 0; i--)
                    Round(ref n1, ref n2, _subKeys[i]);

            byte[] result = new byte[8];
            Array.Copy(BitConverter.GetBytes(n2), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(n1), 0, result, 4, 4);
            return result;
        }

        /// <summary>
        /// Один раунд преобразования ГОСТ:
        /// сложение mod 2^32 → S-подстановка → циклический сдвиг на 11 бит → XOR.
        /// </summary>

        private void Round(ref uint n1, ref uint n2, uint subKey)
            {
                uint temp = (n1 + subKey) & 0xFFFFFFFF;  
                temp = SubstituteBlock(temp);              
                temp = RotateLeft(temp, 11);               
                temp ^= n2;                                
                n2 = n1;
                n1 = temp;
            }

            /// <summary>
            /// Применяет 8 S-блоков к 32-битному значению (по 4 бита на каждый S-блок).
            /// </summary>

            private uint SubstituteBlock(uint value)
            {
                uint result = 0;
                for (int i = 0; i < 8; i++)
                {
                    byte nibble = (byte)((value >> (i * 4)) & 0x0F);
                    byte substituted = SBoxes[i][nibble];
                    result |= (uint)substituted << (i * 4);
                }
                return result;
            }

            /// <summary>
            /// Циклический сдвиг 32-битного числа влево на заданное количество бит.
            /// </summary>

            private static uint RotateLeft(uint value, int shift)
                => (value << shift) | (value >> (32 - shift));

            /// <summary>
            /// Дополняет массив байт до кратности 8 (PKCS-подобный паддинг).
            /// Каждый байт паддинга равен длине паддинга.
            /// </summary>
            private static byte[] PadData(byte[] data)
            {
                int padLength = 8 - (data.Length % 8);
                byte[] padded = new byte[data.Length + padLength];
                Array.Copy(data, padded, data.Length);
                for (int i = data.Length; i < padded.Length; i++)
                    padded[i] = (byte)padLength;
                return padded;
            }

            /// <summary>
            /// Убирает PKCS-подобный паддинг из расшифрованных данных.
            /// </summary>
            private static byte[] UnpadData(byte[] data)
            {
                if (data.Length == 0) return data;
                byte padLength = data[data.Length - 1];
                if (padLength < 1 || padLength > 8) return data;
                return data[..(data.Length - padLength)];
            }
        }
    }