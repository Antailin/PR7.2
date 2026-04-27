using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;


namespace PR7._2
{
    /// <summary>
    /// Главное окно WPF-приложения шифрования/дешифрования ГОСТ 28147-89.
    /// </summary>
    public partial class MainWindow : Window
    {
        /// <summary>Инициализирует главное окно.</summary>
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>Обрабатывает нажатие кнопки «Зашифровать».</summary>
        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInput(out string text, out byte[] key)) return;
            try
            {
                var cipher = new GostCipher(key);
                txtOutput.Text = cipher.EncryptText(text);
                SetStatus("✔ Шифрование выполнено успешно.", Colors.Green);
            }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        /// <summary>Обрабатывает нажатие кнопки «Дешифровать».</summary>
        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInput(out string text, out byte[] key)) return;
            try
            {
                var cipher = new GostCipher(key);
                txtOutput.Text = cipher.DecryptText(text);
                SetStatus("✔ Дешифрование выполнено успешно.", Colors.Green);
            }
            catch (ArgumentException)
            {
                ShowError("Неверный формат Base64 или ключ не совпадает.");
            }
            catch (Exception ex) { ShowError(ex.Message); }
        }

        /// <summary>Копирует результат в буфер обмена.</summary>
        private void btnCopy_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtOutput.Text))
            {
                ShowError("Нет результата для копирования.");
                return;
            }
            Clipboard.SetText(txtOutput.Text);
            SetStatus("✔ Скопировано в буфер обмена.", Colors.SteelBlue);
        }

        /// <summary>Очищает все поля.</summary>
        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            txtInput.Clear();
            txtKey.Clear();
            txtOutput.Clear();
            lblStatus.Text = string.Empty;
        }

        /// <summary>
        /// Валидирует поля ввода и формирует 32-байтный ключ
        /// методом циклического дополнения.
        /// </summary>
        private bool ValidateInput(out string text, out byte[] key)
        {
            text = txtInput.Text;
            key = null;

            if (string.IsNullOrWhiteSpace(text))
            {
                ShowError("Поле «Текст» не может быть пустым.");
                return false;
            }

            string keyStr = txtKey.Password;
            if (string.IsNullOrWhiteSpace(keyStr))
            {
                ShowError("Поле «Ключ» не может быть пустым.");
                return false;
            }

            byte[] rawKey = System.Text.Encoding.UTF8.GetBytes(keyStr);
            key = new byte[32];
            for (int i = 0; i < 32; i++)
                key[i] = rawKey[i % rawKey.Length];

            return true;
        }

        /// <summary>Устанавливает текст и цвет строки статуса.</summary>
        private void SetStatus(string message, Color color)
        {
            lblStatus.Text = message;
            lblStatus.Foreground = new SolidColorBrush(color);
        }

        /// <summary>Показывает ошибку в статусе и MessageBox.</summary>
        private void ShowError(string message)
        {
            SetStatus("✖ Ошибка: " + message, Colors.Red);
            MessageBox.Show(message, "Ошибка",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}