import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import io
import os

class SteganoLogic:
    """Класс для логики LSB-стеганографии без сторонних библиотек."""
    
    @staticmethod
    def encode(image_path, secret_data, key):
        """Скрывает байты в изображении."""
        img = Image.open(image_path).convert('RGB')
        pixels = img.load()
        
        # Добавляем ключ в начало сообщения для проверки при чтении
        # Формат: [длина ключа(1б)][ключ][длина данных(4б)][данные]
        key_len = len(key).to_bytes(1, 'big')
        data_len = len(secret_data).to_bytes(4, 'big')
        full_payload = key_len + key + data_len + secret_data
        
        bits = ''.join(format(byte, '08b') for byte in full_payload)
        width, height = img.size
        
        if len(bits) > width * height * 3:
            raise ValueError("Размер сообщения слишком велик для этого изображения!")
            
        bit_idx = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                channels = [r, g, b]
                
                for i in range(3):
                    if bit_idx < len(bits):
                        # Меняем последний бит канала
                        channels[i] = (channels[i] & ~1) | int(bits[bit_idx])
                        bit_idx += 1
                
                pixels[x, y] = tuple(channels)
                if bit_idx >= len(bits):
                    return img
        return img

    @staticmethod
    def decode(image_path, user_key):
        """Извлекает байты из изображения."""
        img = Image.open(image_path).convert('RGB')
        width, height = img.size
        pixels = img.load()
        
        collected_bits = []
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                for channel in [r, g, b]:
                    collected_bits.append(str(channel & 1))
        
        def bits_to_bytes(bit_list):
            bit_str = "".join(bit_list)
            return bytes(int(bit_str[i:i+8], 2) for i in range(0, len(bit_str), 8))

        # Читаем длину ключа (первый байт)
        all_data = bits_to_bytes(collected_bits[:8000]) # Берем с запасом для заголовка
        k_len = all_data[0]
        extracted_key = all_data[1 : 1 + k_len]
        
        if extracted_key != user_key:
            raise ValueError("Неверный ключ доступа!")
            
        # Читаем длину данных
        d_len_start = 1 + k_len
        d_len = int.from_bytes(all_data[d_len_start : d_len_start + 4], 'big')
        
        # Извлекаем само сообщение
        msg_start_bit = (1 + k_len + 4) * 8
        msg_end_bit = msg_start_bit + (d_len * 8)
        return bits_to_bytes(collected_bits[msg_start_bit : msg_end_bit])

class SteganoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LSB Steganography Pro")
        self.root.geometry("800x700")
        
        self.current_img_path = None
        self.result_img = None
        
        self.tabs = ttk.Notebook(root)
        self.tab_hide = ttk.Frame(self.tabs)
        self.tab_extract = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_hide, text="Скрыть")
        self.tabs.add(self.tab_extract, text="Извлечь")
        self.tabs.pack(expand=1, fill="both")
        
        self._build_hide_ui()
        self._build_extract_ui()

    def _build_hide_ui(self):
        # Выбор фото
        f_img = ttk.LabelFrame(self.tab_hide, text="1. Выберите оригинал (PNG/BMP)", padding=10)
        f_img.pack(fill="x", padx=10, pady=5)
        ttk.Button(f_img, text="Открыть файл", command=self.open_image).pack(side="left")
        self.lbl_info = ttk.Label(f_img, text="Файл не выбран")
        self.lbl_info.pack(side="left", padx=10)

        # Текст
        f_msg = ttk.LabelFrame(self.tab_hide, text="2. Сообщение", padding=10)
        f_msg.pack(fill="both", expand=True, padx=10, pady=5)
        self.txt_msg = scrolledtext.ScrolledText(f_msg, height=8)
        self.txt_msg.pack(fill="both", expand=True)

        # Ключ
        f_key = ttk.Frame(self.tab_hide, padding=10)
        f_key.pack(fill="x")
        ttk.Label(f_key, text="Ключ (пароль):").pack(side="left")
        self.ent_key = ttk.Entry(f_key, show="*")
        self.ent_key.pack(side="left", padx=5, fill="x", expand=True)

        # Кнопки
        f_btns = ttk.Frame(self.tab_hide, padding=10)
        f_btns.pack(fill="x")
        self.btn_run = ttk.Button(f_btns, text="Зашифровать и сохранить", command=self.process_hide, state="disabled")
        self.btn_run.pack(side="right")

    def _build_extract_ui(self):
        f_ex = ttk.LabelFrame(self.tab_extract, text="Выберите зашифрованное фото", padding=10)
        f_ex.pack(fill="x", padx=10, pady=5)
        ttk.Button(f_ex, text="Выбрать файл", command=self.open_image_ex).pack(side="left")
        
        f_key_ex = ttk.Frame(self.tab_extract, padding=10)
        f_key_ex.pack(fill="x")
        ttk.Label(f_key_ex, text="Введите ключ:").pack(side="left")
        self.ent_key_ex = ttk.Entry(f_key_ex, show="*")
        self.ent_key_ex.pack(side="left", padx=5, fill="x", expand=True)
        
        self.btn_ex = ttk.Button(self.tab_extract, text="Извлечь сообщение", command=self.process_extract, state="disabled")
        self.btn_ex.pack(pady=5)
        
        self.txt_ex = scrolledtext.ScrolledText(self.tab_extract, height=10, state="disabled")
        self.txt_ex.pack(fill="both", expand=True, padx=10, pady=10)

    def open_image(self):
        path = filedialog.askopenfilename(filetypes=[("Без потерь", "*.png *.bmp")])
        if path:
            self.current_img_path = path
            self.lbl_info.config(text=os.path.basename(path))
            self.btn_run.config(state="normal")

    def open_image_ex(self):
        path = filedialog.askopenfilename(filetypes=[("Без потерь", "*.png *.bmp")])
        if path:
            self.current_img_path_ex = path
            self.btn_ex.config(state="normal")

    def process_hide(self):
        try:
            msg = self.txt_msg.get("1.0", tk.END).strip().encode('utf-8')
            key = self.ent_key.get().encode('utf-8')
            if not key: raise ValueError("Ключ обязателен!")
            
            res_img = SteganoLogic.encode(self.current_img_path, msg, key)
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
            if save_path:
                res_img.save(save_path)
                messagebox.showinfo("Успех", "Файл успешно сохранен!")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def process_extract(self):
        try:
            key = self.ent_key_ex.get().encode('utf-8')
            data = SteganoLogic.decode(self.current_img_path_ex, key)
            
            self.txt_ex.config(state="normal")
            self.txt_ex.delete("1.0", tk.END)
            self.txt_ex.insert(tk.END, data.decode('utf-8'))
            self.txt_ex.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось извлечь: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganoGUI(root)
    root.mainloop()