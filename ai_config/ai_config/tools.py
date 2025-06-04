# Di dalam linux_admin_ai/tools.py (buat file baru atau letakkan di views.py jika sederhana)
import os
import subprocess
import shlex
from langchain.tools import Tool

# --- Implementasi Fungsi Tool ---
# PENTING: Keamanan adalah prioritas utama untuk tool yang mengeksekusi perintah!

def _execute_shell_command(command: str) -> str:
    """
    Menjalankan perintah shell.
    PERINGATAN: SANGAT BERISIKO. Harus dengan validasi ketat atau sandboxing.
    Untuk TA, batasi hanya pada perintah yang 100% aman atau buat mekanisme konfirmasi.
    """
    print(f"LANGCHAIN TOOL: Executing shell command: {command}")
    if not command.strip():
        return "Error: Tidak ada perintah yang diberikan."

    # CONTOH VALIDASI DASAR (INI TIDAK CUKUP UNTUK PRODUKSI!)
    forbidden_substrings = ["rm -rf", "mkfs", "chmod 000", "dd if=/dev/zero", "sudo reboot", "sudo shutdown"]
    # Anda mungkin ingin whitelist yang sangat ketat, atau parsing & validasi mendalam.
    if any(forbidden in command.lower() for forbidden in forbidden_substrings):
        return f"Error: Perintah '{command}' terdeteksi berpotensi berbahaya dan diblokir oleh tool."

    try:
        # Menggunakan shell=True sangat berisiko dengan input dari LLM.
        # Idealnya, pecah perintah dan gunakan shell=False jika memungkinkan.
        result = subprocess.run(
            command,
            shell=True, 
            capture_output=True,
            text=True,
            timeout=30, # Batas waktu eksekusi
            check=False # Tangani return code secara manual
        )
        output = f"Perintah: {command}\nReturn Code: {result.returncode}\nStdout:\n{result.stdout}\nStderr:\n{result.stderr}"
        if len(output) > 1500: # Batasi panjang output untuk LLM
            output = output[:1500] + "\n... (output dipotong)"
        return output
    except subprocess.TimeoutExpired:
        return f"Error: Eksekusi perintah '{command}' melebihi batas waktu."
    except Exception as e:
        return f"Error saat menjalankan perintah '{command}': {str(e)}"

def _list_directory_contents(directory_path: str = ".") -> str:
    """Melihat isi dari direktori yang ditentukan. Default ke direktori saat ini."""
    print(f"LANGCHAIN TOOL: Listing directory: {directory_path}")
    if not directory_path:
        directory_path = "."
    
    abs_path = os.path.abspath(directory_path)
    # Tambahkan validasi path di sini untuk keamanan (misal, batasi pada subdirektori tertentu)
    # if not abs_path.startswith(os.path.abspath(settings.ALLOWED_BASE_PATH)):
    #     return "Error: Akses ke path direktori ini tidak diizinkan."

    try:
        if not os.path.isdir(abs_path):
            return f"Error: '{abs_path}' bukan direktori yang valid."
        entries = os.listdir(abs_path)
        if not entries:
            return f"Direktori '{abs_path}' kosong."
        return f"Isi direktori '{abs_path}':\n" + "\n".join(entries)
    except FileNotFoundError:
        return f"Error: Direktori '{abs_path}' tidak ditemukan."
    except PermissionError:
        return f"Error: Izin ditolak untuk mengakses direktori '{abs_path}'."
    except Exception as e:
        return f"Error saat melihat isi direktori: {str(e)}"

def _read_file_snippet(file_path: str, num_lines: int = 20) -> str:
    """Membaca beberapa baris awal dari file yang ditentukan."""
    print(f"LANGCHAIN TOOL: Reading file snippet: {file_path}")
    abs_path = os.path.abspath(file_path)
    # Tambahkan validasi path di sini untuk keamanan
    # if not abs_path.startswith(os.path.abspath(settings.ALLOWED_BASE_PATH)):
    #     return "Error: Akses ke path file ini tidak diizinkan."

    try:
        if not os.path.isfile(abs_path):
            # Coba CWD jika path absolut tidak ditemukan dan path awal bukan absolut
            if not os.path.isabs(file_path):
                cwd_path = os.path.join(os.getcwd(), file_path)
                if os.path.isfile(cwd_path):
                    abs_path = cwd_path
                else:
                    return f"Error: File '{file_path}' (atau '{abs_path}') tidak ditemukan."
            else:
                 return f"Error: File '{abs_path}' tidak ditemukan."

        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [next(f).strip() for _ in range(num_lines)]
        snippet = "\n".join(lines)
        if len(lines) == num_lines: # Jika file lebih panjang dari num_lines
            snippet += f"\n... (ditampilkan {num_lines} baris pertama)"
        return f"Cuplikan isi file '{abs_path}':\n{snippet}"
    except FileNotFoundError: # Ini seharusnya sudah ditangani di atas, tapi sebagai fallback
        return f"Error: File '{abs_path}' tidak ditemukan."
    except PermissionError:
        return f"Error: Izin ditolak untuk membaca file '{abs_path}'."
    except Exception as e:
        return f"Error saat membaca file: {str(e)}"

# --- Bungkus Fungsi menjadi LangChain Tools ---
execute_shell_tool = Tool(
    name="ExecuteShellCommand",
    func=_execute_shell_command,
    description="""Sangat berguna untuk menjalankan perintah shell Linux apa pun untuk mendapatkan informasi sistem, mengelola file, memeriksa status layanan, dll.
    Input harus berupa string perintah tunggal (misalnya, 'ls -l /tmp', 'df -h').
    Gunakan dengan sangat hati-hati karena bisa berbahaya. Jika ragu, tanya klarifikasi atau gunakan tool yang lebih spesifik.
    Jangan gunakan untuk perintah yang sangat destruktif kecuali diminta secara eksplisit dan dikonfirmasi aman."""
)

list_directory_tool = Tool(
    name="ListDirectoryContents",
    func=_list_directory_contents,
    description="""Berguna untuk melihat daftar file dan subdirektori dalam path direktori tertentu.
    Input adalah string path direktori. Jika input kosong, akan menggunakan direktori kerja saat ini.
    Gunakan ini untuk eksplorasi sistem file sebelum melakukan operasi file."""
)

read_file_snippet_tool = Tool(
    name="ReadFileSnippet",
    func=_read_file_snippet,
    description="""Berguna untuk membaca dan menampilkan beberapa baris awal dari sebuah file teks.
    Input adalah string path file.
    Gunakan ini untuk memeriksa isi file dengan cepat tanpa harus menampilkan seluruh file jika besar."""
)

# Kumpulkan semua tools
ALL_TOOLS = [execute_shell_tool, list_directory_tool, read_file_snippet_tool]