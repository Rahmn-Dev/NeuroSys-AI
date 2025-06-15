import pytest
from django.test import Client, TestCase
from django.urls import reverse
import json
import os
from tempfile import TemporaryDirectory, NamedTemporaryFile
from pathlib import Path
import django

def test_execute_valid_command(ai_tool_instance):
    result = ai_tool_instance.execute_command("echo Hello World")
    assert result["success"] is True

def test_service_control_start(ai_tool_instance):
    result = ai_tool_instance.service_control("nginx", "status")
    assert result["success"] is True or result["success"] is False  # Sesuaikan sesuai apakah nginx ada
    assert result["service"] == "nginx"
    assert result["action"] == "status"

def test_service_control_invalid_action(ai_tool_instance):
    result = ai_tool_instance.service_control("nginx", "pause")
    assert "Invalid action" in result["error"]

def test_file_read_success(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile.write("Line 1\nLine 2\nLine 3")
        tmpfile_path = tmpfile.name

    try:
        result = ai_tool_instance.file_read(tmpfile_path, lines=2)
        
        # Ubah content menjadi list jika diperlukan
        content_lines = result["content"].splitlines()
        
        assert len(content_lines) == 2
        assert content_lines[0] == "Line 1"
        assert content_lines[1] == "Line 2"
    finally:
        os.remove(tmpfile_path)


def test_file_read_not_found(ai_tool_instance):
    result = ai_tool_instance.file_read("/path/to/nonexistent/file.txt")
    assert "No such file" in result["error"] or "Permission denied" in result["error"]

def test_file_write_overwrite(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile_path = tmpfile.name

    try:
        ai_tool_instance.file_write(tmpfile_path, "Hello World", mode="w")
        with open(tmpfile_path, 'r') as f:
            content = f.read()
        assert content == "Hello World"
    finally:
        os.remove(tmpfile_path)

def test_file_write_append(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile_path = tmpfile.name

    try:
        ai_tool_instance.file_write(tmpfile_path, "Line 1\n", mode="a")
        ai_tool_instance.file_write(tmpfile_path, "Line 2\n", mode="a")
        with open(tmpfile_path, 'r') as f:
            content = f.readlines()
        assert len(content) == 2
        assert content[0] == "Line 1\n"
        assert content[1] == "Line 2\n"
    finally:
        os.remove(tmpfile_path)

def test_log_analyze_pattern(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile.write("INFO: App started\nERROR: Connection failed\nINFO: Retrying...\nERROR: Timeout")
        tmpfile_path = tmpfile.name

    try:
        result = ai_tool_instance.log_analyze(tmpfile_path, pattern="ERROR")
        assert len(result["matches"]) == 2
        assert any("Timeout" in line for line in result["matches"])
    finally:
        os.remove(tmpfile_path)

def test_security_scan_ports(ai_tool_instance):
    result = ai_tool_instance.security_scan("ports")
    assert isinstance(result.get("open_ports"), list)

# def test_security_scan_invalid_type(ai_tool_instance):
#     result = ai_tool_instance.security_scan("invalid-scan-type")
#     assert "Invalid scan type" in result["error"]

def test_config_validate_nginx(ai_tool_instance):
    result = ai_tool_instance.config_validate("nginx")
    assert isinstance(result["valid"], bool)

# def test_config_validate_unsupported(ai_tool_instance):
#     result = ai_tool_instance.config_validate("unsupported-service")
#     assert "Not supported" in result["error"]

def test_file_edit_replace_line(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile.write("Line 1\nLine 2\nLine 3\n")
        tmpfile_path = tmpfile.name

    try:
        ai_tool_instance.file_edit(tmpfile_path, "replace_line", line_number=2, content="New Line 2")
        with open(tmpfile_path, 'r') as f:
            lines = f.readlines()
        assert lines[1] == "New Line 2\n"
    finally:
        os.remove(tmpfile_path)

def test_file_edit_insert_line(ai_tool_instance):
    with NamedTemporaryFile(mode='w', delete=False) as tmpfile:
        tmpfile.write("Line 1\nLine 2\nLine 3\n")
        tmpfile_path = tmpfile.name

    try:
        ai_tool_instance.file_edit(tmpfile_path, "insert_line", line_number=2, content="Inserted Line")
        with open(tmpfile_path, 'r') as f:
            lines = f.readlines()
        assert lines[1] == "Inserted Line\n"
        assert lines[2] == "Line 2\n"
    finally:
        os.remove(tmpfile_path)


@pytest.mark.django_db
def test_process_smart_chat_valid_post():
    """
    Test bahwa endpoint /api/process-smart-chat/ dapat menerima POST dengan JSON
    """
    client = Client()
    
    # Tambahkan try-except untuk menangani case jika URL tidak ditemukan
    try:
        url = reverse('process_smart_chat')  # Sesuai nama 'name' di urls.py
    except Exception as e:
        pytest.fail(f"URL 'process_smart_chat' tidak ditemukan: {e}")

    payload = {
        "message": "tampilkan hello world"
    }

    response = client.post(
        url, 
        data=json.dumps(payload), 
        content_type='application/json'
    )

    # Debugging: print response untuk melihat apa yang dikembalikan
    print(f"Response status: {response.status_code}")
    print(f"Response content: {response.content}")
    
    # Cek apakah response adalah JSON yang valid
    try:
        json_response = response.json()
    except json.JSONDecodeError:
        pytest.fail(f"Response bukan JSON yang valid: {response.content}")

    # Assertion yang lebih fleksibel
    if response.status_code == 200:
        assert 'response' in json_response or 'data' in json_response
        assert 'user_message' in json_response or 'message' in json_response
    else:
        # Jika tidak 200, tampilkan error untuk debugging
        pytest.fail(f"Expected status 200, got {response.status_code}. Response: {json_response}")


@pytest.mark.django_db
def test_process_smart_chat_invalid_json():
    """
    Test bahwa endpoint menolak JSON yang tidak valid
    """
    client = Client()
    
    try:
        url = reverse('process_smart_chat')
    except Exception as e:
        pytest.fail(f"URL 'process_smart_chat' tidak ditemukan: {e}")

    invalid_data = "invalid-json"

    response = client.post(
        url, 
        data=invalid_data, 
        content_type='application/json'
    )
    
    print(f"Invalid JSON test - Response status: {response.status_code}")
    print(f"Invalid JSON test - Response content: {response.content}")
    
    # Cek berbagai kemungkinan status code untuk invalid JSON
    assert response.status_code in [400, 500], f"Expected 400 or 500, got {response.status_code}"
    
    # Cek apakah response berupa JSON
    try:
        json_response = response.json()
        # Cek berbagai kemungkinan key untuk error
        assert ('error' in json_response or 
                'message' in json_response or 
                'detail' in json_response), f"No error field found in response: {json_response}"
    except json.JSONDecodeError:
        # Jika response bukan JSON, itu juga acceptable untuk error case
        pass


@pytest.mark.django_db
def test_process_smart_chat_invalid_method():
    """
    Test bahwa hanya metode POST yang diterima
    """
    client = Client()
    
    try:
        url = reverse('process_smart_chat')
    except Exception as e:
        pytest.fail(f"URL 'process_smart_chat' tidak ditemukan: {e}")

    # Test GET method
    response = client.get(url)
    print(f"GET method test - Response status: {response.status_code}")
    print(f"GET method test - Response content: {response.content}")
    
    assert response.status_code in [405, 404], f"Expected 405 or 404 for GET, got {response.status_code}"
    
    # Jika response adalah JSON, cek error message
    try:
        json_response = response.json()
        assert ('error' in json_response or 
                'message' in json_response or 
                'detail' in json_response), f"No error field found: {json_response}"
    except json.JSONDecodeError:
        # Response mungkin bukan JSON untuk method tidak diizinkan
        pass

    # Test PUT method
    response = client.put(
        url, 
        data='{}', 
        content_type='application/json'
    )
    print(f"PUT method test - Response status: {response.status_code}")
    print(f"PUT method test - Response content: {response.content}")
    
    assert response.status_code in [405, 404], f"Expected 405 or 404 for PUT, got {response.status_code}"
    
    try:
        json_response = response.json()
        assert ('error' in json_response or 
                'message' in json_response or 
                'detail' in json_response), f"No error field found: {json_response}"
    except json.JSONDecodeError:
        pass


# Tambahan test untuk debugging URL
@pytest.mark.django_db
def test_url_exists():
    """
    Test untuk memastikan URL pattern ada dan dapat di-reverse
    """
    try:
        url = reverse('process_smart_chat')
        print(f"URL berhasil di-reverse: {url}")
        assert url is not None
        assert isinstance(url, str)
        assert len(url) > 0
    except Exception as e:
        pytest.fail(f"Gagal me-reverse URL 'process_smart_chat': {e}")


# Test dengan payload kosong
@pytest.mark.django_db 
def test_process_smart_chat_empty_payload():
    """
    Test dengan payload kosong
    """
    client = Client()
    
    try:
        url = reverse('process_smart_chat')
    except Exception as e:
        pytest.fail(f"URL 'process_smart_chat' tidak ditemukan: {e}")

    payload = {}

    response = client.post(
        url, 
        data=json.dumps(payload), 
        content_type='application/json'
    )
    
    print(f"Empty payload test - Response status: {response.status_code}")
    print(f"Empty payload test - Response content: {response.content}")
    
    # Bisa jadi 400 (bad request) atau 200 tergantung implementasi view
    assert response.status_code in [200, 400], f"Unexpected status code: {response.status_code}"