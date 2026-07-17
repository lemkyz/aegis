from aegis.utils.text import strip_markdown_code_fence


def test_removes_python_markdown_fence() -> None:
    value = '''```python
print("Hello")
```'''

    result = strip_markdown_code_fence(value)

    assert result == 'print("Hello")'


def test_removes_generic_markdown_fence() -> None:
    value = '''```
secure_code()
```'''

    result = strip_markdown_code_fence(value)

    assert result == "secure_code()"


def test_keeps_plain_text_unchanged() -> None:
    value = "secure_code()"

    result = strip_markdown_code_fence(value)

    assert result == "secure_code()"


def test_accepts_none() -> None:
    result = strip_markdown_code_fence(None)

    assert result is None
