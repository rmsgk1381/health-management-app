from settings import settings
from security import (
    hash_password,
    is_allowed_origin,
    normalize_email,
    verify_password,
)

# 이메일 양끝 공백을 제거하고 소문자로 정규화하는지 확인한다.
def test_normalize_email_strips_whitespace_lowercases():
    result = normalize_email("  Test.User@EXAMPLE.COM  ")
    assert result == "test.user@example.com"

# 이미 정규화한 이메일의 값을 그대로 유지하는지 확인한다.
def test_normalize_email_preserves_normalized_address():
    email = "test.user@example.com"
    assert normalize_email(email) == email

# 올바른 비밀번호가 저장된 해시 검증을 통과하는지 확인한다.
def test_verify_password_accepts_correct_password():
    stored_hash = hash_password("step15-demo-only")
    assert verify_password("step15-demo-only", stored_hash) is True

# 잘못된 비밀번호가 저장된 해시 검증에서 거부되는지 확인한다.
def test_verify_password_rejects_wrong_password():
    stored_hash = hash_password("step15-demo-only")
    assert verify_password("wrong-demo-password", stored_hash) is False

# 동일한 비밀번호로 생성한 두 해시가 서로 다르고 모두 정상 검증되는지 확인한다.
def test_hash_password_generates_different_hashes_for_same_password():
    first_hash = hash_password("step15-demo-only")
    second_hash = hash_password("step15-demo-only")
    assert first_hash != second_hash
    assert verify_password("step15-demo-only", first_hash) is True
    assert verify_password("step15-demo-only", second_hash) is True
    assert first_hash != "step15-demo-only"
    assert second_hash != "step15-demo-only"

# 설정된 Origin만 허용하고 누락되거나 다른 Origin은 거부하는지 확인한다.
def test_is_allowed_origin_requires_exact_match():
    assert is_allowed_origin(settings.FRONTEND_ORIGIN) is True
    assert is_allowed_origin("http://127.0.0.1:5174") is False
    assert is_allowed_origin(None) is False
