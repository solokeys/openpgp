import pytest

@pytest.fixture(scope="module",autouse=True)
def check_gnuk(card):
    if not card.is_gnuk:
        pytest.skip("Gnuk only feature", allow_module_level=True)
