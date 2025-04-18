from tests.builder import avs_registry_reader



def test_get_operator_id():
    return avs_registry_reader.get_operator_id("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")

print(test_get_operator_id())