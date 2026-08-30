from ariadne_protocol.c_types import types_to_c_header
from ariadne_protocol.types import StructMember, StructType, TypeDef


def test_struct_header_includes_padding() -> None:
    typedef = TypeDef(
        name="node",
        kind="struct",
        text="struct node",
        struct=StructType(
            "node",
            16,
            [
                StructMember("value", 0, "int32_t", 4),
                StructMember("next", 8, "struct node*", 8),
            ],
        ),
    )
    header = types_to_c_header([typedef])
    assert "struct node {" in header
    assert "int32_t value;" in header
    assert "__bn_pad_0[4]" in header
    assert "struct node* next;" in header
