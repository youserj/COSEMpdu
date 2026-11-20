//! Embedded variant: no heap, values in statics, the server is local.

use cosempdu::apdu::{CosemAttributeDescriptor, InvokeIdAndPriority};
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Codec;

use dlms1::common_data_types::DoubleLongUnsigned;
use dlms1::ic::{AttributeAccessMode, AttributeKey, ClassId, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AttrDesc, AttrKind, AttrSpec, Server, Settings};

static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJ_PAIRS: [(&dyn InterfaceClass, ObisCode); 1] = server::objects![REG_OBJ];
static OBJECTS: &[&dyn InterfaceClass] = &server::merge_objects::<1>(&[], &OBJ_PAIRS);

static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);

/// Default rights: public/reader can read, configurator can read+write.
const RW: Access = Access {
    public: AttributeAccessMode::ReadOnly,
    reader: AttributeAccessMode::ReadOnly,
    configurator: AttributeAccessMode::ReadAndWrite,
};

static ATTRS: [AttrSpec; 1] = [AttrSpec {
    key: AttributeKey::new(REG_OBJ.obis, 2),
    access: RW,
    kind: AttrKind::Persistent(0),
}];
static ROM_ATTRS: [AttrDesc; 1] = server::merge_attrs::<1>(&[], &OBJ_PAIRS, &[], &ATTRS);

static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];

fn main() -> Result<(), server::Error> {
    unsafe {
        REGISTER.0 = 230000;
        MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
    }

    let server = Server::new(OBJECTS, &ROM_ATTRS, &[], unsafe {
        &mut *core::ptr::addr_of_mut!(MUT)
    });

    let mut backing = [0u8; 128];
    let mut buf = ByteBuffer::new(&mut backing);
    server
        .handle_get(
            InvokeIdAndPriority::from_bits(1, true, false),
            CosemAttributeDescriptor {
                class_id: ClassId::Register.as_u16(),
                instance_id: REG_OBJ.value().obis.bytes,
                attribute_id: 2,
            },
            &Settings::reader(),
            &mut buf,
        )
        .unwrap();
    println!("decoded: {:?}", buf.extract());

    Ok(())
}
