//! Example of using `Server`: attributes in a ROM table + object catalog.

use cosempdu::apdu::{CosemAttributeDescriptor, InvokeIdAndPriority};
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data};

use dlms1::common_data_types::DoubleLongUnsigned;
use dlms1::ic::{AttributeAccessMode, AttributeKey, ClassId, DataObject, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AttrDesc, AttrKind, AttrSpec, Server, Settings};

// Object catalog (ROM).
static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJ_PAIRS: [(&dyn InterfaceClass, ObisCode); 2] = server::objects![SERIAL_OBJ, REG_OBJ];
static OBJECTS: &[&dyn InterfaceClass] = &server::merge_objects::<2>(&[], &OBJ_PAIRS);

// Attribute values (read-only in ROM, mutable in RAM).
static SN: DoubleLongUnsigned = DoubleLongUnsigned(123456);
static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(230000);

/// Default rights: public/reader can read, configurator can read+write.
const RW: Access = Access {
    public: AttributeAccessMode::ReadOnly,
    reader: AttributeAccessMode::ReadOnly,
    configurator: AttributeAccessMode::ReadAndWrite,
};

// ROM attribute table (sorted by key; OBIS resolves to the object index).
static ATTRS: [AttrSpec; 2] = [
    AttrSpec {
        key: AttributeKey::new(SERIAL_OBJ.obis, 2), // SERIAL value
        access: RW,
        kind: AttrKind::Static(&SN),
    },
    AttrSpec {
        key: AttributeKey::new(REG_OBJ.obis, 2), // REG value
        access: RW,
        kind: AttrKind::Persistent(0),
    },
];
static ROM_ATTRS: [AttrDesc; 2] = server::merge_attrs::<2>(&[], &OBJ_PAIRS, &[], &ATTRS);
static CODECS: [&dyn Codec; 1] = server::merge_codecs::<1>(&[], &ATTRS);

// RAM slots for mutable values.
static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];

fn main() -> Result<(), server::Error> {
    unsafe {
        MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
    }
    let mut server = Server::new(OBJECTS, &ROM_ATTRS, &CODECS, unsafe {
        &mut *core::ptr::addr_of_mut!(MUT)
    });

    // GET (reads as Reader)
    {
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
        println!("register response: {:?}", buf.extract());
    }

    // SET (writes as Configurator) — streaming receive.
    {
        let mut backing = [0u8; 64];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(231000).put(&mut b)?
        };
        let mut s = server
            .stream_set(
                ClassId::Register,
                REG_OBJ.value(),
                &Settings::configurator(),
            )
            .unwrap();
        s.push(&backing[..n])?;
        s.finish()?;
    }
    {
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
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
        println!("register response (after SET): {:?}", buf.extract());
    }

    // static serial
    {
        let mut backing = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut backing);
        server
            .handle_get(
                InvokeIdAndPriority::from_bits(1, true, false),
                CosemAttributeDescriptor {
                    class_id: ClassId::Data.as_u16(),
                    instance_id: SERIAL_OBJ.value().obis.bytes,
                    attribute_id: 2,
                },
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
        println!("serial response: {:?}", buf.extract());
    }

    Ok(())
}
