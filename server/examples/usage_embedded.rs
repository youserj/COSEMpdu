//! Embedded-вариант: без кучи, значения в static, сервер — локальный.

use cosempdu::apdu_sn::Conformance;
use cosempdu::buffer::ByteBuffer;

use dlms1::common_data_types::DoubleLongUnsigned;
use dlms1::ic::{ClassId, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AccessMask, Server};

static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJECTS: &[&dyn InterfaceClass] = &[&REG_OBJ];

static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);

fn main() -> Result<(), server::Error> {
    // Однопоточный embedded: берём `&mut` на static-значение, сервер — локальный.
    let register = unsafe { &mut *core::ptr::addr_of_mut!(REGISTER) };
    register.0 = 230000;

    let read_all = AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR;
    let mut server = Server::new(OBJECTS, Conformance([0x00, 0x7E, 0x1F]));
    server.add_persistent(
        REG_OBJ.value(),
        register,
        Access { read: read_all, write: AccessMask::CONFIGURATOR },
    )?;

    let mut backing = [0u8; 64];
    let mut buf = ByteBuffer::new(&mut backing);
    server.put(ClassId::Register, REG_OBJ.value(), AccessMask::READER, &mut buf)?;
    println!("decoded: {:?}", buf.extract());

    Ok(())
}
