//! Embedded-вариант: без кучи, значения в static, сервер — локальный.

use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

use dlms1::ic::{Attribute, ClassId, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AccessMask, Server};

struct RegisterValue(u32);

impl Attribute for RegisterValue {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> dlms1::Result<usize> {
        Ok(Data::DoubleLongUnsigned(self.0).put(buf)?)
    }
    fn assign(&mut self, d: &Data<'_>) -> dlms1::Result<()> {
        match d {
            Data::DoubleLongUnsigned(v) => {
                self.0 = *v;
                Ok(())
            }
            _ => Err(dlms1::Error::TypeMismatch { expected: 6, got: d.tag() }),
        }
    }
}

static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJECTS: &[&dyn InterfaceClass] = &[&REG_OBJ];

static mut REGISTER: RegisterValue = RegisterValue(0);

fn main() -> Result<(), server::Error> {
    // Однопоточный embedded: берём `&mut` на static-значение, сервер — локальный.
    let register = unsafe { &mut *core::ptr::addr_of_mut!(REGISTER) };
    register.0 = 230000;

    let read_all = AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR;
    let mut server = Server::new(OBJECTS);
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
