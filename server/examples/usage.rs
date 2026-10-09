//! Пример использования `Server`: атрибуты по отдельности + каталог объектов.

use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

use dlms1::ic::{Attribute, ClassId, DataObject, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AccessMask, Server};

/// Конкретный тип: Register value = DoubleLongUnsigned.
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

// Каталог объектов (ROM).
static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJECTS: &[&dyn InterfaceClass] = &[&SERIAL_OBJ, &REG_OBJ];

fn main() -> Result<(), server::Error> {
    let mut server = Server::new(OBJECTS);
    let read_all = AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR;

    // read-only (serial): статичное значение
    static SN: RegisterValue = RegisterValue(123456);
    server.add_static(
        SERIAL_OBJ.value(),
        &SN,
        Access { read: read_all, write: AccessMask::CONFIGURATOR },
    )?;

    // writable (persistent): register value
    let mut register = RegisterValue(230000);
    server.add_persistent(
        REG_OBJ.value(),
        &mut register,
        Access { read: read_all, write: AccessMask::CONFIGURATOR },
    )?;

    // GET (читает Reader)
    {
        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::READER, &mut buf)?;
        println!("register value: {:?}", buf.extract());
    }

    // SET (пишет Configurator)
    server.set(ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR, &Data::DoubleLongUnsigned(231000))?;
    {
        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf)?;
        println!("register value (after SET): {:?}", buf.extract());
    }

    // static serial
    {
        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server.put(ClassId::Data, SERIAL_OBJ.value(), AccessMask::PUBLIC, &mut buf)?;
        println!("serial: {:?}", buf.extract());
    }

    Ok(())
}
