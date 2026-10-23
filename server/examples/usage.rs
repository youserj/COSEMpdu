//! Пример использования `Server`: атрибуты по отдельности + каталог объектов.

use cosempdu::apdu_sn::Conformance;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::Data;

use dlms1::common_data_types::DoubleLongUnsigned;
use dlms1::ic::{ClassId, DataObject, InterfaceClass, Register};
use dlms1::obis::ObisCode;

use server::{Access, AccessMask, Server};

// Каталог объектов (ROM).
static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
static OBJECTS: &[&dyn InterfaceClass] = &[&SERIAL_OBJ, &REG_OBJ];

fn main() -> Result<(), server::Error> {
    let mut server = Server::new(OBJECTS, Conformance([0x00, 0x7E, 0x1F]));
    let read_all = AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR;

    // read-only (serial): статичное значение
    static SN: DoubleLongUnsigned = DoubleLongUnsigned(123456);
    server.add_static(
        SERIAL_OBJ.value(),
        &SN,
        Access { read: read_all, write: AccessMask::CONFIGURATOR },
    )?;

    // writable (persistent): register value
    let mut register = DoubleLongUnsigned(230000);
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

    // SET (пишет Configurator) — потоковый приём.
    {
        let mut backing = [0u8; 64];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(231000).put(&mut b)?
        };
        let mut s = server.stream_set(ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR)?;
        s.push(&backing[..n])?;
        s.finish()?;
    }
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
