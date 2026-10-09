//! Минимальный DLMS/COSEM сервер (реестр атрибутов + каталог объектов).
//!
//! Атрибуты хранятся **по отдельности** — типизированные значения [`Attribute`],
//! права доступа [`Access`] и вид изменяемости ([`ValueRef`]). Поэтому каждый
//! атрибут размещается в памяти независимо (`static` → ROM, `static mut` → RAM).
//! Каталог COSEM-объектов ([`InterfaceClass`]) хранится в сервере как
//! `static`-срез и используется для валидации входящих запросов
//! (`class_id` + OBIS). Куча не используется (no-heap, готово к `no_std`).

use core::fmt;

use cosempdu::buffer::{ByteBuffer, Reader};
use cosempdu::data::{Arena, Data};
use dlms1::ic::{Attribute, AttributeKey, ClassId, InterfaceClass};
use dlms1::obis::ObisCode;

/// Ёмкость реестра (максимальное число атрибутов).
pub const MAX_ATTRS: usize = 1024;

/// Ошибки сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Реестр переполнен (`MAX_ATTRS`).
    RegistryFull,
    /// Объект (OBIS) или атрибут не найден.
    NotFound,
    /// Атрибут недоступен для записи (Static/Dynamic).
    ReadOnly,
    /// Уровень доступа клиента недостаточен.
    AccessDenied,
    /// `class_id` в запросе не совпал с классом объекта.
    UnknownClass { expected: ClassId, got: ClassId },
    /// Значение не соответствует ожидаемому типу (по A-XDR тегу).
    TypeMismatch { expected: u8, got: u8 },
    /// Ошибка кодера/декодера COSEM PDU.
    Codec(cosempdu::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RegistryFull => write!(f, "registry full (MAX_ATTRS)"),
            Error::NotFound => write!(f, "object/attribute not found"),
            Error::ReadOnly => write!(f, "attribute is read-only"),
            Error::AccessDenied => write!(f, "access denied"),
            Error::UnknownClass { expected, got } => {
                write!(f, "class mismatch: expected {expected:?}, got {got:?}")
            }
            Error::TypeMismatch { expected, got } => {
                write!(f, "type mismatch: expected tag {expected}, got {got}")
            }
            Error::Codec(e) => write!(f, "{e}"),
        }
    }
}

impl From<cosempdu::Error> for Error {
    fn from(e: cosempdu::Error) -> Self {
        Error::Codec(e)
    }
}

impl From<dlms1::Error> for Error {
    fn from(e: dlms1::Error) -> Self {
        match e {
            dlms1::Error::TypeMismatch { expected, got } => Error::TypeMismatch { expected, got },
            dlms1::Error::Codec(e) => Error::Codec(e),
            dlms1::Error::ChoiceMismatch { .. } | dlms1::Error::InvalidObis => {
                Error::Codec(cosempdu::Error::Message("invalid attribute value"))
            }
        }
    }
}

/// Битовая маска уровней доступа (каждый уровень — свой бит).
///
/// Уровни не пересекаются, поэтому доступ задаётся набором бит. Приложение может
/// определить свои уровни через `AccessMask(1 << n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(pub u8);

impl AccessMask {
    pub const PUBLIC: Self = AccessMask(1 << 0);
    pub const READER: Self = AccessMask(1 << 1);
    pub const CONFIGURATOR: Self = AccessMask(1 << 2);

    /// Есть ли пересечение с `mask` (т.е. уровень входит в набор).
    pub fn contains(self, mask: AccessMask) -> bool {
        self.0 & mask.0 != 0
    }
}

impl core::ops::BitOr for AccessMask {
    type Output = AccessMask;
    fn bitor(self, rhs: AccessMask) -> AccessMask {
        AccessMask(self.0 | rhs.0)
    }
}

/// Права доступа к атрибуту.
#[derive(Debug, Clone, Copy)]
pub struct Access {
    /// Уровни, которым разрешено чтение (GET).
    pub read: AccessMask,
    /// Уровни, которым разрешена запись (SET; только `Persistent`).
    pub write: AccessMask,
}

/// Ссылка на типизированное значение атрибута + права доступа + вид изменяемости.
pub enum ValueRef<'a> {
    /// Read-only значение (никто не меняет).
    Static(&'a dyn Attribute, Access),
    /// Меняется только самим сервером (`update`).
    Dynamic(&'a mut dyn Attribute, Access),
    /// Меняется извне через SET; сохраняется в NVM.
    Persistent(&'a mut dyn Attribute, Access),
}

/// Бэкенд энергонезависимой памяти (flash/EEPROM) для `Persistent`-атрибутов.
///
/// Крейт `server` не зависит от конкретного железа — реализацию предоставляет
/// приложение.
pub trait Nvm {
    fn load(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Error>;
    fn save(&mut self, offset: usize, buf: &[u8]) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
}

/// Реестр атрибутов: отсортированный по ключу массив + бинарный поиск.
pub struct Registry<'a> {
    entries: [Option<(AttributeKey, ValueRef<'a>)>; MAX_ATTRS],
    len: usize,
}

impl<'a> Registry<'a> {
    pub fn new() -> Self {
        Registry {
            entries: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Бинарный поиск значения по ключу.
    pub fn get(&self, key: &AttributeKey) -> Option<&ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(key)).ok()?
        };
        Some(&self.entries[idx].as_ref().unwrap().1)
    }

    /// Бинарный поиск значения по ключу (мутабельно).
    pub fn get_mut(&mut self, key: &AttributeKey) -> Option<&mut ValueRef<'a>> {
        let idx = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(key)).ok()?
        };
        Some(&mut self.entries[idx].as_mut().unwrap().1)
    }

    /// Вставка/обновление. Вставка нового ключа — O(n) сдвиг (редкая операция).
    pub fn insert(&mut self, key: AttributeKey, value: ValueRef<'a>) -> Result<(), Error> {
        let pos = {
            let occupied = &self.entries[..self.len];
            occupied.binary_search_by(|e| e.as_ref().unwrap().0.cmp(&key))
        };
        match pos {
            Ok(i) => {
                self.entries[i].as_mut().unwrap().1 = value;
                Ok(())
            }
            Err(pos) => {
                if self.len >= MAX_ATTRS {
                    return Err(Error::RegistryFull);
                }
                for i in (pos..self.len).rev() {
                    let e = self.entries[i].take();
                    self.entries[i + 1] = e;
                }
                self.entries[pos] = Some((key, value));
                self.len += 1;
                Ok(())
            }
        }
    }
}

impl<'a> Default for Registry<'a> {
    fn default() -> Self {
        Registry::new()
    }
}

/// COSEM-сервер: каталог объектов + реестр атрибутов.
pub struct Server<'a> {
    objects: &'static [&'static dyn InterfaceClass],
    attributes: Registry<'a>,
}

impl<'a> Server<'a> {
    /// Создать сервер с каталогом COSEM-объектов (для валидации `class_id` + OBIS).
    pub fn new(objects: &'static [&'static dyn InterfaceClass]) -> Self {
        Server {
            objects,
            attributes: Registry::new(),
        }
    }

    /// Найти объект по OBIS и проверить `class_id`.
    fn find_object(&self, class_id: ClassId, obis: &ObisCode) -> Result<&'static dyn InterfaceClass, Error> {
        let obj = self
            .objects
            .iter()
            .find(|o| o.obis() == *obis)
            .copied()
            .ok_or(Error::NotFound)?;
        if obj.class_id() != class_id {
            return Err(Error::UnknownClass {
                expected: obj.class_id(),
                got: class_id,
            });
        }
        Ok(obj)
    }

    /// Зарегистрировать read-only значение.
    pub fn add_static(&mut self, key: AttributeKey, attr: &'a dyn Attribute, access: Access) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Static(attr, access))
    }

    /// Зарегистрировать значение, изменяемое только самим сервером.
    pub fn add_dynamic(&mut self, key: AttributeKey, attr: &'a mut dyn Attribute, access: Access) -> Result<(), Error> {
        self.attributes.insert(key, ValueRef::Dynamic(attr, access))
    }

    /// Зарегистрировать значение, изменяемое извне через SET (NVM).
    pub fn add_persistent(&mut self, key: AttributeKey, attr: &'a mut dyn Attribute, access: Access) -> Result<(), Error> {
        // TODO: NVM — регистрация + восстановление из заводского дефолта.
        self.attributes.insert(key, ValueRef::Persistent(attr, access))
    }

    /// PUT: положить закодированное значение в `buf`, с проверкой права чтения.
    pub fn put(
        &self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<(), Error> {
        self.find_object(class_id, &key.obis)?;
        match self.attributes.get(&key).ok_or(Error::NotFound)? {
            ValueRef::Static(a, access) => {
                if !access.read.contains(level) { return Err(Error::AccessDenied); }
                a.put(buf)?;
            }
            ValueRef::Dynamic(a, access) | ValueRef::Persistent(a, access) => {
                if !access.read.contains(level) { return Err(Error::AccessDenied); }
                a.put(buf)?;
            }
        }
        Ok(())
    }

    /// SET (внешний): записать `data` в `Persistent`-атрибут, с проверкой права записи и типа.
    pub fn set(
        &mut self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
        data: &Data<'_>,
    ) -> Result<(), Error> {
        self.find_object(class_id, &key.obis)?;
        match self.attributes.get_mut(&key) {
            Some(ValueRef::Persistent(a, access)) => {
                if !access.write.contains(level) { return Err(Error::AccessDenied); }
                a.assign(data)?;
            }
            Some(ValueRef::Static(..)) | Some(ValueRef::Dynamic(..)) => return Err(Error::ReadOnly),
            None => return Err(Error::NotFound),
        }
        Ok(())
    }

    /// Декодировать значение из сырого A-XDR APDU (`reader` + `arena`) и применить
    /// к `Persistent`-атрибуту (проверка права записи и типа).
    pub fn get_apdu<'b>(
        &mut self,
        class_id: ClassId,
        key: AttributeKey,
        level: AccessMask,
        reader: &mut Reader<'b>,
        arena: &mut Arena<'b, Data<'b>>,
    ) -> Result<(), Error> {
        let value = Data::get(reader, arena)?;
        self.set(class_id, key, level, &value)
    }

    /// Внутреннее обновление `Dynamic`-атрибута (без проверки уровня и class_id).
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error> {
        match self.attributes.get_mut(&key) {
            Some(ValueRef::Dynamic(a, _)) => { a.assign(data)?; }
            Some(ValueRef::Static(..)) | Some(ValueRef::Persistent(..)) => return Err(Error::ReadOnly),
            None => return Err(Error::NotFound),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlms1::ic::{Attribute, Clock, DataObject, Register, ScalUnit};

    static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
    static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
    static CLOCK_OBJ: Clock = Clock::new(ObisCode::CLOCK);
    static OBJECTS: &[&dyn InterfaceClass] = &[&SERIAL_OBJ, &REG_OBJ, &CLOCK_OBJ];

    fn reg_access() -> Access {
        Access {
            read: AccessMask::PUBLIC | AccessMask::READER | AccessMask::CONFIGURATOR,
            write: AccessMask::CONFIGURATOR,
        }
    }

    /// Конкретный тип: Register value = DoubleLongUnsigned.
    struct RegisterValue(u32);

    impl Attribute for RegisterValue {
        fn put(&self, buf: &mut ByteBuffer<'_>) -> dlms1::Result<usize> {
            Ok(Data::DoubleLongUnsigned(self.0).put(buf)?)
        }
        fn assign(&mut self, d: &Data<'_>) -> dlms1::Result<()> {
            match d {
                Data::DoubleLongUnsigned(v) => { self.0 = *v; Ok(()) }
                _ => Err(dlms1::Error::TypeMismatch { expected: 6, got: d.tag() }),
            }
        }
    }

    /// Конкретный тип: Clock time = DateTime (12-байтный octet-string).
    struct ClockTime([u8; 12]);

    impl Attribute for ClockTime {
        fn put(&self, buf: &mut ByteBuffer<'_>) -> dlms1::Result<usize> {
            Ok(Data::DateTime(self.0).put(buf)?)
        }
        fn assign(&mut self, d: &Data<'_>) -> dlms1::Result<()> {
            match d {
                Data::DateTime(v) => { self.0 = *v; Ok(()) }
                _ => Err(dlms1::Error::TypeMismatch { expected: 25, got: d.tag() }),
            }
        }
    }

    #[test]
    fn registry_sorted_insert_and_search() {
        static A: RegisterValue = RegisterValue(1);
        let acc = Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR };
        let mut r = Registry::new();
        let k1 = AttributeKey::new(ObisCode::new(1, 0, 0, 0, 0, 0), 1);
        let k2 = AttributeKey::new(ObisCode::new(2, 0, 0, 0, 0, 0), 1);
        let k3 = AttributeKey::new(ObisCode::new(3, 0, 0, 0, 0, 0), 1);
        r.insert(k1, ValueRef::Static(&A, acc)).unwrap();
        r.insert(k3, ValueRef::Static(&A, acc)).unwrap();
        r.insert(k2, ValueRef::Static(&A, acc)).unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.get(&k1).is_some());
        assert!(r.get(&k2).is_some());
        assert!(r.get(&k3).is_some());
        assert!(r.get(&AttributeKey::new(ObisCode::new(9, 9, 9, 9, 9, 9), 1)).is_none());
    }

    #[test]
    fn server_get_set_persistent() {
        let mut server = Server::new(OBJECTS);

        static SN: RegisterValue = RegisterValue(123456);
        let serial = SERIAL_OBJ.value();
        server.add_static(serial, &SN, Access { read: AccessMask::PUBLIC, write: AccessMask::CONFIGURATOR }).unwrap();

        let mut register = RegisterValue(230000);
        let rw = REG_OBJ.value();
        server.add_persistent(rw, &mut register, reg_access()).unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::READER, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x03, 0x82, 0x70]);

        server.set(ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR, &Data::DoubleLongUnsigned(1)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x01]);
        }

        assert_eq!(server.put(ClassId::Register, REG_OBJ.value(), AccessMask(1 << 3), &mut buf), Err(Error::AccessDenied));
        assert_eq!(server.set(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &Data::DoubleLongUnsigned(2)), Err(Error::AccessDenied));
        assert_eq!(
            server.set(ClassId::Register, REG_OBJ.value(), AccessMask::CONFIGURATOR, &Data::Unsigned(200)),
            Err(Error::TypeMismatch { expected: 6, got: 17 })
        );
        assert_eq!(server.set(ClassId::Data, SERIAL_OBJ.value(), AccessMask::CONFIGURATOR, &Data::Unsigned(0)), Err(Error::ReadOnly));

        let missing = ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        assert_eq!(server.put(ClassId::Register, AttributeKey::new(missing, 2), AccessMask::PUBLIC, &mut buf), Err(Error::NotFound));
        assert_eq!(server.set(ClassId::Register, AttributeKey::new(missing, 2), AccessMask::PUBLIC, &Data::NullData), Err(Error::NotFound));
    }

    #[test]
    fn server_dynamic_update() {
        let mut server = Server::new(OBJECTS);
        let mut clock_time = ClockTime([0; 12]);
        server.add_dynamic(CLOCK_OBJ.time(), &mut clock_time, reg_access()).unwrap();

        let t: [u8; 12] = [0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF];
        server.update(CLOCK_OBJ.time(), &Data::DateTime(t)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Clock, CLOCK_OBJ.time(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x19, 0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF]);
        }

        assert_eq!(server.set(ClassId::Clock, CLOCK_OBJ.time(), AccessMask::CONFIGURATOR, &Data::DateTime(t)), Err(Error::ReadOnly));

        let mut p = ScalUnit { scaler: 0, unit: 255 };
        let pkey = REG_OBJ.scaler_unit();
        server.add_persistent(pkey, &mut p, reg_access()).unwrap();
        assert_eq!(server.update(REG_OBJ.scaler_unit(), &Data::Structure(&[Data::Integer(0), Data::Enum(255)])), Err(Error::ReadOnly));
    }

    #[test]
    fn server_get_apdu() {
        let mut server = Server::new(OBJECTS);
        let mut register = RegisterValue(0);
        let key = REG_OBJ.value();
        server.add_persistent(key, &mut register, reg_access()).unwrap();

        // Кодируем значение в байты.
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(42).put(&mut buf).unwrap()
        };

        // Декодируем из Reader и применяем.
        let mut arena_storage = [core::mem::MaybeUninit::uninit(); 8];
        let mut arena = Arena::new(&mut arena_storage);
        let mut reader = Reader::new(&backing[..n]);
        server.get_apdu(ClassId::Register, key, AccessMask::CONFIGURATOR, &mut reader, &mut arena).unwrap();

        // Проверяем.
        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        server.put(ClassId::Register, key, AccessMask::PUBLIC, &mut buf).unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x2A]);
    }

    #[test]
    fn server_validate_structure() {
        let mut server = Server::new(OBJECTS);
        let mut scal = ScalUnit { scaler: 3, unit: 1 };
        let key = REG_OBJ.scaler_unit();
        server.add_persistent(key, &mut scal, reg_access()).unwrap();

        server.set(ClassId::Register, REG_OBJ.scaler_unit(), AccessMask::CONFIGURATOR, &Data::Structure(&[Data::Integer(7), Data::Enum(2)])).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            server.put(ClassId::Register, REG_OBJ.scaler_unit(), AccessMask::PUBLIC, &mut buf).unwrap();
            assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x07, 0x16, 0x02]);
        }

        assert!(server
            .set(ClassId::Register, REG_OBJ.scaler_unit(), AccessMask::CONFIGURATOR, &Data::Structure(&[Data::Unsigned(1), Data::Unsigned(2)]))
            .is_err());
    }

    #[test]
    fn server_validates_class_id() {
        let mut server = Server::new(OBJECTS);
        let mut register = RegisterValue(0);
        let key = REG_OBJ.value();
        server.add_persistent(key, &mut register, reg_access()).unwrap();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);

        server.put(ClassId::Register, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf).unwrap();

        assert!(matches!(
            server.put(ClassId::Clock, REG_OBJ.value(), AccessMask::PUBLIC, &mut buf),
            Err(Error::UnknownClass { .. })
        ));

        let unknown = ObisCode::new(9, 9, 9, 9, 9, 9);
        assert_eq!(server.put(ClassId::Register, AttributeKey::new(unknown, 2), AccessMask::PUBLIC, &mut buf), Err(Error::NotFound));
    }

    #[test]
    fn memory_sizes() {
        use core::mem::size_of;
        let entry = size_of::<Option<(AttributeKey, ValueRef<'static>)>>();
        let registry = size_of::<Registry<'static>>();

        println!("AccessMask                  = {} B", size_of::<AccessMask>());
        println!("Access                      = {} B", size_of::<Access>());
        println!("AttributeKey                = {} B", size_of::<AttributeKey>());
        println!("ValueRef<'static>           = {} B", size_of::<ValueRef<'static>>());
        println!("entry Option<(key, ValueRef)> = {} B", entry);
        println!("Registry<'static>           = {} B ({} slots)", registry, MAX_ATTRS);
        println!("Server<'static>             = {} B", size_of::<Server<'static>>());
        println!("registry per 1000 attrs     = {} B ~ {} KB", entry * 1000, entry * 1000 / 1024);
    }
}



