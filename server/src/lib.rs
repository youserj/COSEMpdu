//! Minimal DLMS/COSEM server (attribute registry + object catalog).
//!
//! Attributes are described by the ROM [`AttrDesc`] descriptor table (key = OBIS +
//! attribute number, [`Access`] rights, value storage kind
//! [`AttrKind`]). Values are stored separately: read-only in `static` (ROM),
//! mutable in RAM slots. The COSEM object catalog ([`InterfaceClass`])
//! is stored as a `static` slice for validating `class_id` + OBIS. No heap
//! is used (no-heap, ready for `no_std`).
//!
//! Connections are served by [`Session`] — a value with `rx`/`tx` buffers that
//! belongs to the caller (the connection task or [`Server::serve`]), not
//! to the server. So channel I/O does not require `&mut Server`: [`Server::on_connect`]
//! returns a `Session`, and [`Server::process_request`] processes an
//! already-read WPDU from `session.rx`.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
extern crate std;

use core::fmt;

use cosempdu::apdu::Conformance;
use cosempdu::apdu::{
    CosemAttributeDescriptor, DataAccessResult, GetDataResultWrite, GetResponse,
    InvokeIdAndPriority, DLMS_VERSION_NUMBER,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu::{
    ExceptionResponse, GetRequest, GetRequestNormal, ImplicitTagged, ServiceError_, SetRequest,
    SetRequestNormal, SetResponse, StateError,
};
use cosempdu::buffer::{ArrayBuffer, ByteBuffer};
use cosempdu::data::{Codec, Data};
use cosempdu::stream::{StreamDecoder, StreamSink};
use dlms1::ic::association_ln::{
    ATTR_ASSOCIATED_PARTNERS_ID, ATTR_SECRET, ATTR_SECURITY_SETUP_REFERENCE,
    ATTR_XDLMS_CONTEXT_INFO,
};
use dlms1::ic::security_setup::{ATTR_SECURITY_SUITE, ATTR_SERVER_SYSTEM_TITLE};
#[cfg(any(feature = "tcp", feature = "ble"))]
use dlms1::ic::SecuritySuite;
use dlms1::ic::{
    client_sap, AssociatedPartners, AssociationLn, AttributeAccessMode, AttributeKey, ClassId,
    DataObject, InterfaceClass, MethodAccessMode, SecuritySetup, XdlmsContextInfoValue,
};
use dlms1::obis::ObisCode;
use dlms1::{BitString, Enum, LongUnsigned, OctetString, OctetStringSized, Unsigned};
use static_cell::StaticCell;

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::{
    AARQapdu, ACSEApdu, AcseServiceProvider, AcseServiceUser, ApplicationContextName,
    AssociateSourceDiagnostic, AssociationResult, BerTagged, RLREapdu, ReleaseResponseReason,
    SystemTitle,
};

#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
use cosempdu::acse::AAREapdu;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::{AuthenticationValue, MechanismName};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu::{
    confirmed_service_error_tag, ConfirmedServiceError, Initiate, InitiateRequest,
    InitiateResponse, SnServiceError,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::ber::with_content;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::{Reader, WriteBuf};
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::x680::{Class, Tag, UniversalTag};

mod channel;
mod session;
mod transport;

pub use session::{AssociationState, DedicatedKey, Settings};

#[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
pub use session::CallingAeQualifier;

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use session::{Session, RX_BUF};

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use transport::{Media, TransportRef, MAX_APDU, TRANSPORT_OVERHEAD, WPDU_HEADER_LEN};

#[cfg(feature = "optical")]
pub use transport::{HdlcPool, HdlcState};

#[cfg(any(feature = "tcp", feature = "ble"))]
pub use transport::{Wrapper, WrapperPool, WRAPPER_VERSION};

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use channel::{Channel, Listener};

/// Manufacturer ID (3 octets).
pub const MAN_ID: [u8; 3] = *b"KPZ";

/// OBIS of the device logical name (LDN).
pub const LDN_OBIS: ObisCode = ObisCode::new(0, 0, 42, 0, 0, 255);

/// Device logical-name object (Data, class_id 1).
pub static LDN_OBJ: DataObject = DataObject::new(LDN_OBIS);

/// The server's server_SAP (shared by all associations).
pub const SERVER_SAP: u16 = 1;

/// Conformance block proposed by the server on association (same for all
/// Association LN associations).
pub const PROPOSED_CONFORMANCE: Conformance = Conformance([0x00, 0x7E, 0x1F]);

/// Maximum received xDLMS APDU size (server-max-receive-pdu-size),
/// matches `transport::MAX_APDU`.
pub const SERVER_MAX_RECEIVE_PDU_SIZE: u16 = 1024;

/// OBIS of the Association LN associations (public/reader/configurator): `0.0.40.0.n.255`.
pub const ASSOC_LN_PUBLIC_OBIS: ObisCode = ObisCode::new(0, 0, 40, 0, 1, 255);
pub const ASSOC_LN_READER_OBIS: ObisCode = ObisCode::new(0, 0, 40, 0, 2, 255);
pub const ASSOC_LN_CONFIGURATOR_OBIS: ObisCode = ObisCode::new(0, 0, 40, 0, 3, 255);

/// OBIS of the base Association LN association (`0.0.40.0.0.255`) — the current
/// association (pseudo-instance 0).
pub const ASSOC_LN_BASE_OBIS: ObisCode = ObisCode::new(0, 0, 40, 0, 0, 255);

/// Association LN associations (class_id 15) — one per client_SAP level.
/// `ASSOC_LN_BASE` (`0.0.40.0.0.255`) — the current association (alias, not real).
pub static ASSOC_LN_BASE: AssociationLn = AssociationLn::new(ASSOC_LN_BASE_OBIS);
pub static ASSOC_LN_PUBLIC: AssociationLn = AssociationLn::new(ASSOC_LN_PUBLIC_OBIS);
pub static ASSOC_LN_READER: AssociationLn = AssociationLn::new(ASSOC_LN_READER_OBIS);
pub static ASSOC_LN_CONFIGURATOR: AssociationLn = AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS);

/// OBIS of the Security setup object (class_id 64): `0.0.43.0.e.255` (e = 1, 2, …).
pub const SECURITY_SETUP_OBIS: ObisCode = ObisCode::new(0, 0, 43, 0, 1, 255);

/// Security setup object (class_id 64) — stores `security_suite` (attr 3) and
/// `server_system_title` (attr 5).
pub static SECURITY_SETUP_OBJ: SecuritySetup = SecuritySetup::new(SECURITY_SETUP_OBIS);

/// `security_setup_reference` (attr 9) of referencing associations: Security
/// setup OBIS as a 6-byte octet-string (one shared by all references).
pub static SECURITY_SETUP_REF: OctetStringSized<6> = OctetStringSized(SECURITY_SETUP_OBIS.bytes);

/// Default Security setup `security_suite` (attr 3): AES-GCM-128 (0).
pub static SECURITY_SUITE_VALUE: Enum = Enum(0);

/// Default `associated_partners_id` (attr 3): `{ client_SAP, server_SAP = 1 }`.
pub static ASSOC_PARTNERS_PUBLIC: AssociatedPartners =
    AssociatedPartners::new(client_sap::PUBLIC as i8, SERVER_SAP);
pub static ASSOC_PARTNERS_READER: AssociatedPartners =
    AssociatedPartners::new(client_sap::READER as i8, SERVER_SAP);
pub static ASSOC_PARTNERS_CONFIGURATOR: AssociatedPartners =
    AssociatedPartners::new(client_sap::CONFIGURATOR as i8, SERVER_SAP);

/// Default COSEM object catalog. The `(object, OBIS)` pairs are only for
/// compile-time sorting and do not make it into the runtime catalog.
pub const OBJECTS: &[(&'static dyn InterfaceClass, ObisCode)] = &[
    (&ASSOC_LN_BASE, ASSOC_LN_BASE.obis),
    (&ASSOC_LN_PUBLIC, ASSOC_LN_PUBLIC.obis),
    (&ASSOC_LN_READER, ASSOC_LN_READER.obis),
    (&ASSOC_LN_CONFIGURATOR, ASSOC_LN_CONFIGURATOR.obis),
    (&LDN_OBJ, LDN_OBJ.obis),
    (&SECURITY_SETUP_OBJ, SECURITY_SETUP_OBJ.obis),
];

/// Lexicographic OBIS comparison (6 bytes); equivalent to `Ord` derive on
/// [`ObisCode`] (derive is not `const`).
const fn obis_lt(a: ObisCode, b: ObisCode) -> bool {
    let mut i = 0;
    while i < 6 {
        if a.bytes[i] != b.bytes[i] {
            return a.bytes[i] < b.bytes[i];
        }
        i += 1;
    }
    false
}

/// Merge the default object catalog with the application objects, sort
/// by OBIS and return only the objects (compile-time; OBIS is dropped).
///
/// `TOTAL` is given explicitly (= `defaults.len() + app.len()`): const
/// generic arithmetic in an array length (`[_; N + M]`) is unstable on stable.
pub const fn merge_objects<const TOTAL: usize>(
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
) -> [&'static dyn InterfaceClass; TOTAL] {
    if defaults.len() + app.len() != TOTAL {
        panic!("merge_objects: TOTAL must equal defaults.len() + app.len()");
    }
    // First pair — used to initialize the array (defaults may be empty).
    let first = if defaults.len() > 0 {
        defaults[0]
    } else {
        app[0]
    };
    let mut pairs: [(&'static dyn InterfaceClass, ObisCode); TOTAL] = [first; TOTAL];
    let mut i = 0;
    while i < defaults.len() {
        pairs[i] = defaults[i];
        i += 1;
    }
    let mut j = 0;
    while j < app.len() {
        pairs[defaults.len() + j] = app[j];
        j += 1;
    }

    // Insertion sort by OBIS.
    let mut k = 1;
    while k < TOTAL {
        let mut m = k;
        while m > 0 && obis_lt(pairs[m].1, pairs[m - 1].1) {
            let t = pairs[m - 1];
            pairs[m - 1] = pairs[m];
            pairs[m] = t;
            m -= 1;
        }
        k += 1;
    }

    // Drop the OBIS: what remains is sorted pointers.
    let mut out: [&'static dyn InterfaceClass; TOTAL] = [pairs[0].0; TOTAL];
    let mut n = 0;
    while n < TOTAL {
        out[n] = pairs[n].0;
        n += 1;
    }
    out
}

/// Build the `(object, OBIS)` pair list for [`merge_objects`]. OBIS is read
/// from each object's public `.obis` field, so the pairs cannot diverge
/// from the object's real OBIS.
#[macro_export]
macro_rules! objects {
    ($($obj:ident),* $(,)?) => {
        [$((&$obj, $obj.obis)),*]
    };
}

/// Storage for the base LDN (mutable; initialized by [`init_ldn_base`]).
static LDN_BASE: StaticCell<OctetStringSized<16>> = StaticCell::new();

/// Initialize the base LDN with the default value
/// (3 bytes of [`MAN_ID`] + 13 zeros) and return a mutable reference.
pub fn init_ldn_base() -> &'static mut OctetStringSized<16> {
    LDN_BASE.init(OctetStringSized([
        MAN_ID[0], MAN_ID[1], MAN_ID[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]))
}

/// Storage for the server-system-title (mutable; initialized by
/// [`init_server_system_title`]).
static SERVER_SYSTEM_TITLE: StaticCell<OctetStringSized<8>> = StaticCell::new();

/// Initialize the server-system-title with the default value
/// (3 bytes of [`MAN_ID`] + 5 zeros) and return a mutable reference.
pub fn init_server_system_title() -> &'static mut OctetStringSized<8> {
    SERVER_SYSTEM_TITLE.init(OctetStringSized([
        MAN_ID[0], MAN_ID[1], MAN_ID[2], 0, 0, 0, 0, 0,
    ]))
}

/// Default LLS secrets (attr 7) of the associations (mutable; initialized
/// in [`init_mutable_defaults`] with the standard password [`DEFAULT_LLS_SECRET`]).
static ASSOC_SECRET_PUBLIC: StaticCell<OctetString<16>> = StaticCell::new();
static ASSOC_SECRET_READER: StaticCell<OctetString<16>> = StaticCell::new();
static ASSOC_SECRET_CONFIGURATOR: StaticCell<OctetString<16>> = StaticCell::new();

/// Default LLS password (the standard DLMS ABCDEFGH).
const DEFAULT_LLS_SECRET: &[u8] = b"ABCDEFGH";

/// Initialize the public association's LLS secret with the default value.
fn init_assoc_secret_public() -> &'static mut OctetString<16> {
    ASSOC_SECRET_PUBLIC.init(OctetString::new(DEFAULT_LLS_SECRET))
}

/// Initialize the reader association's LLS secret with the default value.
fn init_assoc_secret_reader() -> &'static mut OctetString<16> {
    ASSOC_SECRET_READER.init(OctetString::new(DEFAULT_LLS_SECRET))
}

/// Initialize the configurator association's LLS secret with the default value.
fn init_assoc_secret_configurator() -> &'static mut OctetString<16> {
    ASSOC_SECRET_CONFIGURATOR.init(OctetString::new(DEFAULT_LLS_SECRET))
}

/// Initialize the default RAM slots in `mutable`:
/// slot 0 — base LDN ([`init_ldn_base`]), slot 1 — server-system-title
/// Security setup ([`init_server_system_title`], attr 5), slots 2–4 — the
/// LLS secrets of the public/reader/configurator associations (attr 7).
///
/// Matches the default [`ATTRS`] spec (slot 0, server-system-title
/// slot 1 and secrets 2–4). The `mutable` array must contain at least 5 slots.
pub fn init_mutable_defaults(mutable: &mut [Option<&'static mut dyn Codec>]) {
    mutable[0] = Some(init_ldn_base());
    mutable[1] = Some(init_server_system_title());
    mutable[2] = Some(init_assoc_secret_public());
    mutable[3] = Some(init_assoc_secret_reader());
    mutable[4] = Some(init_assoc_secret_configurator());
}

/// Convert the session's dedicated key into an octet-string (`cyphering_info`).
fn dedicated_key_to_octet_string(key: DedicatedKey) -> OctetString<32> {
    match key {
        DedicatedKey::None => OctetString::new(&[]),
        #[cfg(feature = "aes128")]
        DedicatedKey::Aes128(k) => OctetString::new(&k),
        #[cfg(feature = "aes256")]
        DedicatedKey::Aes256(k) => OctetString::new(&k),
    }
}

/// Build the `xDLMS_context_info` value (Association LN, attr 5) from the current
/// association state. `conformance` is the negotiated value, `max_receive`/`dlms_version`
/// are server constants; `max_send` and `cyphering_info` reflect the active association.
fn build_xdlms_context_info(ctx: &Settings) -> XdlmsContextInfoValue {
    XdlmsContextInfoValue {
        conformance: BitString {
            bytes: ctx.conformance.0,
            bit_len: 24,
        },
        max_receive_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
        max_send_pdu_size: LongUnsigned(ctx.tx_max),
        dlms_version_number: Unsigned(DLMS_VERSION_NUMBER),
        cyphering_info: dedicated_key_to_octet_string(ctx.dedicated_key),
    }
}

/// Build the default `xDLMS_context_info` for a non-current Association LN
/// association (public/reader/configurator): there is no negotiated session, so
/// the value uses the server's proposed conformance, the server's PDU capability
/// for both receive and send, and no dedicated key.
fn build_default_xdlms_context_info() -> XdlmsContextInfoValue {
    XdlmsContextInfoValue {
        conformance: BitString {
            bytes: PROPOSED_CONFORMANCE.0,
            bit_len: 24,
        },
        max_receive_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
        max_send_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
        dlms_version_number: Unsigned(DLMS_VERSION_NUMBER),
        cyphering_info: OctetString::new(&[]),
    }
}

/// Transient HLS-handshake state: shared scratch for split signature
/// verification. One per process — the handshake is serialized; if the scratch is busy, the server
/// replies `rejected-transient`.
///
/// It does not go into the session's persistent RAM: the qualifier/CtoS/StoC live here
/// only during the handshake; after pass 3 the scratch is released.
#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
struct HlsHandshake {
    /// `true` — the scratch is busy (another session's check is in progress).
    busy: bool,
    /// Client challenge (CtoS) from `calling-authentication-value` (AARQ, pass 1).
    ctos: [u8; 16],
    /// Server challenge (StoC) sent in `responding-authentication-value` (pass 2).
    stoc: [u8; 16],
    /// Client certificate (calling-AE-qualifier).
    qualifier: CallingAeQualifier,
}

#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
static mut HLS_HANDSHAKE: HlsHandshake = HlsHandshake::new();

/// Sole holder of the mutable reference to the HLS scratch (sequential access).
#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
fn hls_handshake() -> &'static mut HlsHandshake {
    // SAFETY: fixed scratch memory; mutable access only through this
    // helper (no_std, sequential handshake).
    unsafe { &mut *core::ptr::addr_of_mut!(HLS_HANDSHAKE) }
}

#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
impl HlsHandshake {
    const fn new() -> Self {
        Self {
            busy: false,
            ctos: [0u8; 16],
            stoc: [0u8; 16],
            qualifier: CallingAeQualifier::None,
        }
    }
}

/// Server errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Object (OBIS) or attribute not found.
    NotFound,
    /// Attribute is not writable (Static/Dynamic).
    ReadOnly,
    /// COSEM PDU encoder/decoder error.
    Codec(cosempdu::Error),

    // ---------------------------------------------------------------------
    // Transport layer (used when an optical/tcp/ble channel is enabled)
    // ---------------------------------------------------------------------
    /// No free transport slot (channel pool is full).
    NoSlot,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound => write!(f, "object/attribute not found"),
            Error::ReadOnly => write!(f, "attribute is read-only"),
            Error::Codec(e) => write!(f, "{e}"),
            Error::NoSlot => write!(f, "no free transport slot"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<cosempdu::Error> for Error {
    fn from(e: cosempdu::Error) -> Self {
        Error::Codec(e)
    }
}

impl From<cosempdu::buffer::Error> for Error {
    fn from(e: cosempdu::buffer::Error) -> Self {
        Error::Codec(e.into())
    }
}

/// Attribute access rights — per level (client_SAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// Public-client access mode (SAP 0x10).
    pub public: AttributeAccessMode,
    /// Reader-client access mode (SAP 0x20).
    pub reader: AttributeAccessMode,
    /// Configurator-client access mode (SAP 0x30).
    pub configurator: AttributeAccessMode,
}

impl Access {
    /// Access mode for a given client_SAP.
    pub const fn for_sap(self, sap: u8) -> Option<AttributeAccessMode> {
        Some(match sap {
            client_sap::PUBLIC => self.public,
            client_sap::READER => self.reader,
            client_sap::CONFIGURATOR => self.configurator,
            _ => return None,
        })
    }

    /// Whether reading (GET) is allowed for the context.
    pub fn can_read(self, settings: &Settings) -> bool {
        matches!(self.for_sap(settings.client_sap), Some(m) if m.can_read(settings.authenticated))
    }

    /// Whether writing (SET) is allowed for the context.
    pub fn can_write(self, settings: &Settings) -> bool {
        matches!(self.for_sap(settings.client_sap), Some(m) if m.can_write(settings.authenticated))
    }
}

/// Object method invocation rights — per level (client_SAP).
///
/// Methods are not tied to attributes: method access is checked separately
/// (for future Action-Request dispatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodAccess {
    /// Public-client invocation mode (SAP 0x10).
    pub public: MethodAccessMode,
    /// Reader-client invocation mode (SAP 0x20).
    pub reader: MethodAccessMode,
    /// Configurator-client invocation mode (SAP 0x30).
    pub configurator: MethodAccessMode,
}

impl MethodAccess {
    /// Invocation mode for a given client_SAP.
    pub const fn for_sap(self, sap: u8) -> Option<MethodAccessMode> {
        Some(match sap {
            client_sap::PUBLIC => self.public,
            client_sap::READER => self.reader,
            client_sap::CONFIGURATOR => self.configurator,
            _ => return None,
        })
    }

    /// Whether method invocation (ACTION) is allowed for the context.
    pub fn can_call(self, settings: &Settings) -> bool {
        matches!(self.for_sap(settings.client_sap), Some(m) if m.can_call(settings.authenticated))
    }
}

/// Object method handler (Action-Request).
///
/// Wire-level Action-Request dispatch is not implemented yet: `cosempdu`
/// has no `ActionRequest`/`ActionResponse` APDU yet (follow-up).
pub type MethodHandler = fn(&mut Server, &Data<'_>, &mut ByteBuffer<'_>) -> Result<usize, Error>;

/// Method key in the ROM registry: object index in the catalog + method number.
///
/// OBIS is not stored (it is already in the object) — like [`AttrKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodKey {
    /// Object index in the OBIS-sorted catalog.
    pub object: u16,
    /// Method number (method_id).
    pub method_id: u8,
}

/// Object method descriptor: rights + handler (a method-registry entry).
#[derive(Clone, Copy)]
pub struct MethodDesc {
    /// Method key (object index + method number).
    pub key: MethodKey,
    /// Method invocation rights per level.
    pub access: MethodAccess,
    /// Request handler.
    pub handler: MethodHandler,
}

/// How an attribute value is stored and changed.
///
/// Attribute descriptors live in ROM (a `static` array sorted by
/// key). RAM keeps only the mutable-pointer table
/// (`&mut dyn Codec`), indexed by the `u16` slot from [`AttrKind`].
#[derive(Clone, Copy)]
pub enum AttrKind {
    /// Read-only value: the pointer sits right in the ROM descriptor.
    Static(&'static dyn Codec),
    /// Changed only by the server (`update`): slot index in the RAM table.
    Dynamic(u16),
    /// Changed externally via SET (NVM): slot index in the RAM table.
    Persistent(u16),
    /// Not stored; computed on GET (marker, the value is built in `lookup_value`).
    Computed,
}

impl core::fmt::Debug for AttrKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AttrKind::Static(_) => write!(f, "Static(dyn Codec)"),
            AttrKind::Dynamic(slot) => write!(f, "Dynamic({slot})"),
            AttrKind::Persistent(slot) => write!(f, "Persistent({slot})"),
            AttrKind::Computed => write!(f, "Computed"),
        }
    }
}

/// Value storage kind in the ROM descriptor (all variants are a `u16` slot).
///
/// `Static` points into the ROM codec array, `Dynamic`/`Persistent` into the RAM
/// mutable-pointer array. More compact than [`AttrKind`]: no fat-ptr for Static.
#[derive(Debug, Clone, Copy)]
pub enum RomKind {
    /// Read-only value: slot in the ROM codec array.
    Static(u16),
    /// Changed only by the server: slot in the RAM array.
    Dynamic(u16),
    /// Changed externally via SET (NVM): slot in the RAM array.
    Persistent(u16),
    /// Not stored; computed on GET (marker).
    Computed,
}

/// Attribute key in the ROM registry: object index in the catalog + attribute number.
///
/// OBIS is not stored — it is already in the object; here only the which-object
/// (index in the sorted catalog) + which-attribute link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttrKey {
    /// Object index in the OBIS-sorted catalog.
    pub object: u16,
    /// Attribute number.
    pub attribute_id: u8,
}

/// Attribute spec for [`merge_attrs`] (compile-time input): OBIS key +
/// rights + storage kind. OBIS is resolved to the object index and does not reach ROM.
#[derive(Debug, Clone, Copy)]
pub struct AttrSpec {
    /// Attribute key (OBIS + attribute number).
    pub key: AttributeKey,
    /// Access rights (read/write per level).
    pub access: Access,
    /// Value storage kind.
    pub kind: AttrKind,
}

/// ROM descriptor of one attribute: key + access rights + storage kind.
///
/// The descriptor array must be sorted by [`AttrDesc::key`]
/// (a compile-time invariant) — binary search relies on it.
#[derive(Debug, Clone, Copy)]
pub struct AttrDesc {
    /// Attribute key (object index + attribute number).
    pub key: AttrKey,
    /// Access rights (read/write per level).
    pub access: Access,
    /// Value storage kind.
    pub kind: RomKind,
}

/// Read-only for all client_SAP levels.
const RO: Access = Access {
    public: AttributeAccessMode::ReadOnly,
    reader: AttributeAccessMode::ReadOnly,
    configurator: AttributeAccessMode::ReadOnly,
};

/// `secret` (attr 7) rights: read forbidden for everyone, write — only configurator
/// (client_SAP 0x30).
const SECRET_ACCESS: Access = Access {
    public: AttributeAccessMode::NoAccess,
    reader: AttributeAccessMode::NoAccess,
    configurator: AttributeAccessMode::WriteOnly,
};

/// Default LDN attribute descriptor (value, attr 2):
/// read-only for all levels, slot 0.
pub const LDN_ATTR_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(LDN_OBIS, 2),
    access: RO,
    kind: AttrKind::Dynamic(0),
};

/// `associated_partners_id` (attr 3) of the public association (Static, read-only).
pub const ASSOC_LN_PUBLIC_ATTR_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_PUBLIC_OBIS, ATTR_ASSOCIATED_PARTNERS_ID),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_PUBLIC),
};

/// `associated_partners_id` (attr 3) of the reader association (Static, read-only).
pub const ASSOC_LN_READER_ATTR_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_READER_OBIS, ATTR_ASSOCIATED_PARTNERS_ID),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_READER),
};

/// `associated_partners_id` (attr 3) of the configurator association (Static, read-only).
pub const ASSOC_LN_CONFIGURATOR_ATTR_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_CONFIGURATOR_OBIS, ATTR_ASSOCIATED_PARTNERS_ID),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_CONFIGURATOR),
};

/// `secret` (attr 7) of the public association (Persistent, slot 2; write — configurator).
pub const ASSOC_LN_PUBLIC_SECRET_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_PUBLIC_OBIS, ATTR_SECRET),
    access: SECRET_ACCESS,
    kind: AttrKind::Persistent(2),
};

/// `secret` (attr 7) of the reader association (Persistent, slot 3; write — configurator).
pub const ASSOC_LN_READER_SECRET_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_READER_OBIS, ATTR_SECRET),
    access: SECRET_ACCESS,
    kind: AttrKind::Persistent(3),
};

/// `secret` (attr 7) of the configurator association (Persistent, slot 4; write — configurator).
pub const ASSOC_LN_CONFIGURATOR_SECRET_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_CONFIGURATOR_OBIS, ATTR_SECRET),
    access: SECRET_ACCESS,
    kind: AttrKind::Persistent(4),
};

/// `security_setup_reference` (attr 9) of the configurator association (Static, read-only):
/// the Security setup object's OBIS (`0.0.43.0.1.255`). LLS associations (reader) have no
/// such reference — their `security_suite` stays default (unused).
pub const ASSOC_LN_CONFIGURATOR_SECURITY_SETUP_REF_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_CONFIGURATOR_OBIS, ATTR_SECURITY_SETUP_REFERENCE),
    access: RO,
    kind: AttrKind::Static(&SECURITY_SETUP_REF),
};

/// `security_suite` (attr 3) Security setup (Static, read-only).
pub const SECURITY_SETUP_SUITE_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(SECURITY_SETUP_OBIS, ATTR_SECURITY_SUITE),
    access: RO,
    kind: AttrKind::Static(&SECURITY_SUITE_VALUE),
};

/// `server_system_title` (attr 5) of Security setup (Dynamic, slot 1).
pub const SECURITY_SETUP_SYSTEM_TITLE_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(SECURITY_SETUP_OBIS, ATTR_SERVER_SYSTEM_TITLE),
    access: Access {
        public: AttributeAccessMode::ReadOnly,
        reader: AttributeAccessMode::NoAccess,
        configurator: AttributeAccessMode::WriteOnly,
    },
    kind: AttrKind::Dynamic(1),
};

/// `xDLMS_context_info` (attr 5) of the public association (Computed — on the fly).
pub const ASSOC_LN_PUBLIC_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_PUBLIC_OBIS, ATTR_XDLMS_CONTEXT_INFO),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the reader association (Computed — on the fly).
pub const ASSOC_LN_READER_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_READER_OBIS, ATTR_XDLMS_CONTEXT_INFO),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the configurator association (Computed — on the fly).
pub const ASSOC_LN_CONFIGURATOR_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_CONFIGURATOR_OBIS, ATTR_XDLMS_CONTEXT_INFO),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the base association (`0.0.40.0.0.255`) —
/// always available (alias of the current association).
pub const ASSOC_LN_BASE_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(ASSOC_LN_BASE_OBIS, ATTR_XDLMS_CONTEXT_INFO),
    access: RO,
    kind: AttrKind::Computed,
};

/// Default attribute registry.
pub const ATTRS: &[AttrSpec] = &[
    LDN_ATTR_DESC,
    ASSOC_LN_PUBLIC_ATTR_DESC,
    ASSOC_LN_READER_ATTR_DESC,
    ASSOC_LN_CONFIGURATOR_ATTR_DESC,
    ASSOC_LN_PUBLIC_SECRET_DESC,
    ASSOC_LN_READER_SECRET_DESC,
    ASSOC_LN_CONFIGURATOR_SECRET_DESC,
    ASSOC_LN_CONFIGURATOR_SECURITY_SETUP_REF_DESC,
    ASSOC_LN_BASE_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_PUBLIC_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_READER_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_CONFIGURATOR_XDLMS_CONTEXT_INFO_DESC,
    SECURITY_SETUP_SUITE_DESC,
    SECURITY_SETUP_SYSTEM_TITLE_DESC,
];

/// Lexicographic key comparison (object index + attribute number);
/// equivalent to `Ord` derive on [`AttrKey`] (derive is not `const`).
const fn attr_key_lt(a: AttrKey, b: AttrKey) -> bool {
    a.object < b.object || (a.object == b.object && a.attribute_id < b.attribute_id)
}

/// OBIS equality (6 bytes).
const fn obis_eq(a: ObisCode, b: ObisCode) -> bool {
    let mut i = 0;
    while i < 6 {
        if a.bytes[i] != b.bytes[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Object index in the OBIS-sorted catalog: the number of objects with a smaller OBIS.
/// Panics at compile time if OBIS is not found in the catalog.
const fn object_rank(
    obis: ObisCode,
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
) -> u16 {
    let mut rank = 0u16;
    let mut found = false;
    let mut i = 0;
    while i < defaults.len() {
        if obis_lt(defaults[i].1, obis) {
            rank += 1;
        }
        if obis_eq(defaults[i].1, obis) {
            found = true;
        }
        i += 1;
    }
    let mut j = 0;
    while j < app.len() {
        if obis_lt(app[j].1, obis) {
            rank += 1;
        }
        if obis_eq(app[j].1, obis) {
            found = true;
        }
        j += 1;
    }
    if !found {
        panic!("merge_attrs: attribute OBIS is not in the object catalog");
    }
    rank
}

/// Transient resolved attribute (compile-time only): the key already has the
/// object index, `kind` — still with the codec for Static.
#[derive(Clone, Copy)]
struct ResolvedAttr {
    key: AttrKey,
    access: Access,
    kind: AttrKind,
}

/// Resolve an attribute spec: OBIS → object index (transiently).
const fn resolve_spec(
    spec: AttrSpec,
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
) -> ResolvedAttr {
    ResolvedAttr {
        key: AttrKey {
            object: object_rank(spec.key.obis, defaults, app),
            attribute_id: spec.key.attribute_id,
        },
        access: spec.access,
        kind: spec.kind,
    }
}

/// Merge the default attributes with the application attributes: resolve OBIS to
/// the object index, replace the Static codec with a slot and sort (compile-time).
///
/// `TOTAL` is given explicitly (= `default_attrs.len() + app_attrs.len()`). Static slots
/// are numbered in spec order and point into the array from [`merge_codecs`].
pub const fn merge_attrs<const TOTAL: usize>(
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
    default_attrs: &[AttrSpec],
    app_attrs: &[AttrSpec],
) -> [AttrDesc; TOTAL] {
    if default_attrs.len() + app_attrs.len() != TOTAL {
        panic!("merge_attrs: TOTAL must equal default_attrs.len() + app_attrs.len()");
    }

    // 1) Resolve specs (order: defaults, then app).
    let first_resolved = if default_attrs.len() > 0 {
        resolve_spec(default_attrs[0], defaults, app)
    } else {
        resolve_spec(app_attrs[0], defaults, app)
    };
    let mut resolved: [ResolvedAttr; TOTAL] = [first_resolved; TOTAL];
    let mut i = 0;
    while i < default_attrs.len() {
        resolved[i] = resolve_spec(default_attrs[i], defaults, app);
        i += 1;
    }
    let mut j = 0;
    while j < app_attrs.len() {
        resolved[default_attrs.len() + j] = resolve_spec(app_attrs[j], defaults, app);
        j += 1;
    }

    // 2) AttrKind → RomKind: the Static codec is replaced with a slot (in spec order).
    let first_kind = match resolved[0].kind {
        AttrKind::Static(_) => RomKind::Static(0),
        AttrKind::Dynamic(s) => RomKind::Dynamic(s),
        AttrKind::Persistent(s) => RomKind::Persistent(s),
        AttrKind::Computed => RomKind::Computed,
    };
    let mut out: [AttrDesc; TOTAL] = [AttrDesc {
        key: resolved[0].key,
        access: resolved[0].access,
        kind: first_kind,
    }; TOTAL];
    let mut static_slot = 0u16;
    let mut n = 0;
    while n < TOTAL {
        let r = resolved[n];
        let kind = match r.kind {
            AttrKind::Static(_) => {
                let s = static_slot;
                static_slot += 1;
                RomKind::Static(s)
            }
            AttrKind::Dynamic(s) => RomKind::Dynamic(s),
            AttrKind::Persistent(s) => RomKind::Persistent(s),
            AttrKind::Computed => RomKind::Computed,
        };
        out[n] = AttrDesc {
            key: r.key,
            access: r.access,
            kind,
        };
        n += 1;
    }

    // 3) Insertion sort by key.
    let mut k = 1;
    while k < TOTAL {
        let mut m = k;
        while m > 0 && attr_key_lt(out[m].key, out[m - 1].key) {
            let t = out[m - 1];
            out[m - 1] = out[m];
            out[m] = t;
            m -= 1;
        }
        k += 1;
    }
    out
}

/// First Static codec (to initialize the array in [`merge_codecs`]).
const fn first_static_codec(
    default_attrs: &[AttrSpec],
    app_attrs: &[AttrSpec],
) -> &'static dyn Codec {
    let mut i = 0;
    while i < default_attrs.len() {
        match default_attrs[i].kind {
            AttrKind::Static(c) => return c,
            _ => {}
        }
        i += 1;
    }
    let mut j = 0;
    while j < app_attrs.len() {
        match app_attrs[j].kind {
            AttrKind::Static(c) => return c,
            _ => {}
        }
        j += 1;
    }
    panic!("merge_codecs: no static codec found");
}

/// Collect the ROM codec array for Static attributes (in spec order —
/// the [`RomKind::Static`] slots from [`merge_attrs`] point to these positions).
///
/// `STATIC_TOTAL` must be > 0; for a server without Static attributes pass `&[]`.
pub const fn merge_codecs<const STATIC_TOTAL: usize>(
    default_attrs: &[AttrSpec],
    app_attrs: &[AttrSpec],
) -> [&'static dyn Codec; STATIC_TOTAL] {
    let first = first_static_codec(default_attrs, app_attrs);
    let mut out: [&'static dyn Codec; STATIC_TOTAL] = [first; STATIC_TOTAL];
    let mut s = 0usize;
    let mut i = 0;
    while i < default_attrs.len() {
        match default_attrs[i].kind {
            AttrKind::Static(c) => {
                out[s] = c;
                s += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let mut j = 0;
    while j < app_attrs.len() {
        match app_attrs[j].kind {
            AttrKind::Static(c) => {
                out[s] = c;
                s += 1;
            }
            _ => {}
        }
        j += 1;
    }
    out
}

/// Non-volatile memory backend (flash/EEPROM) for `Persistent` attributes.
///
/// The `server` crate is hardware-agnostic — the implementation is provided by
/// the application.
pub trait Nvm {
    fn load(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Error>;
    fn save(&mut self, offset: usize, buf: &[u8]) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
}

/// COSEM server: object catalog + attribute registry + the proposed
/// capability negotiation (conformance).
pub struct Server<const N: usize = 3> {
    /// ROM: object catalog sorted by OBIS (for binary search).
    objects: &'static [&'static dyn InterfaceClass],
    /// ROM: sorted attribute catalog (key + rights + storage kind).
    attrs: &'static [AttrDesc],
    /// ROM: codec array for Static attributes (slot from [`RomKind::Static`]).
    codecs: &'static [&'static dyn Codec],
    /// RAM: mutable-value slots (index — the `u16` slot from [`RomKind`]).
    mutable: &'static mut [Option<&'static mut dyn Codec>],
    #[cfg(feature = "optical")]
    optical_pool: HdlcPool<N>,
    #[cfg(feature = "tcp")]
    tcp_pool: WrapperPool<N>,
    #[cfg(feature = "ble")]
    ble_pool: WrapperPool<N>,
}

/// Attribute value for GET: either a reference to a stored value or an
/// on-the-fly computed value (`xDLMS_context_info` Association LN, attr 5).
///
/// Needed so `Server::lookup_value` is the single dispatch point over
/// [`RomKind`]: `Computed` has no stored `&dyn Codec` (the value is owned and
/// built per-request), so `GetValue::Computed` carries it by value.
pub enum GetValue<'a> {
    /// Stored value (Static/Dynamic/Persistent).
    Codec(&'a dyn Codec),
    /// Computed value (`xDLMS_context_info`).
    Computed(XdlmsContextInfoValue),
}

impl Codec for GetValue<'_> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        match self {
            GetValue::Codec(c) => c.put(buf),
            GetValue::Computed(v) => v.put(buf),
        }
    }

    fn assign(&mut self, _: &Data<'_>) -> cosempdu::Result<()> {
        Err(cosempdu::Error::Message("attribute is read-only"))
    }
}

impl<const N: usize> Server<N> {
    /// Create a server with a COSEM object catalog, a ROM attribute table,
    /// RAM slots for mutable values and `N` sessions.
    pub fn with_capacity(
        objects: &'static [&'static dyn InterfaceClass],
        attrs: &'static [AttrDesc],
        codecs: &'static [&'static dyn Codec],
        mutable: &'static mut [Option<&'static mut dyn Codec>],
    ) -> Self {
        Server {
            objects,
            attrs,
            codecs,
            mutable,
            #[cfg(feature = "optical")]
            optical_pool: HdlcPool::<N>::new(),
            #[cfg(feature = "tcp")]
            tcp_pool: WrapperPool::<N>::new(0), // own wPort — set via Server::set_wport
            #[cfg(feature = "ble")]
            ble_pool: WrapperPool::<N>::new(0), // own wPort — set via Server::set_ble_port
        }
    }

    /// Set the server's own wPort for the TCP channel (before accepting connections).
    #[cfg(feature = "tcp")]
    pub fn set_wport(&mut self, port: u16) {
        self.tcp_pool.set_source_port(port);
    }

    /// Set the server's own wPort for the BLE channel (before accepting connections).
    #[cfg(feature = "ble")]
    pub fn set_ble_port(&mut self, port: u16) {
        self.ble_pool.set_source_port(port);
    }

    /// Object index in the OBIS-sorted catalog (binary search).
    fn object_index(&self, obis: &ObisCode) -> Option<u16> {
        self.objects
            .binary_search_by_key(obis, |o| o.obis())
            .ok()
            .map(|i| i as u16)
    }

    /// Find an object by OBIS, check `class_id` and return `(index, object)`.
    ///
    /// The catalog is sorted by OBIS ([`merge_objects`]) — binary search.
    fn find_object(
        &self,
        class_id: ClassId,
        obis: &ObisCode,
    ) -> Result<(u16, &'static dyn InterfaceClass), DataAccessResult> {
        let idx = self
            .objects
            .binary_search_by_key(obis, |o| o.obis())
            .ok()
            .ok_or(DataAccessResult::ObjectUnavailable)?;
        let obj = self.objects[idx];
        if obj.class_id() != class_id {
            return Err(DataAccessResult::ObjectClassInconsistent);
        }
        Ok((idx as u16, obj))
    }

    /// Return all catalog objects of a concrete type `T` as an iterator
    /// ([`InterfaceClass`] descriptors are `Copy`). Empty if there are no such objects.
    pub fn get_objects<T: InterfaceClass + Copy>(&self) -> impl Iterator<Item = T> + '_ {
        self.objects
            .iter()
            .filter_map(|o| o.as_any().downcast_ref::<T>())
            .copied()
    }

    /// The current server-system-title (raw bytes) from slot 1 of the RAM table.
    fn system_title(&self) -> Option<&[u8]> {
        self.mutable
            .get(1)
            .and_then(|slot| slot.as_deref())
            .and_then(|codec| codec.octet_string())
    }

    /// Binary search of an attribute descriptor by key `(object index, number)`.
    fn attr(&self, object: u16, attribute_id: u8) -> Option<AttrDesc> {
        let key = AttrKey {
            object,
            attribute_id,
        };
        self.attrs
            .binary_search_by_key(&key, |d| d.key)
            .ok()
            .map(|i| self.attrs[i])
    }

    /// Attribute value by `(assoc_idx, attribute_id)` as `&dyn Codec` without
    /// access-checking — for reading Association LN service attributes
    /// during AARQ.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn attr_codec(&self, assoc_idx: u8, attribute_id: u8) -> Option<&dyn Codec> {
        let desc = self.attr(assoc_idx as u16, attribute_id)?;
        match desc.kind {
            RomKind::Static(slot) => Some(self.codecs[slot as usize]),
            RomKind::Dynamic(slot) | RomKind::Persistent(slot) => {
                self.mutable[slot as usize].as_deref()
            }
            RomKind::Computed => None,
        }
    }

    /// `security_suite` of the chosen association: reads `security_setup_reference`
    /// (attr 9) of the association, finds the Security setup object (class_id 64)
    /// in the catalog by it and reads its `security_suite` (attr 3).
    ///
    /// `None` if the reference is absent (e.g. an LLS association) or the chain
    /// does not resolve — the caller keeps the default `SecuritySuite::AesGcm128`.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn security_suite(&self, assoc_idx: u8) -> Option<SecuritySuite> {
        let obis_bytes = self
            .attr_codec(assoc_idx, ATTR_SECURITY_SETUP_REFERENCE)?
            .octet_string()?;
        let obis = ObisCode::from_logical_name(obis_bytes).ok()?;
        let (idx, _) = self.find_object(ClassId::SecuritySetup, &obis).ok()?;
        let value = self
            .attr_codec(idx as u8, ATTR_SECURITY_SUITE)?
            .enum_value()?;
        SecuritySuite::from_u8(value)
    }

    /// Handle a `Get-Request` (only `Normal` without `access_selection`) and
    /// write the `Get-Response` into `buf`.
    ///
    /// `invoke` + `descriptor` — already-decoded owned fields (`Copy`), so
    /// the caller does not hold a borrow on the receive buffer. Returns the number
    /// of bytes written. A data-access error goes into the `Get-Response` as
    /// `DataAccessError`, not aborting the processing.
    // TODO: support `Next` / `WithList` and `access_selection`.
    pub fn handle_get(
        &self,
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        ctx: &Settings,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize, Error> {
        // Fetch the value; the Data-Access-Result goes into the Get-Response (DataAccessError).
        let value = self.lookup_value(descriptor, ctx);
        let result = match &value {
            Ok(v) => GetDataResultWrite::Data(v),
            Err(code) => GetDataResultWrite::DataAccessError(*code),
        };
        let start = buf.pos();
        GetResponse::put_normal(invoke, result, buf)?;
        Ok(buf.pos() - start)
    }

    /// OBIS of the association object by its catalog index (for computed attributes).
    fn assoc_obis(&self, assoc_idx: u8) -> Option<ObisCode> {
        self.objects.get(assoc_idx as usize).map(|o| o.obis())
    }

    /// Parse the descriptor (`class_id` + OBIS + `attribute_id`) and find the value
    /// for GET (after checking `class_id` and read access): a stored `&dyn Codec`
    /// or a computed [`GetValue::Computed`].
    fn lookup_value(
        &self,
        descriptor: CosemAttributeDescriptor,
        ctx: &Settings,
    ) -> Result<GetValue<'_>, DataAccessResult> {
        let class_id = ClassId::from_u16(descriptor.class_id)
            .ok_or(DataAccessResult::ObjectClassInconsistent)?;
        let obis = ObisCode::from_bytes(descriptor.instance_id);
        let attribute_id = descriptor.attribute_id as u8;

        let (index, _) = self.find_object(class_id, &obis)?;
        let desc = self
            .attr(index, attribute_id)
            .ok_or(DataAccessResult::ReadWriteDenied)?;
        if !desc.access.can_read(ctx) {
            return Err(DataAccessResult::ScopeOfAccessViolated);
        }
        match desc.kind {
            RomKind::Static(slot) => Ok(GetValue::Codec(self.codecs[slot as usize])),
            RomKind::Dynamic(slot) | RomKind::Persistent(slot) => self.mutable[slot as usize]
                .as_deref()
                .map(GetValue::Codec)
                .ok_or(DataAccessResult::ReadWriteDenied),
            // Computed value (`xDLMS_context_info`): O(1) match. The base OBIS
            // and the current association's OBIS use the negotiated session
            // parameters; any other Association LN association (public/reader/
            // configurator) has no negotiated parameters and falls back to the
            // server defaults.
            RomKind::Computed => match (class_id, attribute_id, obis) {
                (ClassId::AssociationLn, ATTR_XDLMS_CONTEXT_INFO, o)
                    if o == ASSOC_LN_BASE_OBIS || Some(o) == self.assoc_obis(ctx.assoc_idx) =>
                {
                    Ok(GetValue::Computed(build_xdlms_context_info(ctx)))
                }
                (ClassId::AssociationLn, ATTR_XDLMS_CONTEXT_INFO, _) => {
                    Ok(GetValue::Computed(build_default_xdlms_context_info()))
                }
                _ => Err(DataAccessResult::ReadWriteDenied),
            },
        }
    }

    /// Streaming (external) SET: begin receiving a segmented value that is
    /// decoded directly into the attribute. Returns a handle for feeding blocks.
    pub fn stream_set<'s>(
        &'s mut self,
        class_id: ClassId,
        key: AttributeKey,
        ctx: &Settings,
    ) -> Result<StreamingSet<'s>, DataAccessResult> {
        let (index, _) = self.find_object(class_id, &key.obis)?;
        let desc = self
            .attr(index, key.attribute_id)
            .ok_or(DataAccessResult::ObjectUndefined)?;
        match desc.kind {
            RomKind::Persistent(slot) => {
                if !desc.access.can_write(ctx) {
                    return Err(DataAccessResult::ScopeOfAccessViolated);
                }
                let codec = self.mutable[slot as usize]
                    .as_deref_mut()
                    .ok_or(DataAccessResult::ReadWriteDenied)?;
                let sink = codec
                    .stream_sink()
                    .ok_or_else(|| DataAccessResult::HardwareFault)?;
                Ok(StreamingSet {
                    decoder: StreamDecoder::new(sink),
                })
            }
            RomKind::Static(_) | RomKind::Dynamic(_) | RomKind::Computed => {
                Err(DataAccessResult::ReadWriteDenied)
            }
        }
    }

    /// Internal `Dynamic`-attribute update (no level or class_id checks).
    pub fn update(&mut self, key: AttributeKey, data: &Data<'_>) -> Result<(), Error> {
        let index = self.object_index(&key.obis).ok_or(Error::NotFound)?;
        let desc = self.attr(index, key.attribute_id).ok_or(Error::NotFound)?;
        match desc.kind {
            RomKind::Dynamic(slot) => {
                let codec = self.mutable[slot as usize]
                    .as_deref_mut()
                    .ok_or(Error::NotFound)?;
                codec.assign(data)?;
                Ok(())
            }
            RomKind::Static(_) | RomKind::Persistent(_) | RomKind::Computed => Err(Error::ReadOnly),
        }
    }

    /// Number of concurrent sessions the server supports.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Create a session for a new connection: takes a transport slot and
    /// returns a [`Session`]. The session (with `rx`/`tx` buffers) belongs
    /// to the caller, so channel I/O does not require `&mut Server`.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_connect(&mut self, media: Media) -> Result<Session, Error> {
        let transport_ref = match media {
            #[cfg(feature = "optical")]
            Media::Optical => {
                self.optical_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Hdlc(HdlcState::new())
            }
            #[cfg(feature = "tcp")]
            Media::Tcp => {
                self.tcp_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(Wrapper::new(self.tcp_pool.source_port(), 0))
            }
            #[cfg(feature = "ble")]
            Media::Ble => {
                self.ble_pool.alloc().ok_or(Error::NoSlot)?;
                TransportRef::Wrapper(Wrapper::new(self.ble_pool.source_port(), 0))
            }
        };
        Ok(Session::new(media, transport_ref))
    }

    /// Release the transport slot when the connection closes.
    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    pub fn on_disconnect(&mut self, media: Media) {
        self.release(media);
    }

    /// Serve one connection: on_connect → association → a loop of
    /// Get-requests → on_disconnect.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub async fn serve<C: Channel<Frame = Wrapper>>(
        &mut self,
        media: Media,
        mut channel: C,
    ) -> Result<(), Error> {
        let mut session = self.on_connect(media)?;

        // Serving loop: AARQ/AARE, GET/SET, RLRQ — all through process_request.
        // Exit on RLRQ (state = Disconnecting)/timeout/close/error.
        let result = loop {
            if let Err(e) = self.handle_request(&mut session, &mut channel).await {
                break Err(e);
            }
            if session.settings.state == AssociationState::Disconnecting {
                break Ok(());
            }
        };

        // Always release the slot: on success as well as on timeout/error.
        self.on_disconnect(session.media());
        result
    }

    /// Process one already-read WPDU (AARQ, an xDLMS request or RLRQ) from
    /// `session.rx` and build the response WPDU right in `session.tx`.
    /// Performs no network I/O.
    ///
    /// Association release (RLRQ) is reflected in `session.settings.state`
    /// (`Disconnecting`) — the caller uses it to decide whether to continue the loop.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    pub fn process_request(
        &mut self,
        settings: &mut Settings,
        transport_ref: &mut TransportRef,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
        received: Wrapper,
    ) -> Result<bool, Error> {
        // Dispatch by APDU tag (class, number, constructed) + state.
        let tag = {
            let mut r = Reader::new(rx.extract());
            Tag::get(&mut r)?
        };
        // WPDU validation + response wrapper (for all requests).
        let source_port = received.source_port();
        let wrapper = validate_wrapper(transport_ref, received)?;
        *transport_ref = TransportRef::Wrapper(wrapper);
        tx.set_pos(WPDU_HEADER_LEN)?; // space for the 8-byte WPDU header (backed up below)
                                      // The response is always written to tx; `send` decides whether to hand it to the client
                                      // (only an AARQ with response_allowed=false suppresses sending).
        let mut send = true;
        let apdu_len = match (tag.class, tag.number, tag.constructed, settings.state) {
            // ACSE: AARQ = [APPLICATION 0] IMPLICIT SEQUENCE.
            (Class::Application, 0, true, AssociationState::Idle) => {
                let (n, response_allowed) = self.process_aarq(settings, rx, tx, source_port)?;
                send = response_allowed;
                n
            }
            (Class::Application, 0, true, _) => build_association_not_established(tx)?,
            // ACSE: RLRQ = [APPLICATION 2] IMPLICIT SEQUENCE.
            (Class::Application, 2, true, _) => handle_release(settings, rx, tx)?,
            // xDLMS: Get-Request = [192] IMPLICIT CHOICE (association established).
            (Class::Private, 0, false, AssociationState::Associated) => {
                self.process_get(settings, rx, tx)?
            }
            // xDLMS: Set-Request = [193] IMPLICIT CHOICE (association established).
            (Class::Private, 1, false, AssociationState::Associated) => {
                self.process_set(settings, rx, tx)?
            }
            // GET/SET without an established association → "Association is not established".
            (Class::Private, 0 | 1, false, _) => build_association_not_established(tx)?,
            // Table 89. Request is not well formed
            _ => build_exception_response(tx)?,
        };

        // Back up the 8-byte WPDU header at the start of tx.
        tx.write_at(&wrapper.header_bytes(apdu_len as u16), 0)?;
        Ok(send)
    }

    /// AARQ → AARE: parse the association request, check client_SAP,
    /// application-context and DLMS version; write the AARE (APDU) into tx.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_aarq(
        &self,
        settings: &mut Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
        source_port: u16,
    ) -> Result<(usize, bool), Error> {
        let aarq = {
            let mut r = Reader::new(rx.extract());
            // TODO: the whole AARQapdu is decoded here, but only
            // application_context_name, user_information and calling_ap_title are used.
            // The remaining fields (called-AP-title, invocation-id, authentication-value
            // etc.) are not needed yet. When they are — decide whether to store
            // them owned in Settings (grows the persistent Session RAM) or introduce
            // a partial decoder (saves ~120 B of transient stack).
            AARQapdu::get(&mut r)?
        };

        let ui = aarq.user_information.ok_or_else(|| {
            Error::Codec(cosempdu::Error::Message("AARQ without user-information"))
        })?;
        let req = InitiateRequest::get(&mut Reader::new(ui))?;
        let proposed_dlms_version = req.proposed_dlms_version_number;

        // The agreed application-context-name (short names were rejected above).
        settings.app_context = aarq.application_context_name;
        settings.conformance = req.proposed_conformance.intersection(PROPOSED_CONFORMANCE);
        settings.tx_max = core::cmp::min(MAX_APDU as u16, req.client_max_receive_pdu_size);
        // Authentication chosen by the client (sender-acse-requirements, bit 0).
        settings.authenticated = aarq.sender_acse_requirements;

        // Client system-title (calling-AP-title). Invalid length → reject.
        match aarq.calling_ap_title {
            Some(calling) => match SystemTitle::from_slice(calling) {
                Ok(title) => settings.system_title_c = Some(title),
                Err(_) => {
                    return Ok((
                        put_aare(
                            tx,
                            settings.app_context,
                            AssociationResult::RejectedPermanent,
                            AssociateSourceDiagnostic::ServiceUser(
                                AcseServiceUser::CallingApTitleNotRecognized,
                            ),
                            UserInformation::None,
                        )?,
                        req.response_allowed,
                    ));
                }
            },
            None => {
                // With ciphering the calling-AP-title is required (client
                // identifier for key agreement); missing → no-reason-given.
                if settings.is_ciphered() {
                    return Ok((
                        put_aare(
                            tx,
                            settings.app_context,
                            AssociationResult::RejectedPermanent,
                            AssociateSourceDiagnostic::ServiceProvider(
                                AcseServiceProvider::NoReasonGiven,
                            ),
                            UserInformation::None,
                        )?,
                        req.response_allowed,
                    ));
                }
                settings.system_title_c = None;
            }
        }

        // called-AP-title check: if the client explicitly names a title,
        // it must match the server-system-title (otherwise called-AP-title-not-recognized).
        if let Some(called) = aarq.called_ap_title {
            if self.system_title() != Some(called) {
                return Ok((
                    put_aare(
                        tx,
                        settings.app_context,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::CalledApTitleNotRecognized,
                        ),
                        UserInformation::None,
                    )?,
                    req.response_allowed,
                ));
            }
        }

        // client_SAP = WPDU source_port; find AssociationLn in the shared catalog,
        // matching associated_partners_id.client_sap via Server.attr + codecs.
        let (assoc_idx, client_sap) =
            match self.objects.iter().enumerate().find_map(|(idx, obj)| {
                obj.as_any().downcast_ref::<AssociationLn>()?;
                let desc = self.attr(idx as u16, ATTR_ASSOCIATED_PARTNERS_ID)?;
                let RomKind::Static(slot) = desc.kind else {
                    return None;
                };
                let (client_sap, _) = self.codecs[slot as usize].associated_partners()?;
                (client_sap as u16 == source_port).then_some((idx as u8, client_sap))
            }) {
                Some(v) => v,
                None => {
                    return Ok((
                        put_aare(
                            tx,
                            settings.app_context,
                            AssociationResult::RejectedPermanent,
                            AssociateSourceDiagnostic::ServiceUser(
                                AcseServiceUser::AuthenticationFailure,
                            ),
                            UserInformation::None,
                        )?,
                        req.response_allowed,
                    ));
                }
            };
        settings.assoc_idx = assoc_idx;
        settings.client_sap = client_sap;

        // security_suite comes from the Security setup (attr 3) referenced by
        // the association via security_setup_reference (attr 9). Without a
        // reference (e.g. LLS) the default AesGcm128 remains — unused.
        let security_suite = self
            .security_suite(assoc_idx)
            .unwrap_or(SecuritySuite::AesGcm128);

        // Client dedicated key (only when ciphering; length checked against the suite).
        settings.dedicated_key = if settings.is_ciphered() {
            req.dedicated_key
                .filter(|k| k.len() == security_suite.key_len())
                .map(DedicatedKey::from_slice)
                .unwrap_or(DedicatedKey::None)
        } else {
            DedicatedKey::None
        };

        match settings.app_context {
            ApplicationContextName::ShortNameCiphering
            | ApplicationContextName::ShortNameNoCiphering => {
                return Ok((
                    put_aare(
                        tx,
                        ApplicationContextName::LogicalNameNoCiphering,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::ApplicationContextNameNotSupported,
                        ),
                        UserInformation::None,
                    )?,
                    req.response_allowed,
                ));
            }
            _ => {}
        }

        if proposed_dlms_version < DLMS_VERSION_NUMBER {
            // Reject: dlms-version-too-low → AARE(RejectedPermanent) +
            // ConfirmedServiceError(initiate-error: dlms-version-too-low).
            return Ok((
                put_aare(
                    tx,
                    settings.app_context,
                    AssociationResult::RejectedPermanent,
                    AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven),
                    UserInformation::Error(ConfirmedServiceError {
                        tag: confirmed_service_error_tag::INITIATE_ERROR,
                        service_error: SnServiceError::Initiate(Initiate::DlmsVersionTooLow),
                    }),
                )?,
                req.response_allowed,
            ));
        }

        // Authentication: dispatch by mechanism-name (checked only when
        // authentication is chosen — sender-acse-requirements, bit 0).
        match (settings.authenticated, aarq.mechanism_name) {
            // LLS (LowLevelSecurity = 1): the password from calling-authentication-value
            // is compared against the `secret` attribute (attr 7) of the chosen association.
            (true, Some(MechanismName::LowLevelSecurity)) => {
                if !self.verify_lls_secret(settings, &aarq) {
                    return Ok((
                        put_aare(
                            tx,
                            settings.app_context,
                            AssociationResult::RejectedPermanent,
                            AssociateSourceDiagnostic::ServiceUser(
                                AcseServiceUser::AuthenticationFailure,
                            ),
                            UserInformation::None,
                        )?,
                        req.response_allowed,
                    ));
                }
            }
            // HLS/ECDSA (7) → 4-pass handshake (implemented below).
            #[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
            (true, Some(MechanismName::HighLevelSecurityEcdsa)) => {
                return self.start_hls_handshake(settings, &aarq, tx, req.response_allowed);
            }
            // LowestLevelSecurity (0) / None / other HLS mechanisms — accepted without
            // further checks (TODO: GMAC = 5, SHA-256 = 6, etc.).
            _ => {}
        }

        settings.state = AssociationState::Associating;
        let n = put_aare(
            tx,
            settings.app_context,
            AssociationResult::Accepted,
            AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null),
            UserInformation::Response(InitiateResponse::new(settings.conformance, MAX_APDU as u16)),
        )?;

        // Association established (AARE written to tx; sending decided by response_allowed).
        settings.state = AssociationState::Associated;
        Ok((n, req.response_allowed))
    }

    /// LLS: compare the password from `calling-authentication-value` with `secret` (attr 7)
    /// of the chosen association. On a missing secret — fail-closed (`false`).
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn verify_lls_secret(&self, settings: &Settings, aarq: &AARQapdu<'_>) -> bool {
        let expected = self
            .attr_codec(settings.assoc_idx, ATTR_SECRET)
            .and_then(|codec| codec.octet_string());
        let provided = match aarq.calling_authentication_value {
            Some(AuthenticationValue::CharString(v)) => v,
            Some(AuthenticationValue::BitString(v)) => v,
            None => &[],
        };
        match expected {
            Some(secret) => provided == secret,
            None => false,
        }
    }

    /// Pass 1/2 HLS-handshake (ECDSA, 4-pass): accept CtoS (calling-authentication-value)
    /// and the client certificate (calling-AE-qualifier), generate StoC and reply AARE
    /// (accepted + HLS 0x0E + responding-authentication-value = StoC). Passes 3/4 go through
    /// the ACTION method `reply_to_HLS_authentication` (follow-up: ActionRequest/ActionResponse).
    #[cfg(all(
        any(feature = "tcp", feature = "ble"),
        any(feature = "ecdsa_p256", feature = "ecdsa_p384")
    ))]
    fn start_hls_handshake(
        &self,
        settings: &mut Settings,
        aarq: &AARQapdu<'_>,
        tx: &mut ArrayBuffer<RX_BUF>,
        response_allowed: bool,
    ) -> Result<(usize, bool), Error> {
        let handshake = hls_handshake();
        if handshake.busy {
            // Scratch is busy with another session's check → rejected-transient.
            return Ok((
                put_aare(
                    tx,
                    settings.app_context,
                    AssociationResult::RejectedTransient,
                    AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::NoReasonGiven),
                    UserInformation::None,
                )?,
                response_allowed,
            ));
        }

        // The client certificate is required for HLS (length 64/96 → P256/P384).
        // TODO: confirm that qualifier = only the public key (not system-title || key).
        let qualifier = match aarq.calling_ae_qualifier {
            Some(cert) => CallingAeQualifier::from_slice(cert),
            None => {
                return Ok((
                    put_aare(
                        tx,
                        settings.app_context,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::CallingAeQualifierNotRecognized,
                        ),
                        UserInformation::None,
                    )?,
                    response_allowed,
                ));
            }
        };
        if matches!(qualifier, CallingAeQualifier::None) {
            return Ok((
                put_aare(
                    tx,
                    settings.app_context,
                    AssociationResult::RejectedPermanent,
                    AssociateSourceDiagnostic::ServiceUser(
                        AcseServiceUser::CallingAeQualifierNotRecognized,
                    ),
                    UserInformation::None,
                )?,
                response_allowed,
            ));
        }

        // CtoS — client challenge from calling-authentication-value (optional;
        // the server needs it for pass 4, where it returns f(CtoS)).
        let ctos = match aarq.calling_authentication_value {
            Some(AuthenticationValue::CharString(v)) => v,
            Some(AuthenticationValue::BitString(v)) => v,
            None => &[],
        };

        // Claim the scratch for the handshake (released after pass 3;
        // TODO: timeout/release if the client never sends the ACTION reply).
        handshake.busy = true;
        handshake.qualifier = qualifier;
        let len = ctos.len().min(16);
        handshake.ctos[..len].copy_from_slice(&ctos[..len]);
        // TODO: server-to-client challenge (StoC) — random value (RNG); constant stub.
        handshake.stoc = [0x43u8; 16];

        settings.state = AssociationState::Associating;

        // AARE (pass 2): accepted + HLS success + StoC in responding-authentication-value.
        let stoc = handshake.stoc;
        let aare = AAREapdu {
            application_context_name: settings.app_context,
            result: AssociationResult::Accepted,
            // TODO: confirm the "HLS success (0x0E)" encoding — probably
            // acse-service-user: authentication-required (14 = 0x0E).
            result_source_diagnostic: AssociateSourceDiagnostic::ServiceUser(
                AcseServiceUser::AuthenticationRequired,
            ),
            responding_ap_title: self.system_title(),
            responding_ae_qualifier: None,
            responding_ap_invocation_id: None,
            responding_ae_invocation_id: None,
            responder_acse_requirements: None,
            mechanism_name: None,
            responding_authentication_value: Some(AuthenticationValue::CharString(&stoc)),
            user_information: None,
        };
        let n = {
            let mut buf = ByteBuffer::new(tx.as_bytes_mut());
            buf.set_pos(WPDU_HEADER_LEN)?;
            let n = aare.put(&mut buf)?;
            tx.set_pos(WPDU_HEADER_LEN + n)?;
            n
        };
        Ok((n, response_allowed))
    }

    /// Get-Request (Normal, without access_selection) → Get-Response in session.tx.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_get(
        &self,
        settings: &Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
    ) -> Result<usize, Error> {
        // 1) Decode the Get-Request into owned fields.
        let (invoke, descriptor) = {
            let mut r = Reader::new(rx.extract());
            match GetRequest::get(&mut r)? {
                GetRequest::Normal(GetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection: None,
                }) => (invoke, descriptor),
                _ => return Err(Error::NotFound),
            }
        };

        // 2) Get-Response (APDU) straight into tx, offset for the WPDU header.
        let mut buf = ByteBuffer::new(tx.as_bytes_mut());
        buf.set_pos(WPDU_HEADER_LEN)?;
        let n = self.handle_get(invoke, descriptor, settings, &mut buf)?;
        tx.set_pos(WPDU_HEADER_LEN + n)?;
        Ok(n)
    }

    /// Set-Request (Normal, without access_selection) → apply the value → Set-Response.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_set(
        &mut self,
        settings: &Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
    ) -> Result<usize, Error> {
        // 1) Decode Set-Request::Normal and apply the value to the attribute.
        //    A data-access error does not abort processing; it goes into the Set-Response.
        let (invoke, result) = {
            let mut r = Reader::new(rx.extract());
            match SetRequest::get(&mut r)? {
                SetRequest::Normal(SetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection: None,
                    value,
                }) => {
                    let class_id = ClassId::from_u16(descriptor.class_id).ok_or(Error::NotFound)?;
                    let obis = ObisCode::from_bytes(descriptor.instance_id);
                    let key = AttributeKey::new(obis, descriptor.attribute_id as u8);

                    // Apply the value; on a Data-Access-Result return its code in the response.
                    let result = match self.stream_set(class_id, key, settings) {
                        Ok(mut s) => {
                            s.push(value.remaining_bytes())?;
                            s.finish()?;
                            DataAccessResult::Success
                        }
                        Err(code) => code,
                    };

                    (invoke, result)
                }
                _ => return Err(Error::NotFound),
            }
        };

        // 2) Set-Response (APDU) straight into tx (the WPDU-header offset was made in process_request).
        Ok(SetResponse::put_normal(invoke, result, tx)?)
    }

    /// Serve one xDLMS request: read a WPDU into session.rx, process
    /// ([`Server::process_request`]) and send the response from session.tx.
    /// Association release is reflected in `session.settings.state`.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    async fn handle_request<C: Channel<Frame = Wrapper>>(
        &mut self,
        session: &mut Session,
        channel: &mut C,
    ) -> Result<(), Error> {
        let received = channel.read(session.rx_mut()).await?;
        session.set_rx_len(received.apdu_len() as usize);

        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            self.process_request(settings, transport_ref, rx, tx, received)?
        };

        if send {
            channel.write(session.tx()).await?;
        }
        session.clear_rx();
        Ok(())
    }

    #[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
    fn release(&mut self, media: Media) {
        match media {
            #[cfg(feature = "optical")]
            Media::Optical => self.optical_pool.free(),
            #[cfg(feature = "tcp")]
            Media::Tcp => self.tcp_pool.free(),
            #[cfg(feature = "ble")]
            Media::Ble => self.ble_pool.free(),
        }
    }
}

impl Server<3> {
    /// Create a server with the default number of sessions (3).
    pub fn new(
        objects: &'static [&'static dyn InterfaceClass],
        attrs: &'static [AttrDesc],
        codecs: &'static [&'static dyn Codec],
        mutable: &'static mut [Option<&'static mut dyn Codec>],
    ) -> Self {
        Self::with_capacity(objects, attrs, codecs, mutable)
    }
}

/// Transport layer: Wrapper-header validation (the WPDU is addressed to our wPort)
/// and building the response settings (server view: our wPort → client wPort).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn validate_wrapper(transport: &TransportRef, received: Wrapper) -> Result<Wrapper, Error> {
    // The server's own wPort is already stored in TransportRef at on_connect.
    let server_port = match transport {
        TransportRef::Wrapper(s) => s.source_port(),
        #[cfg(feature = "optical")]
        TransportRef::Hdlc(_) => {
            return Err(Error::Codec(cosempdu::Error::Message(
                "wrapper validation requires tcp/ble channel",
            )))
        }
    };

    // Validation: the client must address the WPDU to our wPort.
    if received.destination_port() != server_port {
        return Err(Error::Codec(cosempdu::Error::Message(
            "wrong destination wPort",
        )));
    }

    // Response settings: our wPort → client wPort (from its header).
    Ok(Wrapper::new(server_port, received.source_port()))
}

/// Server-side view of the ports (Copy) for the response WPDU header.

/// Expanded `AAREapdu::put` tags: we encode the AARE straight into tx, without
/// an intermediate struct and without a scratch buffer for user-information.
#[cfg(any(feature = "tcp", feature = "ble"))]
const AARE_TAG: Tag = Tag {
    class: Class::Application,
    number: 1,
    constructed: true,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
const CTX_NAME_TAG: Tag = Tag {
    class: Class::Context,
    number: 1,
    constructed: true,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
const UI_TAG: Tag = Tag {
    class: Class::Context,
    number: 30,
    constructed: true,
};

/// user-information encoded inline.
#[cfg(any(feature = "tcp", feature = "ble"))]
enum UserInformation {
    /// No field.
    None,
    /// `dlms-version-too-low` → ConfirmedServiceError.
    Error(ConfirmedServiceError),
    /// Successful association → InitiateResponse.
    Response(InitiateResponse),
}

/// Expanded `AAREapdu::put`: the AARE straight into `buf`, user-information inline.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn put_aare<B: WriteBuf>(
    buf: &mut B,
    ctx_name: ApplicationContextName,
    result: AssociationResult,
    diagnostic: AssociateSourceDiagnostic,
    ui: UserInformation,
) -> cosempdu::Result<usize> {
    with_content(buf, &AARE_TAG, |b| {
        let mut written = 0usize;
        written += with_content(b, &CTX_NAME_TAG, |ib| {
            with_content(ib, &Tag::universal(UniversalTag::ObjectIdentifier), |o| {
                ctx_name.put(o)
            })
        })?;
        written += result.put(b)?;
        written += diagnostic.put(b)?;
        match ui {
            UserInformation::None => {}
            UserInformation::Error(cse) => {
                written += with_content(b, &UI_TAG, |explicit| {
                    with_content(explicit, &Tag::universal(UniversalTag::OctetString), |o| {
                        cse.put(o)
                    })
                })?;
            }
            UserInformation::Response(resp) => {
                written += with_content(b, &UI_TAG, |explicit| {
                    with_content(explicit, &Tag::universal(UniversalTag::OctetString), |o| {
                        resp.put(o)
                    })
                })?;
            }
        }
        Ok(written)
    })
}

/// Unknown/malformed APDU → error-response to the peer.
///
/// LN referencing — `ExceptionResponse` (service-unknown, operation-not-possible);
/// SN referencing — not used.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_exception_response(tx: &mut ArrayBuffer<RX_BUF>) -> Result<usize, Error> {
    let exc = ExceptionResponse {
        state_error: StateError::ServiceUnknown,
        service_error: ServiceError_::OperationNotPossible,
    };
    Ok(exc.put(tx)?)
}

/// LN referencing — `ExceptionResponse` (service-not-allowed, operation-not-possible).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_association_not_established(tx: &mut ArrayBuffer<RX_BUF>) -> Result<usize, Error> {
    let exc = ExceptionResponse {
        state_error: StateError::ServiceNotAllowed,
        service_error: ServiceError_::OperationNotPossible,
    };
    Ok(exc.put(tx)?)
}

/// RLRQ → RLRE: confirm the association release and write the RLRE into session.tx.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn handle_release(
    settings: &mut Settings,
    rx: &ArrayBuffer<RX_BUF>,
    tx: &mut ArrayBuffer<RX_BUF>,
) -> Result<usize, Error> {
    // Make sure it is actually an RLRQ (not AARQ/AARE/RLRE).
    let acse = ACSEApdu::get(&mut Reader::new(rx.extract()))?;
    match acse {
        ACSEApdu::Rlrq(_) => {}
        _ => return Err(Error::Codec(cosempdu::Error::Message("expected RLRQ"))),
    }

    // RLRE (APDU, reason normal) into tx (the WPDU-header offset was made in process_request).
    let rlre = RLREapdu {
        reason: Some(ReleaseResponseReason::Normal),
        user_information: None,
    };
    let n = rlre.put(tx)?;
    settings.state = AssociationState::Disconnecting;
    Ok(n)
}

/// Streaming SET handle: keeps the decoder over the attribute sink while
/// value blocks are being received.
pub struct StreamingSet<'s> {
    decoder: StreamDecoder<'s, dyn StreamSink + 's>,
}

impl<'s> StreamingSet<'s> {
    /// Feed the next chunk of the value's A-XDR bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.decoder.push(bytes)?;
        Ok(())
    }

    /// Finish the stream; an error if the value is incomplete.
    pub fn finish(&mut self) -> Result<(), Error> {
        self.decoder.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosempdu::apdu::{
        CosemAttributeDescriptor, GetDataResult, GetResponseNormal, ImplicitTagged,
        InvokeIdAndPriority,
    };
    use cosempdu::buffer::Reader;
    use dlms1::common_data_types::{
        ArrayOwned, DateTime, DoubleLongUnsigned, OctetString, OctetStringSized, Unsigned,
    };
    use dlms1::ic::{
        AttributeAccessMode, Clock, DataObject, ExtendedRegister, ObjectDefinition, Register,
        RegisterActivation, RegisterAssignmentValue, ScalUnit,
    };

    /// Default rights: public/reader can read, configurator can read+write.
    const RW: Access = Access {
        public: AttributeAccessMode::ReadOnly,
        reader: AttributeAccessMode::ReadOnly,
        configurator: AttributeAccessMode::ReadAndWrite,
    };

    static SERIAL_OBJ: DataObject = DataObject::new(ObisCode::new(0, 0, 96, 1, 0, 255));
    static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
    static CLOCK_OBJ: Clock = Clock::new(ObisCode::CLOCK);
    static RA_OBJ: RegisterActivation = RegisterActivation::new(ObisCode::new(0, 0, 96, 1, 1, 255));
    static OBJ_PAIRS: [(&dyn InterfaceClass, ObisCode); 4] =
        crate::objects![SERIAL_OBJ, REG_OBJ, CLOCK_OBJ, RA_OBJ];
    // Sorted by OBIS (binary search in Server::find_object).
    static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<4>(&[], &OBJ_PAIRS);

    static mut NO_MUT: [Option<&'static mut dyn Codec>; 0] = [];

    /// Build the ROM attribute registry from specs (test helper: resolves
    /// OBIS→index, Static codec → slot, and sorts; in production — `merge_attrs`).
    fn rom_attrs(specs: &[AttrSpec]) -> &'static [AttrDesc] {
        let mut out: std::vec::Vec<AttrDesc> = std::vec::Vec::with_capacity(specs.len());
        let mut static_slot = 0u16;
        for s in specs {
            let mut rank = 0u16;
            for pair in OBJ_PAIRS.iter() {
                if pair.1 < s.key.obis {
                    rank += 1;
                }
            }
            let kind = match s.kind {
                AttrKind::Static(_) => {
                    let slot = static_slot;
                    static_slot += 1;
                    RomKind::Static(slot)
                }
                AttrKind::Dynamic(slot) => RomKind::Dynamic(slot),
                AttrKind::Persistent(slot) => RomKind::Persistent(slot),
                AttrKind::Computed => RomKind::Computed,
            };
            out.push(AttrDesc {
                key: AttrKey {
                    object: rank,
                    attribute_id: s.key.attribute_id,
                },
                access: s.access,
                kind,
            });
        }
        out.sort_by_key(|d| (d.key.object, d.key.attribute_id));
        std::boxed::Box::leak(out.into_boxed_slice())
    }

    /// Collect the ROM codec array for Static attributes (in spec order).
    fn rom_codecs(specs: &[AttrSpec]) -> &'static [&'static dyn Codec] {
        let mut codecs: std::vec::Vec<&'static dyn Codec> = std::vec::Vec::new();
        for s in specs {
            if let AttrKind::Static(c) = s.kind {
                codecs.push(c);
            }
        }
        std::boxed::Box::leak(codecs.into_boxed_slice())
    }

    /// Read-only server (no mutable attributes).
    fn server(specs: &[AttrSpec]) -> Server {
        Server::new(OBJECTS, rom_attrs(specs), rom_codecs(specs), unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        })
    }

    /// Test helper: apply `Data` to an attribute via a streaming SET.
    fn set_data(
        server: &mut Server,
        class_id: ClassId,
        key: AttributeKey,
        ctx: &Settings,
        data: &Data<'_>,
    ) -> Result<(), DataAccessResult> {
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            data.put(&mut b)
                .map_err(|_| DataAccessResult::HardwareFault)?
        };
        let mut s = server.stream_set(class_id, key, ctx)?;
        s.push(&backing[..n])
            .map_err(|_| DataAccessResult::TypeUnmatched)?;
        s.finish().map_err(|_| DataAccessResult::TypeUnmatched)
    }

    /// Build a `CosemAttributeDescriptor` from `class_id` + the attribute key.
    fn descriptor(class_id: ClassId, key: AttributeKey) -> CosemAttributeDescriptor {
        CosemAttributeDescriptor {
            class_id: class_id.as_u16(),
            instance_id: key.obis.bytes,
            attribute_id: key.attribute_id as i8,
        }
    }

    /// Test helper: read an attribute and write its A-XDR into `buf`
    /// (a wrapper over `Server::lookup_value` + `Codec::put`).
    fn put(
        server: &Server,
        class_id: ClassId,
        key: AttributeKey,
        ctx: &Settings,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<(), DataAccessResult> {
        server
            .lookup_value(descriptor(class_id, key), ctx)?
            .put(buf)
            .map_err(|_| DataAccessResult::HardwareFault)?;
        Ok(())
    }

    #[test]
    fn server_handles_get_request_normal() {
        static REG: DoubleLongUnsigned = DoubleLongUnsigned(42);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 2),
            access: RW,
            kind: AttrKind::Static(&REG),
        }];

        let server = server(&ATTRS);

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::Register.as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let mut tx = [0u8; 128];
        let tx_n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, descriptor, &Settings::public(), &mut b)
                .unwrap()
        };

        let resp = {
            let mut r = Reader::new(&tx[..tx_n]);
            GetResponse::get(&mut r).unwrap()
        };

        match resp {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::Data(r),
            }) => {
                assert_eq!(invoke.invoke_id(), 1);
                let mut eb = [0u8; 16];
                let en = {
                    let mut b = ByteBuffer::new(&mut eb);
                    REG.put(&mut b).unwrap()
                };
                assert_eq!(r.as_bytes(), &eb[..en]);
            }
            _ => panic!("expected GetResponse::Normal with data"),
        }
    }

    #[test]
    fn server_handles_get_request_missing_object() {
        let server = server(&[]);

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::Register.as_u16(),
            instance_id: ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff).bytes,
            attribute_id: 2,
        };
        let mut tx = [0u8; 128];
        let tx_n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, descriptor, &Settings::public(), &mut b)
                .unwrap()
        };

        let resp = {
            let mut r = Reader::new(&tx[..tx_n]);
            GetResponse::get(&mut r).unwrap()
        };

        match resp {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::DataAccessError(code),
            }) => {
                assert_eq!(invoke.invoke_id(), 1);
                assert_eq!(code, DataAccessResult::ObjectUnavailable);
            }
            _ => panic!("expected GetResponse::Normal with DataAccessError"),
        }
    }

    #[test]
    fn server_get_set_persistent() {
        static SN: DoubleLongUnsigned = DoubleLongUnsigned(123456);
        static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(230000);
        static ATTRS: [AttrSpec; 2] = [
            AttrSpec {
                key: AttributeKey::new(ObisCode::new(0, 0, 96, 1, 0, 255), 2),
                access: Access {
                    public: AttributeAccessMode::ReadOnly,
                    reader: AttributeAccessMode::NoAccess,
                    configurator: AttributeAccessMode::WriteOnly,
                },
                kind: AttrKind::Static(&SN),
            },
            AttrSpec {
                key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 2),
                access: RW,
                kind: AttrKind::Persistent(0),
            },
        ];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        put(
            &server,
            ClassId::Register,
            REG_OBJ.value(),
            &Settings::reader(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x03, 0x82, 0x70]);

        set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.value(),
            &Settings::configurator(),
            &Data::DoubleLongUnsigned(1),
        )
        .unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            put(
                &server,
                ClassId::Register,
                REG_OBJ.value(),
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
            assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x01]);
        }

        assert_eq!(
            put(
                &server,
                ClassId::Register,
                REG_OBJ.value(),
                &Settings::with_sap(0x08),
                &mut buf
            ),
            Err(DataAccessResult::ScopeOfAccessViolated)
        );
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Register,
                REG_OBJ.value(),
                &Settings::public(),
                &Data::DoubleLongUnsigned(2)
            ),
            Err(DataAccessResult::ScopeOfAccessViolated)
        );
        assert!(set_data(
            &mut server,
            ClassId::Register,
            REG_OBJ.value(),
            &Settings::configurator(),
            &Data::Unsigned(200)
        )
        .is_err());
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Data,
                SERIAL_OBJ.value(),
                &Settings::configurator(),
                &Data::Unsigned(0)
            ),
            Err(DataAccessResult::ReadWriteDenied)
        );

        let missing = ObisCode::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        assert_eq!(
            put(
                &server,
                ClassId::Register,
                AttributeKey::new(missing, 2),
                &Settings::public(),
                &mut buf
            ),
            Err(DataAccessResult::ObjectUnavailable)
        );
        assert_eq!(
            set_data(
                &mut server,
                ClassId::Register,
                AttributeKey::new(missing, 2),
                &Settings::public(),
                &Data::NullData
            ),
            Err(DataAccessResult::ObjectUnavailable)
        );
    }

    #[test]
    fn server_dynamic_update() {
        static mut CLOCK_TIME: DateTime = DateTime([0; 12]);
        static mut SCAL: ScalUnit = ScalUnit {
            scaler: 0,
            unit: 255,
        };
        static ATTRS: [AttrSpec; 2] = [
            AttrSpec {
                key: AttributeKey::new(ObisCode::CLOCK, 2),
                access: RW,
                kind: AttrKind::Dynamic(0),
            },
            AttrSpec {
                key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 3),
                access: RW,
                kind: AttrKind::Persistent(1),
            },
        ];
        static mut MUT: [Option<&'static mut dyn Codec>; 2] = [None, None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(CLOCK_TIME));
            MUT[1] = Some(&mut *core::ptr::addr_of_mut!(SCAL));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        let t: [u8; 12] = [
            0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        server.update(CLOCK_OBJ.time(), &Data::DateTime(t)).unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            put(
                &server,
                ClassId::Clock,
                CLOCK_OBJ.time(),
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
            assert_eq!(
                buf.extract(),
                &[0x19, 0x07, 0xE8, 0x0A, 0x09, 0x00, 0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00, 0xFF]
            );
        }

        assert_eq!(
            set_data(
                &mut server,
                ClassId::Clock,
                CLOCK_OBJ.time(),
                &Settings::configurator(),
                &Data::DateTime(t)
            ),
            Err(DataAccessResult::ReadWriteDenied)
        );

        assert_eq!(
            server.update(
                REG_OBJ.scaler_unit(),
                &Data::Structure(&[Data::Integer(0), Data::Enum(255)])
            ),
            Err(Error::ReadOnly)
        );
    }

    #[test]
    fn server_dynamic_system_title() {
        static mut TITLE: OctetStringSized<8> = OctetStringSized([0u8; 8]);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::new(0, 0, 96, 1, 0, 255), 2),
            access: RW,
            kind: AttrKind::Dynamic(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(TITLE));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        let combined = [0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04];
        server
            .update(SERIAL_OBJ.value(), &Data::OctetString(&combined))
            .unwrap();

        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            put(
                &server,
                ClassId::Data,
                SERIAL_OBJ.value(),
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
            assert_eq!(
                buf.extract(),
                &[0x09, 0x08, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04]
            );
        }

        let combined2 = [0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
        server
            .update(SERIAL_OBJ.value(), &Data::OctetString(&combined2))
            .unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            put(
                &server,
                ClassId::Data,
                SERIAL_OBJ.value(),
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
            assert_eq!(
                buf.extract(),
                &[0x09, 0x08, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E]
            );
        }

        assert_eq!(
            set_data(
                &mut server,
                ClassId::Data,
                SERIAL_OBJ.value(),
                &Settings::configurator(),
                &Data::OctetString(&combined2),
            ),
            Err(DataAccessResult::ReadWriteDenied)
        );
    }

    #[test]
    fn server_dynamic_array() {
        static mut ARRAY: ArrayOwned<Unsigned, 4> = ArrayOwned::new_empty(Unsigned(0));
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::new(0, 0, 96, 1, 0, 255), 2),
            access: RW,
            kind: AttrKind::Dynamic(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(ARRAY));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        // Update (assign): array of 3 unsigned (variable length).
        let values = [Data::Unsigned(1), Data::Unsigned(2), Data::Unsigned(3)];
        server
            .update(SERIAL_OBJ.value(), &Data::Array(&values))
            .unwrap();

        // Read (put): array {3} unsigned.
        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);
        put(
            &server,
            ClassId::Data,
            SERIAL_OBJ.value(),
            &Settings::public(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(
            buf.extract(),
            &[0x01, 0x03, 0x11, 0x01, 0x11, 0x02, 0x11, 0x03]
        );

        // Capacity overflow (5 > 4) — error.
        let bad = [Data::Unsigned(1); 5];
        assert!(server
            .update(SERIAL_OBJ.value(), &Data::Array(&bad))
            .is_err());
    }

    #[test]
    fn server_stream_set_scalar() {
        static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 2),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = REG_OBJ.value();

        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::DoubleLongUnsigned(42).put(&mut buf).unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, &Settings::configurator())
                .unwrap();
            let mid = n / 2;
            s.push(&backing[..mid]).unwrap();
            s.push(&backing[mid..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        put(
            &server,
            ClassId::Register,
            key,
            &Settings::public(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf.extract(), &[0x06, 0x00, 0x00, 0x00, 0x2A]);
    }

    #[test]
    fn server_stream_set_composite() {
        static mut SCAL: ScalUnit = ScalUnit {
            scaler: 0,
            unit: 255,
        };
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 3),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(SCAL));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = REG_OBJ.scaler_unit();

        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            Data::Structure(&[Data::Integer(3), Data::Enum(1)])
                .put(&mut buf)
                .unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, &Settings::configurator())
                .unwrap();
            s.push(&backing[..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut out);
        put(
            &server,
            ClassId::Register,
            key,
            &Settings::public(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x03, 0x16, 0x01]);
    }

    #[test]
    fn server_stream_set_blob() {
        static mut VALUE: OctetString<60> = OctetString::new(&[]);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 2),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(VALUE));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = REG_OBJ.value();

        let content: [u8; 60] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::OctetString(&content).put(&mut b).unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::Register, key, &Settings::configurator())
                .unwrap();
            for chunk in backing[..n].chunks(20) {
                s.push(chunk).unwrap();
            }
            s.finish().unwrap();
        }

        let mut out = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut out);
        put(
            &server,
            ClassId::Register,
            key,
            &Settings::public(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(buf.extract(), &backing[..n]);
    }

    #[test]
    fn server_validate_structure() {
        static mut SCAL: ScalUnit = ScalUnit { scaler: 3, unit: 1 };
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 3),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(SCAL));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = REG_OBJ.scaler_unit();

        set_data(
            &mut server,
            ClassId::Register,
            key,
            &Settings::configurator(),
            &Data::Structure(&[Data::Integer(7), Data::Enum(2)]),
        )
        .unwrap();
        {
            let mut backing = [0u8; 64];
            let mut buf = ByteBuffer::new(&mut backing);
            put(
                &server,
                ClassId::Register,
                key,
                &Settings::public(),
                &mut buf,
            )
            .unwrap();
            assert_eq!(buf.extract(), &[0x02, 0x02, 0x0F, 0x07, 0x16, 0x02]);
        }

        assert!(set_data(
            &mut server,
            ClassId::Register,
            key,
            &Settings::configurator(),
            &Data::Structure(&[Data::Unsigned(1), Data::Unsigned(2)])
        )
        .is_err());
    }

    #[test]
    fn server_validates_class_id() {
        static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL, 2),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
        }

        let server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = REG_OBJ.value();

        let mut backing = [0u8; 64];
        let mut buf = ByteBuffer::new(&mut backing);

        put(
            &server,
            ClassId::Register,
            key,
            &Settings::public(),
            &mut buf,
        )
        .unwrap();

        assert!(matches!(
            put(&server, ClassId::Clock, key, &Settings::public(), &mut buf),
            Err(DataAccessResult::ObjectClassInconsistent)
        ));

        let unknown = ObisCode::new(9, 9, 9, 9, 9, 9);
        assert_eq!(
            put(
                &server,
                ClassId::Register,
                AttributeKey::new(unknown, 2),
                &Settings::public(),
                &mut buf
            ),
            Err(DataAccessResult::ObjectUnavailable)
        );
    }

    #[test]
    fn server_register_activation_register_assignment() {
        static mut VALUE: RegisterAssignmentValue<2> =
            RegisterAssignmentValue([ObjectDefinition::EMPTY; 2]);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(ObisCode::new(0, 0, 96, 1, 1, 255), 2),
            access: RW,
            kind: AttrKind::Persistent(0),
        }];
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];
        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(VALUE));
        }

        let mut server = Server::new(OBJECTS, rom_attrs(&ATTRS), rom_codecs(&ATTRS), unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        let key = RA_OBJ.register_assignment();

        let ln0 = ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL;
        let ln1 = ObisCode::ACTIVE_ENERGY_EXPORT_TOTAL;
        let f0 = [
            Data::LongUnsigned(ClassId::Register.as_u16()),
            Data::OctetString(&ln0.bytes),
        ];
        let f1 = [
            Data::LongUnsigned(ClassId::ExtendedRegister.as_u16()),
            Data::OctetString(&ln1.bytes),
        ];
        let items = [Data::Structure(&f0), Data::Structure(&f1)];
        let mut backing = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            Data::Array(&items).put(&mut b).unwrap()
        };

        {
            let mut s = server
                .stream_set(ClassId::RegisterActivation, key, &Settings::configurator())
                .unwrap();
            let a = n / 3;
            let b = 2 * a;
            s.push(&backing[..a]).unwrap();
            s.push(&backing[a..b]).unwrap();
            s.push(&backing[b..n]).unwrap();
            s.finish().unwrap();
        }

        let mut out = [0u8; 128];
        let mut buf = ByteBuffer::new(&mut out);
        put(
            &server,
            ClassId::RegisterActivation,
            key,
            &Settings::public(),
            &mut buf,
        )
        .unwrap();
        assert_eq!(
            buf.extract(),
            &[
                0x01, 0x02, 0x02, 0x02, 0x12, 0x00, 0x03, 0x09, 0x06, 0x01, 0x00, 0x01, 0x08, 0x00,
                0xFF, 0x02, 0x02, 0x12, 0x00, 0x04, 0x09, 0x06, 0x01, 0x00, 0x02, 0x08, 0x00, 0xFF,
            ]
        );
    }

    #[test]
    fn server_get_objects_by_type() {
        let server = server(&[]);

        // Each type has a single instance.
        assert_eq!(server.get_objects::<Register>().next(), Some(REG_OBJ));
        assert_eq!(server.get_objects::<Clock>().next(), Some(CLOCK_OBJ));
        assert_eq!(server.get_objects::<DataObject>().next(), Some(SERIAL_OBJ));
        assert_eq!(
            server.get_objects::<RegisterActivation>().next(),
            Some(RA_OBJ)
        );

        // A type absent from the catalog yields an empty iterator (no panic).
        assert_eq!(server.get_objects::<ExtendedRegister>().count(), 0);
    }

    #[test]
    fn server_default_catalog_has_associations() {
        use dlms1::ic::association_ln::ATTR_ASSOCIATED_PARTNERS_ID;
        use dlms1::ic::AssociationLn;

        // Default catalog: LDN + three Association LN associations + Security setup.
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 14] =
            crate::merge_attrs::<14>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 5] = crate::merge_codecs::<5>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        // Four Association LN objects: base + public/reader/configurator.
        let assocs = server
            .get_objects::<AssociationLn>()
            .collect::<std::vec::Vec<_>>();
        assert_eq!(assocs.len(), 4);

        // associated_partners_id (attr 3) of the real associations is Static (read-only);
        // the base one (`0.0.40.0.0.255`) has no such attribute.
        for assoc in &assocs {
            if assoc.obis == ASSOC_LN_BASE_OBIS {
                continue;
            }
            let key = AttributeKey::new(assoc.obis, ATTR_ASSOCIATED_PARTNERS_ID);
            assert!(server
                .lookup_value(descriptor(ClassId::AssociationLn, key), &Settings::public())
                .is_ok());
        }
    }

    /// `xDLMS_context_info` (attr 5) is computed from the session state (not stored):
    /// GET returns the structure `{ conformance, max_receive, max_send, dlms_version,
    /// quality_of_service = 0, cyphering_info }`.
    #[test]
    fn server_get_xdlms_context_info_computed() {
        use dlms1::ic::association_ln::ATTR_XDLMS_CONTEXT_INFO;

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 14] =
            crate::merge_attrs::<14>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 5] = crate::merge_codecs::<5>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_CONFIGURATOR_OBIS.bytes,
            attribute_id: ATTR_XDLMS_CONTEXT_INFO as i8,
        };
        let mut ctx = Settings::configurator();
        ctx.tx_max = 1200;
        ctx.conformance = Conformance([0x11, 0x22, 0x33]);
        ctx.assoc_idx = server
            .find_object(ClassId::AssociationLn, &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as u8;

        let mut tx = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server.handle_get(invoke, descriptor, &ctx, &mut b).unwrap()
        };

        let resp = {
            let mut r = Reader::new(&tx[..n]);
            GetResponse::get(&mut r).unwrap()
        };
        match resp {
            GetResponse::Normal(GetResponseNormal {
                invoke,
                result: GetDataResult::Data(r),
            }) => {
                assert_eq!(invoke.invoke_id(), 1);
                assert_eq!(
                    r.as_bytes(),
                    &[
                        0x02, 0x06, // structure {6}
                        0x04, 0x18, 0x11, 0x22, 0x33, // bit-string 24 bits
                        0x12, 0x04, 0x00, // long-unsigned 1024 (max_receive)
                        0x12, 0x04, 0xB0, // long-unsigned 1200 (max_send)
                        0x11, 0x06, // unsigned 6 (dlms_version)
                        0x0F, 0x00, // integer 0 (quality_of_service)
                        0x09, 0x00, // empty octet-string (cyphering_info)
                    ]
                );
            }
            other => panic!("expected GetResponse::Normal with data, got {other:?}"),
        }

        // The base OBIS (`0.0.40.0.0.255`) is always available and yields the same value.
        let base_descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_BASE_OBIS.bytes,
            attribute_id: ATTR_XDLMS_CONTEXT_INFO as i8,
        };
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, base_descriptor, &ctx, &mut b)
                .unwrap()
        };
        let resp = {
            let mut r = Reader::new(&tx[..n]);
            GetResponse::get(&mut r).unwrap()
        };
        match resp {
            GetResponse::Normal(GetResponseNormal {
                result: GetDataResult::Data(r),
                ..
            }) => {
                assert_eq!(
                    r.as_bytes(),
                    &[
                        0x02, 0x06, // structure {6}
                        0x04, 0x18, 0x11, 0x22, 0x33, // bit-string 24 bits
                        0x12, 0x04, 0x00, // long-unsigned 1024 (max_receive)
                        0x12, 0x04, 0xB0, // long-unsigned 1200 (max_send)
                        0x11, 0x06, // unsigned 6 (dlms_version)
                        0x0F, 0x00, // integer 0 (quality_of_service)
                        0x09, 0x00, // empty octet-string (cyphering_info)
                    ]
                );
            }
            other => panic!("expected GetResponse::Normal with data, got {other:?}"),
        }

        // A foreign association (reader while currently configurator) has no
        // negotiated parameters → the server's default xDLMS_context_info.
        let other_descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_READER_OBIS.bytes,
            attribute_id: ATTR_XDLMS_CONTEXT_INFO as i8,
        };
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, other_descriptor, &ctx, &mut b)
                .unwrap()
        };
        let resp = {
            let mut r = Reader::new(&tx[..n]);
            GetResponse::get(&mut r).unwrap()
        };
        match resp {
            GetResponse::Normal(GetResponseNormal {
                result: GetDataResult::Data(r),
                ..
            }) => {
                assert_eq!(
                    r.as_bytes(),
                    &[
                        0x02, 0x06, // structure {6}
                        0x04, 0x18, 0x00, 0x7E, 0x1F, // bit-string 24 bits (proposed)
                        0x12, 0x04, 0x00, // long-unsigned 1024 (max_receive)
                        0x12, 0x04, 0x00, // long-unsigned 1024 (max_send)
                        0x11, 0x06, // unsigned 6 (dlms_version)
                        0x0F, 0x00, // integer 0 (quality_of_service)
                        0x09, 0x00, // empty octet-string (cyphering_info)
                    ]
                );
            }
            other => panic!("expected GetResponse::Normal with data, got {other:?}"),
        }
    }

    /// Secret (attr 7) — Persistent: writing is allowed only for the configurator
    /// (client_SAP 0x30), reading is forbidden for everyone.
    #[test]
    fn server_secret_persistent_write_only_configurator() {
        use dlms1::ic::association_ln::ATTR_SECRET;

        static mut SECRETS: [Option<&'static mut dyn Codec>; 5] = [None, None, None, None, None];
        static mut S_PUBLIC: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut S_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut S_CONFIG: OctetString<16> = OctetString::new(b"ABCDEFGH");

        unsafe {
            SECRETS[2] = Some(&mut *core::ptr::addr_of_mut!(S_PUBLIC));
            SECRETS[3] = Some(&mut *core::ptr::addr_of_mut!(S_READER));
            SECRETS[4] = Some(&mut *core::ptr::addr_of_mut!(S_CONFIG));
        }

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 14] =
            crate::merge_attrs::<14>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 5] = crate::merge_codecs::<5>(&[], crate::ATTRS);

        let mut server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(SECRETS)
        });

        let public_secret = AttributeKey::new(ASSOC_LN_PUBLIC_OBIS, ATTR_SECRET);

        // Writing is allowed only for the configurator (client_SAP 0x30).
        assert!(server
            .stream_set(
                ClassId::AssociationLn,
                public_secret,
                &Settings::configurator()
            )
            .is_ok());
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, public_secret, &Settings::public()),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, public_secret, &Settings::reader()),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // Reading the secret is forbidden for everyone.
        assert!(matches!(
            server.lookup_value(
                descriptor(ClassId::AssociationLn, public_secret),
                &Settings::configurator()
            ),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));
    }

    #[test]
    fn memory_sizes() {
        use core::mem::size_of;

        println!("Settings = {} B", size_of::<Settings>());
        println!("MethodAccess = {} B", size_of::<MethodAccess>());
        println!("Access = {} B", size_of::<Access>());
        println!("AttributeKey = {} B", size_of::<AttributeKey>());
        println!("AttrKind = {} B", size_of::<AttrKind>());
        println!("RomKind = {} B", size_of::<RomKind>());
        println!("AttrKey = {} B", size_of::<AttrKey>());
        println!("AttrSpec = {} B", size_of::<AttrSpec>());
        println!("AttrDesc = {} B", size_of::<AttrDesc>());
        println!("Server = {} B", size_of::<Server>());
    }
}

#[cfg(all(test, feature = "optical"))]
mod transport_tests {
    use crate::{Error, Media, Server, RX_BUF};
    use cosempdu::data::Codec;
    use dlms1::ic::InterfaceClass;

    static NO_OBJECTS: &[&dyn InterfaceClass] = &[];
    static mut NO_MUT: [Option<&'static mut dyn Codec>; 0] = [];

    #[test]
    fn connect_disconnect_and_slot_reuse() {
        let mut server: Server = Server::new(NO_OBJECTS, &[], &[], unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        let s0 = server.on_connect(Media::Optical).unwrap();
        let _s1 = server.on_connect(Media::Optical).unwrap();
        let _s2 = server.on_connect(Media::Optical).unwrap();

        // The optical pool slot limit (N = 3) is exhausted.
        assert!(matches!(
            server.on_connect(Media::Optical),
            Err(Error::NoSlot)
        ));

        // Releasing a slot returns it to the pool.
        server.on_disconnect(s0.media());
        let _s3 = server.on_connect(Media::Optical).unwrap();
    }

    #[test]
    fn data_accumulates_and_overflow() {
        let mut server: Server = Server::new(NO_OBJECTS, &[], &[], unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });
        let mut s = server.on_connect(Media::Optical).unwrap();

        assert!(s.push_rx(&[1, 2, 3]));
        assert_eq!(s.rx(), &[1, 2, 3]);

        // rx-buffer overflow (push_rx returns false).
        let big = [0u8; RX_BUF + 1];
        assert!(!s.push_rx(&big));
    }
}

#[cfg(all(test, any(feature = "tcp", feature = "ble")))]
mod wrapper_tests {
    use crate::{AttrDesc, Media, Server, TransportRef, Wrapper};
    use cosempdu::acse::{ACSEApdu, RLRQapdu, ReleaseRequestReason, ReleaseResponseReason};
    use cosempdu::apdu::Conformance;
    use cosempdu::buffer::{ByteBuffer, Reader};
    use cosempdu::data::Codec;
    use dlms1::ic::InterfaceClass;

    const CONF: Conformance = Conformance([0x00, 0x7E, 0x1F]);
    static NO_OBJECTS: &[&dyn InterfaceClass] = &[];
    static mut NO_MUT: [Option<&'static mut dyn Codec>; 0] = [];

    /// Default catalog (LDN + 3 associations + Security setup) — for AARQ tests.
    static DEFAULT_OBJECTS: &[&dyn InterfaceClass] =
        &crate::merge_objects::<6>(&[], crate::OBJECTS);
    static DEFAULT_ATTRS: [AttrDesc; 14] =
        crate::merge_attrs::<14>(&[], crate::OBJECTS, &[], crate::ATTRS);
    static DEFAULT_CODECS: [&dyn Codec; 5] = crate::merge_codecs::<5>(&[], crate::ATTRS);

    #[test]
    fn wrapper_put_get_roundtrip() {
        let setting = Wrapper::new(0, 0x1234);

        let apdu = [0x0F, 0x01, 0x02, 0x03];
        let mut backing = [0u8; 64];
        let n = {
            let mut buf = ByteBuffer::new(&mut backing);
            setting.put(&mut buf, |b| b.write(&apdu)).unwrap()
        };

        let mut reader = Reader::new(&backing[..n]);
        let decoded = Wrapper::get(&mut reader).unwrap();
        assert_eq!(decoded.apdu_len() as usize, apdu.len());
        assert_eq!(decoded.destination_port(), 0x1234);
        assert_eq!(decoded.source_port(), 0);
        assert_eq!(reader.read(decoded.apdu_len() as usize).unwrap(), &apdu[..]);
    }

    /// RLRQ (release-request) → RLRE (normal) + association-release indication.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_rlrq() {
        use crate::AssociationState;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        // State after AARQ: src=server(1) → dst=client(16).
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));

        // RLRQ APDU (reason normal).
        let mut backing = [0u8; 16];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            RLRQapdu {
                reason: Some(ReleaseRequestReason::Normal),
                user_information: None,
            }
            .put(&mut b)
            .unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Must write RLRE into tx and put the session into Disconnecting.
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, AssociationState::Disconnecting);

        // Response: WPDU header + RLRE.
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Rlre(r) => assert_eq!(r.reason, Some(ReleaseResponseReason::Normal)),
            other => panic!("expected RLRE, got {other:?}"),
        }
    }

    /// AARQ → AARE + Session.state = Associated.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_aarq() {
        use crate::AssociationState;
        use cosempdu::acse::{AARQapdu, ApplicationContextName, AssociationResult};
        use cosempdu::apdu::InitiateRequest;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // AARQ APDU.
        let req = InitiateRequest::new(CONF, 1200);
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut apdu = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        // received: client (src=16) → server (dst=1).
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, AssociationState::Associated);

        // Response: AARE (accepted).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// AARQ with version-too-low → AARE(RejectedPermanent) + ConfirmedServiceError(initiate: dlms-version-too-low).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_dlms_version_too_low() {
        use crate::AssociationState;
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult,
        };
        use cosempdu::apdu::{
            confirmed_service_error_tag, ConfirmedServiceError, ImplicitTagged, Initiate,
            InitiateRequest, SnServiceError,
        };

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // AARQ APDU with proposed_dlms_version_number = 5 (< 6).
        let req = InitiateRequest {
            dedicated_key: None,
            response_allowed: true,
            proposed_dlms_version_number: 5,
            proposed_conformance: CONF,
            client_max_receive_pdu_size: 1200,
        };
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut apdu = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        // received: client (src=16) → server (dst=1).
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }

        // Association NOT established (stays in Idle).
        assert_eq!(session.settings.state, AssociationState::Idle);

        // Response: AARE (rejected-permanent) + ConfirmedServiceError(initiate: dlms-version-too-low).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => {
                assert_eq!(a.result, AssociationResult::RejectedPermanent);
                assert_eq!(
                    a.result_source_diagnostic,
                    AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven)
                );
                let ui = a.user_information.expect("AARE with user-information");
                let cse = ConfirmedServiceError::get(&mut Reader::new(ui)).unwrap();
                assert_eq!(cse.tag, confirmed_service_error_tag::INITIATE_ERROR);
                assert_eq!(
                    cse.service_error,
                    SnServiceError::Initiate(Initiate::DlmsVersionTooLow)
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// AARQ with ciphering but without calling-AP-title → AARE(RejectedPermanent) +
    /// acse-service-provider: no-reason-given.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_ciphering_without_calling_ap_title() {
        use crate::AssociationState;
        use cosempdu::acse::{
            AARQapdu, AcseServiceProvider, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult,
        };
        use cosempdu::apdu::InitiateRequest;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // AARQ with application-context = LogicalNameCiphering and NO calling-AP-title.
        let req = InitiateRequest::new(CONF, 1200);
        let mut ui = [0u8; 64];
        let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
        let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameCiphering);
        aarq.user_information = Some(&ui[..n]);
        let mut apdu = [0u8; 256];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        // received: client (src=16) → server (dst=1).
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }

        // Association NOT established (stays in Idle).
        assert_eq!(session.settings.state, AssociationState::Idle);

        // Response: AARE (rejected-permanent) + acse-service-provider: no-reason-given.
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => {
                assert_eq!(a.result, AssociationResult::RejectedPermanent);
                assert_eq!(
                    a.result_source_diagnostic,
                    AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::NoReasonGiven)
                );
            }
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// HLS 4-pass: pass 1 (AARQ with CtoS + certificate) → pass 2 (AARE accepted +
    /// StoC in responding-authentication-value + HLS 0x0E), plus rejections.
    #[cfg(all(feature = "tcp", any(feature = "ecdsa_p256", feature = "ecdsa_p384")))]
    #[test]
    fn process_request_hls_handshake() {
        use crate::{AssociationState, CallingAeQualifier, Session};
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult, AuthenticationValue, MechanismName,
        };
        use cosempdu::apdu::InitiateRequest;

        // Reset the global scratch (the only HLS test, but just in case).
        crate::hls_handshake().busy = false;
        crate::hls_handshake().qualifier = CallingAeQualifier::None;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);

        // Encode an AARQ (HLS/ECDSA) and put it into the session rx.
        fn put_aarq(session: &mut Session, cert: Option<&[u8]>, ctos: Option<&[u8]>) {
            let req = InitiateRequest::new(CONF, 1200);
            let mut ui = [0u8; 64];
            let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
            let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
            aarq.sender_acse_requirements = true;
            aarq.mechanism_name = Some(MechanismName::HighLevelSecurityEcdsa);
            aarq.calling_ae_qualifier = cert;
            aarq.calling_authentication_value = ctos.map(AuthenticationValue::CharString);
            aarq.user_information = Some(&ui[..n]);
            let mut apdu = [0u8; 256];
            let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
            session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
            session.set_rx_len(m);
        }

        let cert = [0x11u8; 64];
        let ctos = [0xAAu8; 16];

        // 1) Pass 1 (CtoS + certificate) → accepted + StoC + HLS (0x0E), state = Associating.
        let mut session = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session, Some(&cert), Some(&ctos));
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, AssociationState::Associating);
        {
            let tx = session.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => {
                    assert_eq!(a.result, AssociationResult::Accepted);
                    assert_eq!(
                        a.result_source_diagnostic,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::AuthenticationRequired
                        )
                    );
                    let stoc = [0x43u8; 16];
                    assert_eq!(
                        a.responding_authentication_value,
                        Some(AuthenticationValue::CharString(&stoc[..]))
                    );
                }
                other => panic!("expected AARE, got {other:?}"),
            }
        }
        session.clear_rx();

        // Release the scratch after pass 1 (pass 3/4 is a follow-up ACTION).
        crate::hls_handshake().busy = false;

        // 2) Pass 1 without a certificate → rejected-permanent (calling-AE-qualifier-not-recognized).
        let mut session2 = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session2, None, Some(&ctos));
        {
            let (settings, transport_ref, rx, tx) = session2.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session2.settings.state, AssociationState::Idle);
        {
            let tx = session2.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => {
                    assert_eq!(a.result, AssociationResult::RejectedPermanent);
                    assert_eq!(
                        a.result_source_diagnostic,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::CallingAeQualifierNotRecognized
                        )
                    );
                }
                other => panic!("expected AARE, got {other:?}"),
            }
        }
        session2.clear_rx();

        // 3) Scratch busy → rejected-transient.
        crate::hls_handshake().busy = true;
        let mut session3 = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session3, Some(&cert), Some(&ctos));
        {
            let (settings, transport_ref, rx, tx) = session3.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session3.settings.state, AssociationState::Idle);
        {
            let tx = session3.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::RejectedTransient),
                other => panic!("expected AARE, got {other:?}"),
            }
        }
        crate::hls_handshake().busy = false;
    }

    /// Unknown APDU tag (LN) → ExceptionResponse (service-unknown, operation-not-possible).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_unknown_tag_ln() {
        use cosempdu::apdu::{ExceptionResponse, ImplicitTagged, ServiceError_, StateError};

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));

        // Tag [2] context-specific primitive — not GetRequest/SetRequest/ACSE.
        session.rx_mut()[0] = 0x82;
        session.set_rx_len(1);

        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        let exc = ExceptionResponse::get(&mut Reader::new(apdu)).unwrap();
        assert_eq!(exc.state_error, StateError::ServiceUnknown);
        assert_eq!(exc.service_error, ServiceError_::OperationNotPossible);
    }

    /// LLS (LowLevelSecurity): the password from calling-authentication-value is compared with
    /// the association `secret` (attr 7); correct password → accepted, wrong → rejected.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_lls_secret() {
        use crate::{AssociationState, Session};
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult, AuthenticationValue, MechanismName,
        };
        use cosempdu::apdu::InitiateRequest;
        use dlms1::common_data_types::OctetString;

        // Association secrets (Persistent slots 2/3/4 of the default registry).
        static mut SECRET_PUBLIC: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut SECRET_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut SECRET_CONFIGURATOR: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut LLS_MUT: [Option<&'static mut dyn Codec>; 5] = [None, None, None, None, None];

        unsafe {
            LLS_MUT[2] = Some(&mut *core::ptr::addr_of_mut!(SECRET_PUBLIC));
            LLS_MUT[3] = Some(&mut *core::ptr::addr_of_mut!(SECRET_READER));
            LLS_MUT[4] = Some(&mut *core::ptr::addr_of_mut!(SECRET_CONFIGURATOR));
        }

        fn put_aarq(session: &mut Session, password: Option<&[u8]>) {
            let req = InitiateRequest::new(CONF, 1200);
            let mut ui = [0u8; 64];
            let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
            let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
            aarq.sender_acse_requirements = true;
            aarq.mechanism_name = Some(MechanismName::LowLevelSecurity);
            aarq.calling_authentication_value = password.map(AuthenticationValue::CharString);
            aarq.user_information = Some(&ui[..n]);
            let mut apdu = [0u8; 256];
            let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
            session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
            session.set_rx_len(m);
        }

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(LLS_MUT)
            });
        server.set_wport(1);

        // 1) Correct password → accepted, state = Associated.
        let mut session = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session, Some(b"ABCDEFGH"));
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, AssociationState::Associated);
        {
            let tx = session.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
                other => panic!("expected AARE, got {other:?}"),
            }
        }
        session.clear_rx();

        // 2) Wrong password → rejected-permanent + authentication-failure, state = Idle.
        let mut session2 = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session2, Some(b"WRONG"));
        {
            let (settings, transport_ref, rx, tx) = session2.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session2.settings.state, AssociationState::Idle);
        {
            let tx = session2.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => {
                    assert_eq!(a.result, AssociationResult::RejectedPermanent);
                    assert_eq!(
                        a.result_source_diagnostic,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::AuthenticationFailure
                        )
                    );
                }
                other => panic!("expected AARE, got {other:?}"),
            }
        }
    }

    /// `security_suite()` is resolved via `security_setup_reference` (attr 9)
    /// configurator → Security setup (class_id 64) → `security_suite` (attr 3).
    /// LLS associations (reader) have no reference → `None` (fallback AesGcm128).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_resolves_security_suite() {
        use dlms1::ic::{ClassId, SecuritySuite};

        let server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });

        // Configurator references the Security setup → AesGcm128 (enum 0).
        let (idx, _) = server
            .find_object(ClassId::AssociationLn, &crate::ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap();
        assert_eq!(
            server.security_suite(idx as u8),
            Some(SecuritySuite::AesGcm128)
        );

        // Reader (LLS) has no reference → None.
        let (idx, _) = server
            .find_object(ClassId::AssociationLn, &crate::ASSOC_LN_READER_OBIS)
            .unwrap();
        assert_eq!(server.security_suite(idx as u8), None);
    }

    /// Get-Request without an established association → "Association is not established"
    /// (LN: exception-response service-not-allowed / operation-not-possible).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_get_without_association_ln() {
        use cosempdu::apdu::{ExceptionResponse, ImplicitTagged, ServiceError_, StateError};

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));
        // state = Idle — no association established.

        session.rx_mut()[0] = 0xC0; // Get-Request [192]
        session.set_rx_len(1);

        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        let exc = ExceptionResponse::get(&mut Reader::new(apdu)).unwrap();
        assert_eq!(exc.state_error, StateError::ServiceNotAllowed);
        assert_eq!(exc.service_error, ServiceError_::OperationNotPossible);
    }

    /// Set-Request::Normal → the value is applied to the attribute; the response is null-data.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_set() {
        use crate::{Access, AssociationState, AttrDesc, AttrKind, AttrSpec};
        use cosempdu::apdu::{
            CosemAttributeDescriptor, DataAccessResult, ImplicitTagged, InvokeIdAndPriority,
            SetRequest, SetResponse, SetResponseNormal,
        };
        use dlms1::common_data_types::DoubleLongUnsigned;
        use dlms1::ic::{client_sap, AttributeAccessMode, AttributeKey, Register};
        use dlms1::obis::ObisCode;

        static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
        static OBJ_PAIRS: [(&dyn InterfaceClass, ObisCode); 1] = crate::objects![REG_OBJ];
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<1>(&[], &OBJ_PAIRS);

        static mut REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(REG_OBJ.obis, 2),
            access: Access {
                public: AttributeAccessMode::ReadOnly,
                reader: AttributeAccessMode::NoAccess,
                configurator: AttributeAccessMode::WriteOnly,
            },
            kind: AttrKind::Persistent(0),
        }];
        static ROM_ATTRS: [AttrDesc; 1] = crate::merge_attrs::<1>(&[], &OBJ_PAIRS, &[], &ATTRS);
        static mut MUT: [Option<&'static mut dyn Codec>; 1] = [None];

        unsafe {
            MUT[0] = Some(&mut *core::ptr::addr_of_mut!(REGISTER));
        }
        let mut server: Server = Server::new(OBJECTS, &ROM_ATTRS, &[], unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));
        session.settings.state = AssociationState::Associated;
        session.settings.client_sap = client_sap::CONFIGURATOR;

        // Set-Request::Normal: value = DoubleLongUnsigned(7).
        let invoke = InvokeIdAndPriority::from_bits(2, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: REG_OBJ.class_id().as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let value = DoubleLongUnsigned(7);
        let mut backing = [0u8; 128];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            SetRequest::put_normal(invoke, descriptor, None, &value, &mut b).unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Process: return true (continue); the attribute is updated.
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(unsafe { REGISTER.0 }, 7);

        // Response: SetResponse::Normal (success).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match SetResponse::get(&mut Reader::new(apdu)).unwrap() {
            SetResponse::Normal(SetResponseNormal {
                invoke,
                result: DataAccessResult::Success,
            }) => {
                assert_eq!(invoke.invoke_id(), 2);
            }
            other => panic!("expected SetResponse::Normal with success, got {other:?}"),
        }
    }

    /// Set-Request on a read-only attribute → SetResponse::Normal with ReadWriteDenied (does not abort).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_set_readonly() {
        use crate::{Access, AssociationState, AttrDesc, AttrKind, AttrSpec};
        use cosempdu::apdu::{
            CosemAttributeDescriptor, DataAccessResult, ImplicitTagged, InvokeIdAndPriority,
            SetRequest, SetResponse, SetResponseNormal,
        };
        use dlms1::common_data_types::DoubleLongUnsigned;
        use dlms1::ic::{client_sap, AttributeAccessMode, AttributeKey, Register};
        use dlms1::obis::ObisCode;

        static REG_OBJ: Register = Register::new(ObisCode::ACTIVE_ENERGY_IMPORT_TOTAL);
        static OBJ_PAIRS: [(&dyn InterfaceClass, ObisCode); 1] = crate::objects![REG_OBJ];
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<1>(&[], &OBJ_PAIRS);

        static REGISTER: DoubleLongUnsigned = DoubleLongUnsigned(0);
        static ATTRS: [AttrSpec; 1] = [AttrSpec {
            key: AttributeKey::new(REG_OBJ.obis, 2),
            access: Access {
                public: AttributeAccessMode::ReadOnly,
                reader: AttributeAccessMode::NoAccess,
                configurator: AttributeAccessMode::WriteOnly,
            },
            kind: AttrKind::Static(&REGISTER),
        }];
        static ROM_ATTRS: [AttrDesc; 1] = crate::merge_attrs::<1>(&[], &OBJ_PAIRS, &[], &ATTRS);
        static ROM_CODECS: [&dyn Codec; 1] = crate::merge_codecs::<1>(&[], &ATTRS);

        let mut server: Server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));
        session.settings.state = AssociationState::Associated;
        session.settings.client_sap = client_sap::CONFIGURATOR;

        // Set-Request::Normal: value = DoubleLongUnsigned(7).
        let invoke = InvokeIdAndPriority::from_bits(2, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: REG_OBJ.class_id().as_u16(),
            instance_id: REG_OBJ.obis().bytes,
            attribute_id: 2,
        };
        let value = DoubleLongUnsigned(7);
        let mut backing = [0u8; 128];
        let apdu_n = {
            let mut b = ByteBuffer::new(&mut backing);
            SetRequest::put_normal(invoke, descriptor, None, &value, &mut b).unwrap()
        };
        session.rx_mut()[..apdu_n].copy_from_slice(&backing[..apdu_n]);
        session.set_rx_len(apdu_n);

        // Process: do not abort (true); the response is ReadWriteDenied.
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }

        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match SetResponse::get(&mut Reader::new(apdu)).unwrap() {
            SetResponse::Normal(SetResponseNormal {
                invoke,
                result: DataAccessResult::ReadWriteDenied,
            }) => {
                assert_eq!(invoke.invoke_id(), 2);
            }
            other => panic!("expected SetResponse::Normal with ReadWriteDenied, got {other:?}"),
        }
    }
}
