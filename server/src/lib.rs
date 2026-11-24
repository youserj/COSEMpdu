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

use cosempdu::acse::{ApplicationContextName, MechanismName};
use cosempdu::apdu::Conformance;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::apdu::{
    ActionRequest, ActionRequestNormal, ActionResponse, ActionResponseWithOptionalDataWrite,
    ActionResult, CosemMethodDescriptor, ExceptionResponse, GetRequest, GetRequestNormal,
    ServiceError_, SetRequest, SetRequestNormal, SetResponse, StateError,
};
use cosempdu::apdu::{
    CosemAttributeDescriptor, DataAccessResult, GetDataResultWrite, GetResponse, ImplicitTagged,
    InvokeIdAndPriority, DLMS_VERSION_NUMBER,
};
use cosempdu::axdr::put_length;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::buffer::ArrayBuffer;
use cosempdu::buffer::ByteBuffer;
use cosempdu::data::{Codec, Data};
use cosempdu::stream::{StreamDecoder, StreamSink};
use dlms1::ic::association_ln::{
    write_object_list as encode_object_list, AssociationStatus, ObjectListElementInfo,
    ObjectListSink, ObjectListSource, ATTR_APPLICATION_CONTEXT_NAME, ATTR_ASSOCIATION_STATUS,
    ATTR_AUTHENTICATION_MECHANISM_NAME, ATTR_LOGICAL_NAME, ATTR_OBJECT_LIST,
    ATTR_SECURITY_SETUP_REFERENCE, ATTR_XDLMS_CONTEXT_INFO,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use dlms1::ic::association_ln::{
    ATTR_ASSOCIATED_PARTNERS_ID, ATTR_SECRET, METHOD_CHANGE_HLS_SECRET,
};
#[cfg(any(feature = "tcp", feature = "ble"))]
use dlms1::ic::security_setup::ATTR_SECURITY_SUITE;
#[cfg(any(feature = "tcp", feature = "ble"))]
use dlms1::ic::SecuritySuite;
use dlms1::ic::{
    client_sap, AssociatedPartners, AssociationLn, AttributeAccessMode, AttributeKey, ClassId,
    ContextNameStructure, DataObject, InterfaceClass, MechanismNameStructure, MethodAccessMode,
    MethodKey, SecuritySetup, XdlmsContextInfoValue,
};
use dlms1::obis::ObisCode;
use dlms1::{BitString, Enum, LongUnsigned, OctetString, OctetStringSized, Unsigned};
#[cfg(any(feature = "tcp", feature = "ble"))]
use methods::{action_result, ActionOutcome};

#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::{
    AARQapdu, ACSEApdu, AcseServiceProvider, AcseServiceUser, AssociateSourceDiagnostic,
    AssociationResult, BerTagged, RLREapdu, ReleaseResponseReason, SystemTitle,
};

#[cfg(all(
    any(feature = "tcp", feature = "ble"),
    any(feature = "ecdsa_p256", feature = "ecdsa_p384")
))]
use cosempdu::acse::AAREapdu;
#[cfg(any(feature = "tcp", feature = "ble"))]
use cosempdu::acse::AuthenticationValue;
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
#[cfg(any(feature = "tcp", feature = "ble"))]
mod methods;
mod once;
mod session;
mod transport;

pub use once::OnceCell;
pub use session::{DedicatedKey, GetBlock, SessionState, Settings};

#[cfg(any(feature = "ecdsa_p256", feature = "ecdsa_p384"))]
pub use session::CallingAeQualifier;

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use session::{Session, RX_BUF};

#[cfg(any(feature = "optical", feature = "tcp", feature = "ble"))]
pub use transport::{Media, TransportRef, MAX_APDU, TRANSPORT_OVERHEAD};

#[cfg(any(feature = "tcp", feature = "ble"))]
pub use transport::WPDU_HEADER_LEN;

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

/// `authentication_mechanism_name` (attr 6) mechanism ids of the default
/// associations (`mechanism_name_type` last arc): `0` — lowest level security
/// (no authentication), `1` — LLS, `2`…`7` — HLS variants. The public
/// association is anonymous; LLS belongs to the reader, HLS to the configurator.
pub const AUTH_MECH_PUBLIC: u8 = MechanismName::LowestLevelSecurity as u8;
pub const AUTH_MECH_READER: u8 = MechanismName::LowLevelSecurity as u8;
pub const AUTH_MECH_CONFIGURATOR: u8 = MechanismName::HighLevelSecurity as u8;

/// `authentication_mechanism_name` (attr 6) of the associations:
/// `{ 2 16 756 5 8 2 <id> }`.
pub static ASSOC_AUTH_MECH_PUBLIC: MechanismNameStructure =
    MechanismNameStructure::new(AUTH_MECH_PUBLIC);
pub static ASSOC_AUTH_MECH_READER: MechanismNameStructure =
    MechanismNameStructure::new(AUTH_MECH_READER);
pub static ASSOC_AUTH_MECH_CONFIGURATOR: MechanismNameStructure =
    MechanismNameStructure::new(AUTH_MECH_CONFIGURATOR);

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
static LDN_BASE: OnceCell<OctetStringSized<16>> = OnceCell::new();

/// Initialize the base LDN with the default value
/// (3 bytes of [`MAN_ID`] + 13 zeros) and return a mutable reference.
pub fn init_ldn_base() -> &'static mut OctetStringSized<16> {
    LDN_BASE.init(OctetStringSized([
        MAN_ID[0], MAN_ID[1], MAN_ID[2], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]))
}

/// Storage for the server-system-title (mutable; initialized by
/// [`init_server_system_title`]).
static SERVER_SYSTEM_TITLE: OnceCell<OctetStringSized<8>> = OnceCell::new();

/// Initialize the server-system-title with the default value
/// (3 bytes of [`MAN_ID`] + 5 zeros) and return a mutable reference.
pub fn init_server_system_title() -> &'static mut OctetStringSized<8> {
    SERVER_SYSTEM_TITLE.init(OctetStringSized([
        MAN_ID[0], MAN_ID[1], MAN_ID[2], 0, 0, 0, 0, 0,
    ]))
}

/// Default LLS secrets (attr 7) of the LLS associations (mutable; initialized
/// in [`init_mutable_defaults`] with the standard password [`DEFAULT_LLS_SECRET`]).
static ASSOC_SECRET_READER: OnceCell<OctetString<16>> = OnceCell::new();
static ASSOC_SECRET_CONFIGURATOR: OnceCell<OctetString<16>> = OnceCell::new();

/// Default LLS password (the standard DLMS ABCDEFGH).
const DEFAULT_LLS_SECRET: &[u8] = b"ABCDEFGH";

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
/// Security setup ([`init_server_system_title`], attr 5), slots 2–3 — the
/// LLS secrets of the reader/configurator associations (attr 7). The public
/// association is anonymous, so it has no secret.
///
/// Matches the default [`ATTRS`] spec (slot 0, server-system-title
/// slot 1 and secrets 2–3). The `mutable` array must contain at least 4 slots.
pub fn init_mutable_defaults(mutable: &mut [Option<&'static mut dyn Codec>]) {
    mutable[0] = Some(init_ldn_base());
    mutable[1] = Some(init_server_system_title());
    mutable[2] = Some(init_assoc_secret_reader());
    mutable[3] = Some(init_assoc_secret_configurator());
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

/// Build the `xDLMS_context_info` value (Association LN, attr 5).
/// `max_receive_pdu_size`/`dlms_version_number` are server constants; the caller
/// supplies the association-dependent `conformance`, `max_send_pdu_size` and
/// `cyphering_info`.
fn xdlms_context_info(
    conformance: Conformance,
    max_send_pdu_size: u16,
    cyphering_info: OctetString<32>,
) -> XdlmsContextInfoValue {
    XdlmsContextInfoValue {
        conformance: BitString {
            bytes: conformance.0,
            bit_len: 24,
        },
        max_receive_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
        max_send_pdu_size: LongUnsigned(max_send_pdu_size),
        dlms_version_number: Unsigned(DLMS_VERSION_NUMBER),
        cyphering_info,
    }
}

/// Default `xDLMS_context_info` for a non-current Association LN association
/// (public/reader/configurator): there is no negotiated session, so the value
/// uses the server's proposed conformance, the server's PDU capability for both
/// receive and send, and no dedicated key.
const DEFAULT_XDLMS_CONTEXT_INFO: XdlmsContextInfoValue = XdlmsContextInfoValue {
    conformance: BitString {
        bytes: PROPOSED_CONFORMANCE.0,
        bit_len: 24,
    },
    max_receive_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
    max_send_pdu_size: LongUnsigned(SERVER_MAX_RECEIVE_PDU_SIZE),
    dlms_version_number: Unsigned(DLMS_VERSION_NUMBER),
    cyphering_info: OctetString::new(&[]),
};

/// Map the session state to the `association_status` value (Association LN, attr 8).
fn association_status(state: SessionState) -> AssociationStatus {
    match state {
        SessionState::Idle | SessionState::Disconnecting => AssociationStatus::NonAssociated,
        SessionState::Associating => AssociationStatus::AssociationPending,
        SessionState::Associated => AssociationStatus::Associated,
    }
}

/// Security level of an `authentication_mechanism_name` id (the last OID arc):
/// `0` — no authentication, `1` — LLS, `2`…`7` — any HLS variant.
#[cfg(any(feature = "tcp", feature = "ble"))]
const fn mechanism_level(id: u8) -> u8 {
    match id {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}

/// Access mode advertised in `object_list`; `None` means "not listed".
fn access_mode(access: Access, sap: u8) -> Option<AttributeAccessMode> {
    match access.for_sap(sap) {
        Some(AttributeAccessMode::NoAccess) | None => None,
        Some(mode) => Some(mode),
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

/// Compile-time method spec: object OBIS + method number + per-level rights.
/// Resolved to [`MethodDesc`] by [`merge_methods`] (OBIS → object index).
///
/// Handlers are separate functions ([`crate::methods`]); the ROM registry
/// ([`MethodDesc`]) stores the key and the access rights, and the dispatch
/// `match` in `Server::handle_action` picks the handler.
#[derive(Clone, Copy)]
pub struct MethodSpec {
    /// Compile-time method reference (object OBIS + method id), e.g.
    /// `AssociationLn::new(obis).change_hls_secret()`.
    pub key: MethodKey,
    pub access: MethodAccess,
}

/// Resolved method key in the ROM registry: object index in the catalog +
/// method number.
///
/// OBIS is not stored (it is already in the object) — like [`AttrKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodDescKey {
    /// Object index in the OBIS-sorted catalog.
    pub object: u16,
    /// Method number (method_id) — ASN.1 `Integer8`, as on the wire.
    pub method_id: i8,
}

/// Object method descriptor: key + per-level rights (a method-registry entry).
#[derive(Clone, Copy)]
pub struct MethodDesc {
    /// Method key (object index + method number).
    pub key: MethodDescKey,
    /// Method invocation rights per level.
    pub access: MethodAccess,
}

/// Whether a method is visible to a client level in `object_list`.
const fn method_visible(access: MethodAccess, sap: u8) -> bool {
    matches!(access.for_sap(sap), Some(m) if !matches!(m, MethodAccessMode::NoAccess))
}

/// Whether the dispatch of [`Server::handle_action`] has a handler for
/// `(class_id, method_id)`.
///
/// Kept next to the dispatch so that the ROM registry ([`METHODS`]) and the
/// handlers ([`crate::methods`]) cannot drift silently — see the
/// `every_registry_method_has_handler` test.
#[cfg(any(feature = "tcp", feature = "ble"))]
const fn has_handler(class_id: ClassId, method_id: i8) -> bool {
    matches!(
        (class_id, method_id),
        (ClassId::AssociationLn, METHOD_CHANGE_HLS_SECRET)
    )
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
    /// Attribute number (attribute-id) — ASN.1 `Integer8`, as on the wire.
    pub attribute_id: i8,
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

/// `secret` (attr 7) of an association: read-only for its own client level
/// after authentication; the value is changed through the Association LN
/// method `change_HLS_secret` (method 2), not SET. All other levels have no
/// access.
const READER_SECRET_ACCESS: Access = Access {
    public: AttributeAccessMode::NoAccess,
    reader: AttributeAccessMode::AuthenticatedReadOnly,
    configurator: AttributeAccessMode::NoAccess,
};
const CONFIGURATOR_SECRET_ACCESS: Access = Access {
    public: AttributeAccessMode::NoAccess,
    reader: AttributeAccessMode::NoAccess,
    configurator: AttributeAccessMode::AuthenticatedReadOnly,
};

/// Default LDN attribute descriptor (value, attr 2):
/// read-only for all levels, slot 0.
pub const LDN_ATTR_DESC: AttrSpec = AttrSpec {
    key: DataObject::new(LDN_OBIS).value(),
    access: RO,
    kind: AttrKind::Dynamic(0),
};

/// `associated_partners_id` (attr 3) of the public association (Static, read-only).
pub const ASSOC_LN_PUBLIC_ATTR_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).associated_partners_id(),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_PUBLIC),
};

/// `associated_partners_id` (attr 3) of the reader association (Static, read-only).
pub const ASSOC_LN_READER_ATTR_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).associated_partners_id(),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_READER),
};

/// `associated_partners_id` (attr 3) of the configurator association (Static, read-only).
pub const ASSOC_LN_CONFIGURATOR_ATTR_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).associated_partners_id(),
    access: RO,
    kind: AttrKind::Static(&ASSOC_PARTNERS_CONFIGURATOR),
};

/// `authentication_mechanism_name` (attr 6) of the public association (Static, read-only): LLS.
pub const ASSOC_LN_PUBLIC_AUTH_MECH_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).authentication_mechanism_name(),
    access: RO,
    kind: AttrKind::Static(&ASSOC_AUTH_MECH_PUBLIC),
};

/// `authentication_mechanism_name` (attr 6) of the reader association (Static, read-only): LLS.
pub const ASSOC_LN_READER_AUTH_MECH_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).authentication_mechanism_name(),
    access: RO,
    kind: AttrKind::Static(&ASSOC_AUTH_MECH_READER),
};

/// `authentication_mechanism_name` (attr 6) of the configurator association
/// (Static, read-only): HLS.
pub const ASSOC_LN_CONFIGURATOR_AUTH_MECH_DESC: AttrSpec = AttrSpec {
    key: AttributeKey::new(
        ASSOC_LN_CONFIGURATOR_OBIS,
        ATTR_AUTHENTICATION_MECHANISM_NAME,
    ),
    access: RO,
    kind: AttrKind::Static(&ASSOC_AUTH_MECH_CONFIGURATOR),
};

/// `secret` (attr 7) of the reader association (Persistent, slot 2; read-only for
/// the reader's own level after authentication; SET only via method 2).
pub const ASSOC_LN_READER_SECRET_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).secret(),
    access: READER_SECRET_ACCESS,
    kind: AttrKind::Persistent(2),
};

/// `secret` (attr 7) of the configurator association (Persistent, slot 3;
/// read-only for the configurator's own level after authentication; SET only
/// via method 2).
pub const ASSOC_LN_CONFIGURATOR_SECRET_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).secret(),
    access: CONFIGURATOR_SECRET_ACCESS,
    kind: AttrKind::Persistent(3),
};

/// `security_setup_reference` (attr 9) of the configurator association (Static, read-only):
/// the Security setup object's OBIS (`0.0.43.0.1.255`). LLS associations (reader) have no
/// such reference — their `security_suite` stays default (unused).
pub const ASSOC_LN_CONFIGURATOR_SECURITY_SETUP_REF_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).security_setup_reference(),
    access: RO,
    kind: AttrKind::Static(&SECURITY_SETUP_REF),
};

/// Access ceiling of a shared object (Security setup): it is reachable only by
/// the association that references it via `security_setup_reference` (attr 9).
/// There is exactly one association per client level, so the reference is
/// expressed as the per-level ceiling — the configurator is the referencing one,
/// public/reader have no access.
const SHARED_READ: Access = Access {
    public: AttributeAccessMode::NoAccess,
    reader: AttributeAccessMode::NoAccess,
    configurator: AttributeAccessMode::ReadOnly,
};

/// Write side of [`SHARED_READ`] (same reachability rule).
const SHARED_WRITE: Access = Access {
    public: AttributeAccessMode::NoAccess,
    reader: AttributeAccessMode::NoAccess,
    configurator: AttributeAccessMode::WriteOnly,
};

/// `security_suite` (attr 3) Security setup (Static, read-only, shared).
pub const SECURITY_SETUP_SUITE_DESC: AttrSpec = AttrSpec {
    key: SecuritySetup::new(SECURITY_SETUP_OBIS).security_suite(),
    access: SHARED_READ,
    kind: AttrKind::Static(&SECURITY_SUITE_VALUE),
};

/// `server_system_title` (attr 5) of Security setup (Dynamic, slot 1, shared).
pub const SECURITY_SETUP_SYSTEM_TITLE_DESC: AttrSpec = AttrSpec {
    key: SecuritySetup::new(SECURITY_SETUP_OBIS).server_system_title(),
    access: SHARED_WRITE,
    kind: AttrKind::Dynamic(1),
};

/// `xDLMS_context_info` (attr 5) of the public association (Computed — on the fly).
pub const ASSOC_LN_PUBLIC_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).xdlms_context_info(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the reader association (Computed — on the fly).
pub const ASSOC_LN_READER_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).xdlms_context_info(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the configurator association (Computed — on the fly).
pub const ASSOC_LN_CONFIGURATOR_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).xdlms_context_info(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `xDLMS_context_info` (attr 5) of the base association (`0.0.40.0.0.255`) —
/// always available (alias of the current association).
pub const ASSOC_LN_BASE_XDLMS_CONTEXT_INFO_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_BASE_OBIS).xdlms_context_info(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `association_status` (attr 8) of the public association (Computed — on the fly).
pub const ASSOC_LN_PUBLIC_ASSOCIATION_STATUS_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).association_status(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `association_status` (attr 8) of the reader association (Computed — on the fly).
pub const ASSOC_LN_READER_ASSOCIATION_STATUS_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).association_status(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `association_status` (attr 8) of the configurator association (Computed — on the fly).
pub const ASSOC_LN_CONFIGURATOR_ASSOCIATION_STATUS_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).association_status(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `association_status` (attr 8) of the base association (`0.0.40.0.0.255`) —
/// always available (alias of the current association).
pub const ASSOC_LN_BASE_ASSOCIATION_STATUS_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_BASE_OBIS).association_status(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `object_list` (attr 2) of the public association (Computed — on the fly).
pub const ASSOC_LN_PUBLIC_OBJECT_LIST_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).object_list(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `object_list` (attr 2) of the reader association (Computed — on the fly).
pub const ASSOC_LN_READER_OBJECT_LIST_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).object_list(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `object_list` (attr 2) of the configurator association (Computed — on the fly).
pub const ASSOC_LN_CONFIGURATOR_OBJECT_LIST_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).object_list(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `object_list` (attr 2) of the base association (`0.0.40.0.0.255`) —
/// always available (alias of the current association).
pub const ASSOC_LN_BASE_OBJECT_LIST_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_BASE_OBIS).object_list(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `application_context_name` (attr 4) of the public association (Computed).
pub const ASSOC_LN_PUBLIC_APPLICATION_CONTEXT_NAME_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_PUBLIC_OBIS).application_context_name(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `application_context_name` (attr 4) of the reader association (Computed).
pub const ASSOC_LN_READER_APPLICATION_CONTEXT_NAME_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_READER_OBIS).application_context_name(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `application_context_name` (attr 4) of the configurator association (Computed).
pub const ASSOC_LN_CONFIGURATOR_APPLICATION_CONTEXT_NAME_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).application_context_name(),
    access: RO,
    kind: AttrKind::Computed,
};

/// `application_context_name` (attr 4) of the base association (Computed).
pub const ASSOC_LN_BASE_APPLICATION_CONTEXT_NAME_DESC: AttrSpec = AttrSpec {
    key: AssociationLn::new(ASSOC_LN_BASE_OBIS).application_context_name(),
    access: RO,
    kind: AttrKind::Computed,
};

/// Default attribute registry.
pub const ATTRS: &[AttrSpec] = &[
    LDN_ATTR_DESC,
    ASSOC_LN_PUBLIC_ATTR_DESC,
    ASSOC_LN_READER_ATTR_DESC,
    ASSOC_LN_CONFIGURATOR_ATTR_DESC,
    ASSOC_LN_PUBLIC_AUTH_MECH_DESC,
    ASSOC_LN_READER_AUTH_MECH_DESC,
    ASSOC_LN_CONFIGURATOR_AUTH_MECH_DESC,
    ASSOC_LN_READER_SECRET_DESC,
    ASSOC_LN_CONFIGURATOR_SECRET_DESC,
    ASSOC_LN_CONFIGURATOR_SECURITY_SETUP_REF_DESC,
    ASSOC_LN_BASE_OBJECT_LIST_DESC,
    ASSOC_LN_PUBLIC_OBJECT_LIST_DESC,
    ASSOC_LN_READER_OBJECT_LIST_DESC,
    ASSOC_LN_CONFIGURATOR_OBJECT_LIST_DESC,
    ASSOC_LN_BASE_APPLICATION_CONTEXT_NAME_DESC,
    ASSOC_LN_PUBLIC_APPLICATION_CONTEXT_NAME_DESC,
    ASSOC_LN_READER_APPLICATION_CONTEXT_NAME_DESC,
    ASSOC_LN_CONFIGURATOR_APPLICATION_CONTEXT_NAME_DESC,
    ASSOC_LN_BASE_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_PUBLIC_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_READER_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_CONFIGURATOR_XDLMS_CONTEXT_INFO_DESC,
    ASSOC_LN_BASE_ASSOCIATION_STATUS_DESC,
    ASSOC_LN_PUBLIC_ASSOCIATION_STATUS_DESC,
    ASSOC_LN_READER_ASSOCIATION_STATUS_DESC,
    ASSOC_LN_CONFIGURATOR_ASSOCIATION_STATUS_DESC,
    SECURITY_SETUP_SUITE_DESC,
    SECURITY_SETUP_SYSTEM_TITLE_DESC,
];

/// `change_HLS_secret` (Association LN method 2) rights: only the owning
/// association, after authentication.
const READER_METHOD_ACCESS: MethodAccess = MethodAccess {
    public: MethodAccessMode::NoAccess,
    reader: MethodAccessMode::AuthenticatedAccess,
    configurator: MethodAccessMode::NoAccess,
};
const CONFIGURATOR_METHOD_ACCESS: MethodAccess = MethodAccess {
    public: MethodAccessMode::NoAccess,
    reader: MethodAccessMode::NoAccess,
    configurator: MethodAccessMode::AuthenticatedAccess,
};

/// Default method registry: `change_HLS_secret` on the reader and configurator
/// associations (public is anonymous and has no secret). Resolve it with
/// [`merge_methods`] against the same object catalog.
pub const METHODS: &[MethodSpec] = &[
    MethodSpec {
        key: AssociationLn::new(ASSOC_LN_READER_OBIS).change_hls_secret(),
        access: READER_METHOD_ACCESS,
    },
    MethodSpec {
        key: AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).change_hls_secret(),
        access: CONFIGURATOR_METHOD_ACCESS,
    },
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

/// Lexicographic method-key comparison (object index + method number).
const fn method_key_lt(a: MethodDescKey, b: MethodDescKey) -> bool {
    if a.object != b.object {
        return a.object < b.object;
    }
    a.method_id < b.method_id
}

/// Resolve a method spec: OBIS → object index (transiently).
const fn resolve_method(
    spec: MethodSpec,
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
) -> MethodDesc {
    MethodDesc {
        key: MethodDescKey {
            object: object_rank(spec.key.obis, defaults, app),
            method_id: spec.key.method_id,
        },
        access: spec.access,
    }
}

/// Merge the default methods with the application methods: resolve OBIS to the
/// object index and sort by `(object, method_id)` (compile-time).
///
/// `TOTAL` is given explicitly (= `default_methods.len() + app_methods.len()`).
pub const fn merge_methods<const TOTAL: usize>(
    defaults: &[(&'static dyn InterfaceClass, ObisCode)],
    app: &[(&'static dyn InterfaceClass, ObisCode)],
    default_methods: &[MethodSpec],
    app_methods: &[MethodSpec],
) -> [MethodDesc; TOTAL] {
    if default_methods.len() + app_methods.len() != TOTAL {
        panic!("merge_methods: TOTAL must equal default_methods.len() + app_methods.len()");
    }

    // 1) Resolve specs (order: defaults, then app).
    let first = if default_methods.len() > 0 {
        resolve_method(default_methods[0], defaults, app)
    } else {
        resolve_method(app_methods[0], defaults, app)
    };
    let mut out: [MethodDesc; TOTAL] = [first; TOTAL];
    let mut i = 0;
    while i < default_methods.len() {
        out[i] = resolve_method(default_methods[i], defaults, app);
        i += 1;
    }
    let mut j = 0;
    while j < app_methods.len() {
        out[default_methods.len() + j] = resolve_method(app_methods[j], defaults, app);
        j += 1;
    }

    // 2) Insertion sort by key.
    let mut k = 1;
    while k < TOTAL {
        let mut m = k;
        while m > 0 && method_key_lt(out[m].key, out[m - 1].key) {
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
    /// ROM: sorted method registry (key + rights); see [`merge_methods`].
    methods: &'static [MethodDesc],
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

/// Attribute value for GET: either a reference to a stored value or a computed
/// attribute (`xDLMS_context_info` / `association_status`, Association LN
/// attrs 5 and 8).
pub enum GetValue<'a> {
    /// Stored value (Static/Dynamic/Persistent).
    Codec(&'a dyn Codec),
    /// Computed value — resolved to a [`ComputedKind`], encoded per request.
    Computed(ComputedKind),
}

/// Which computed attribute to encode. Values are (re)encoded on demand
/// (strategy 1: re-encode from the start, then copy the requested window), so
/// no owned value is materialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputedKind {
    /// `xDLMS_context_info` of the current association (negotiated params).
    XdlmsContextInfo,
    /// `xDLMS_context_info` of a foreign association (server defaults).
    DefaultXdlmsContextInfo,
    /// `association_status` of the current association (from the session state).
    AssociationStatus,
    /// `association_status` of a foreign association (non-associated).
    DefaultAssociationStatus,
    /// Association LN `object_list` for the given client_SAP.
    ObjectList(u8),
    /// Attribute 1 (`logical_name`) of a catalog object (octet-string).
    LogicalName(ObisCode),
    /// Association LN `application_context_name` (attr 4).
    ApplicationContext(ApplicationContextName),
}

/// Scratch big enough for the small computed values (`xDLMS_context_info` is
/// 19 B, `association_status` — 2 B).
const COMPUTED_SCRATCH: usize = 64;

/// Length of the dedicated key in bytes (for the `xDLMS_context_info` length).
const fn dedicated_key_len(key: DedicatedKey) -> usize {
    match key {
        DedicatedKey::None => 0,
        #[cfg(feature = "aes128")]
        DedicatedKey::Aes128(_) => 16,
        #[cfg(feature = "aes256")]
        DedicatedKey::Aes256(_) => 32,
    }
}

/// A-XDR length-prefix size for `value` (matches `cosempdu::axdr::put_length`).
const fn length_prefix_len(value: usize) -> usize {
    if value <= 0x7F {
        1
    } else {
        let bits = 64 - (value as u64).leading_zeros();
        1 + ((bits + 7) / 8) as usize
    }
}

/// Byte sink used by the `object_list` encoder: the same encoder both measures
/// the full length and copies a block window, so offsets stay consistent.
/// Counts bytes (for the full encoded length).
struct CountingSink {
    len: usize,
}

impl ObjectListSink for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> cosempdu::Result<()> {
        self.len += bytes.len();
        Ok(())
    }
}

/// Writes straight into a `ByteBuffer` (normal response path).
struct BufferSink<'a, 'b> {
    out: &'a mut ByteBuffer<'b>,
}

impl ObjectListSink for BufferSink<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> cosempdu::Result<()> {
        self.out.write(bytes)?;
        Ok(())
    }
}

/// Copies only the window `[offset, offset + max)` (strategy 1 block path).
struct WindowSink<'a, 'b> {
    out: &'a mut ByteBuffer<'b>,
    offset: usize,
    end: usize,
    seen: usize,
}

impl ObjectListSink for WindowSink<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> cosempdu::Result<()> {
        let start = self.seen;
        let end = start + bytes.len();
        let lo = start.max(self.offset);
        let hi = end.min(self.end);
        if lo < hi {
            self.out.write(&bytes[lo - start..hi - start])?;
        }
        self.seen = end;
        Ok(())
    }
}

/// `Codec` adapter: lets `GetResponse::put_normal` encode a computed value.
struct ComputedCodec<'a, const N: usize> {
    server: &'a Server<N>,
    kind: ComputedKind,
    ctx: &'a Settings,
}

impl<const N: usize> Codec for ComputedCodec<'_, N> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        self.server.computed_put(self.kind, self.ctx, buf)
    }

    fn assign(&mut self, _: &Data<'_>) -> cosempdu::Result<()> {
        Err(cosempdu::Error::Message("attribute is read-only"))
    }
}

impl Codec for GetValue<'_> {
    fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
        match self {
            GetValue::Codec(c) => c.put(buf),
            // A computed value needs the session context; it is encoded by
            // `handle_get`, not through this adapter.
            GetValue::Computed(_) => Err(cosempdu::Error::Message(
                "computed value must be encoded via handle_get",
            )),
        }
    }

    fn assign(&mut self, _: &Data<'_>) -> cosempdu::Result<()> {
        Err(cosempdu::Error::Message("attribute is read-only"))
    }
}

/// `object_list` source for a given client_SAP (Association LN v1).
///
/// The A-XDR layout is owned by `DLMS1::ic::association_ln::write_object_list`;
/// here only the data is supplied.
struct ServerObjectList<'a, const N: usize> {
    server: &'a Server<N>,
    /// Client_SAP the list is rendered for (per-level access rights).
    sap: u8,
}

impl<const N: usize> ObjectListSource for ServerObjectList<'_, N> {
    fn object_count(&self) -> usize {
        (0..self.server.objects.len())
            .filter(|&index| self.visible(index))
            .count()
    }

    fn element(&self, index: usize) -> ObjectListElementInfo {
        let index = self
            .catalog_index(index)
            .expect("object_list element index out of range");
        let obj = self.server.objects[index];
        ObjectListElementInfo {
            class_id: obj.class_id(),
            version: obj.version(),
            logical_name: obj.obis(),
        }
    }

    fn attribute_count(&self, index: usize) -> usize {
        let Some(index) = self.catalog_index(index) else {
            return 0;
        };
        1 + self
            .server
            .object_attrs(index as u16)
            .filter(|d| access_mode(d.access, self.sap).is_some())
            .count()
    }

    fn attribute(&self, index: usize, item: usize) -> (i8, AttributeAccessMode) {
        if item == 0 {
            // Attribute 1 (`logical_name`) is always readable and is not in ATTRS.
            return (ATTR_LOGICAL_NAME, AttributeAccessMode::ReadOnly);
        }
        let Some(index) = self.catalog_index(index) else {
            return (0, AttributeAccessMode::NoAccess);
        };
        let mut remaining = item - 1;
        for desc in self.server.object_attrs(index as u16) {
            if let Some(mode) = access_mode(desc.access, self.sap) {
                if remaining == 0 {
                    return (desc.key.attribute_id, mode);
                }
                remaining -= 1;
            }
        }
        // Contract: `item < attribute_count(index)`.
        (0, AttributeAccessMode::NoAccess)
    }

    fn method_count(&self, index: usize) -> usize {
        let Some(index) = self.catalog_index(index) else {
            return 0;
        };
        self.methods_for(index)
            .iter()
            .filter(|d| method_visible(d.access, self.sap))
            .count()
    }

    fn method(&self, index: usize, item: usize) -> (i8, MethodAccessMode) {
        let Some(index) = self.catalog_index(index) else {
            return (0, MethodAccessMode::NoAccess);
        };
        self.methods_for(index)
            .iter()
            .filter(|d| method_visible(d.access, self.sap))
            .nth(item)
            .map(|d| {
                (
                    d.key.method_id,
                    d.access
                        .for_sap(self.sap)
                        .unwrap_or(MethodAccessMode::NoAccess),
                )
            })
            .unwrap_or((0, MethodAccessMode::NoAccess))
    }
}

impl<const N: usize> ServerObjectList<'_, N> {
    /// Whether the catalog object at `index` exposes anything to this client level
    /// (see [`Server::object_visible`]).
    fn visible(&self, index: usize) -> bool {
        self.server.object_visible(index as u16, self.sap)
    }

    /// Catalog index of the `visible`-th listed object, `None` when the caller
    /// violates the `item < object_count()` contract.
    fn catalog_index(&self, visible: usize) -> Option<usize> {
        let mut seen = 0;
        for index in 0..self.server.objects.len() {
            if self.visible(index) {
                if seen == visible {
                    return Some(index);
                }
                seen += 1;
            }
        }
        None
    }

    /// Registry entries of the object at catalog `index` (sorted by method number).
    fn methods_for(&self, index: usize) -> &[MethodDesc] {
        self.server.methods_of(index as u16)
    }
}

/// Error of [`Server::find_object`]: the OBIS is absent from the catalog or the
/// object has a different `class_id`. Converted to the service-specific error
/// type at the call site (`DataAccessResult` / `ActionResult`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FindObjectError {
    ObjectUnavailable,
    ObjectClassInconsistent,
}

impl From<FindObjectError> for DataAccessResult {
    fn from(error: FindObjectError) -> Self {
        match error {
            FindObjectError::ObjectUnavailable => DataAccessResult::ObjectUnavailable,
            FindObjectError::ObjectClassInconsistent => DataAccessResult::ObjectClassInconsistent,
        }
    }
}

#[cfg(any(feature = "tcp", feature = "ble"))]
impl From<FindObjectError> for ActionResult {
    fn from(error: FindObjectError) -> Self {
        match error {
            FindObjectError::ObjectUnavailable => ActionResult::ObjectUnavailable,
            FindObjectError::ObjectClassInconsistent => ActionResult::ObjectClassInconsistent,
        }
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
            methods: &[],
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

    /// Attach the method registry (resolved with [`merge_methods`] against the
    /// same object catalog). Without it ACTION requests return
    /// `ObjectUndefined` and `object_list` advertises no methods.
    pub fn with_methods(mut self, methods: &'static [MethodDesc]) -> Self {
        self.methods = methods;
        self
    }

    /// Binary search of a method descriptor by key `(object index, number)`.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn method(&self, object: u16, method_id: i8) -> Option<MethodDesc> {
        let key = MethodDescKey { object, method_id };
        self.methods
            .binary_search_by_key(&key, |d| d.key)
            .ok()
            .map(|i| self.methods[i])
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

    /// Find an object by OBIS, check its class and return `(index, object)`.
    ///
    /// `class_id` is the numeric class id taken straight from the request
    /// descriptor: the class is validated against the catalog object here, so the
    /// call sites need no separate `ClassId::from_u16` check (an unknown class id
    /// can never match and is reported as
    /// [`FindObjectError::ObjectClassInconsistent`]).
    ///
    /// The catalog is sorted by OBIS ([`merge_objects`]) — binary search.
    fn find_object(
        &self,
        class_id: u16,
        obis: &ObisCode,
    ) -> Result<(u16, &'static dyn InterfaceClass), FindObjectError> {
        let idx = self
            .objects
            .binary_search_by_key(obis, |o| o.obis())
            .ok()
            .ok_or(FindObjectError::ObjectUnavailable)?;
        let obj = self.objects[idx];
        if obj.class_id().as_u16() != class_id {
            return Err(FindObjectError::ObjectClassInconsistent);
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
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn system_title(&self) -> Option<&[u8]> {
        self.mutable
            .get(1)
            .and_then(|slot| slot.as_deref())
            .and_then(|codec| codec.octet_string())
    }

    /// Binary search of an attribute descriptor by key `(object index, number)`.
    fn attr(&self, object: u16, attribute_id: i8) -> Option<AttrDesc> {
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
    /// access-checking — for internal resolution (Association LN service
    /// attributes, `security_setup_reference`, AARQ).
    fn attr_codec(&self, assoc_idx: u8, attribute_id: i8) -> Option<&dyn Codec> {
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
        let obis = self.security_setup_reference(assoc_idx)?;
        let (idx, _) = self
            .find_object(ClassId::SecuritySetup.as_u16(), &obis)
            .ok()?;
        let value = self
            .attr_codec(idx as u8, ATTR_SECURITY_SUITE)?
            .enum_value()?;
        SecuritySuite::from_u8(value)
    }

    /// Handle a `Get-Request-Normal` and write the `Get-Response` into `buf`.
    ///
    /// `invoke` + `descriptor` — already-decoded owned fields (`Copy`), so
    /// the caller does not hold a borrow on the receive buffer. A data-access
    /// error goes into the `Get-Response` as `DataAccessError`, not aborting the
    /// processing.
    ///
    /// Computed values are written directly; if one does not fit into `buf`, the
    /// first block of a `get-response-with-datablock` is written and the transfer
    /// state is stored in `ctx` (see [`Self::handle_get_next`]).
    pub fn handle_get(
        &self,
        invoke: InvokeIdAndPriority,
        descriptor: CosemAttributeDescriptor,
        ctx: &mut Settings,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize, Error> {
        match self.lookup_value(descriptor, ctx) {
            Ok(GetValue::Codec(codec)) => {
                ctx.get_block = None;
                Ok(GetResponse::put_normal(
                    invoke,
                    GetDataResultWrite::Data(codec),
                    buf,
                )?)
            }
            Ok(GetValue::Computed(kind)) => {
                // `get-response-normal`: tag + normal + invoke + data-choice.
                const NORMAL_HEADER: usize = 4;
                let total = self.computed_len(kind, ctx)?;
                if self.tx_available(ctx, buf) >= NORMAL_HEADER + total {
                    ctx.get_block = None;
                    let codec = ComputedCodec {
                        server: self,
                        kind,
                        ctx: &*ctx,
                    };
                    Ok(GetResponse::put_normal(
                        invoke,
                        GetDataResultWrite::Data(&codec),
                        buf,
                    )?)
                } else {
                    let (n, last) = self.put_computed_block(invoke, kind, ctx, 0, buf)?;
                    ctx.get_block = if last {
                        None
                    } else {
                        Some(GetBlock {
                            descriptor,
                            next_block: 1,
                        })
                    };
                    Ok(n)
                }
            }
            Err(code) => {
                ctx.get_block = None;
                Ok(GetResponse::put_normal(
                    invoke,
                    GetDataResultWrite::DataAccessError(code),
                    buf,
                )?)
            }
        }
    }

    /// Handle a `Get-Request-Next`: write the next block of the in-progress
    /// `get-response-with-datablock` transfer stored in `ctx`.
    pub fn handle_get_next(
        &self,
        invoke: InvokeIdAndPriority,
        block_number: u32,
        ctx: &mut Settings,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<usize, Error> {
        let Some(state) = ctx.get_block else {
            return Ok(GetResponse::put_normal(
                invoke,
                GetDataResultWrite::DataAccessError(DataAccessResult::DataBlockUnavailable),
                buf,
            )?);
        };
        if block_number != state.next_block {
            ctx.get_block = None;
            return Ok(GetResponse::put_normal(
                invoke,
                GetDataResultWrite::DataAccessError(DataAccessResult::DataBlockNumberInvalid),
                buf,
            )?);
        }
        let kind = match self.lookup_value(state.descriptor, ctx) {
            Ok(GetValue::Computed(kind)) => kind,
            _ => {
                ctx.get_block = None;
                return Ok(GetResponse::put_normal(
                    invoke,
                    GetDataResultWrite::DataAccessError(DataAccessResult::DataBlockUnavailable),
                    buf,
                )?);
            }
        };
        let (n, last) = self.put_computed_block(invoke, kind, ctx, block_number, buf)?;
        ctx.get_block = if last {
            None
        } else {
            Some(GetBlock {
                descriptor: state.descriptor,
                next_block: block_number + 1,
            })
        };
        Ok(n)
    }

    /// Bytes available for the response APDU: the buffer remainder capped by the
    /// negotiated `tx_max` (0 means "use the buffer size").
    fn tx_available(&self, ctx: &Settings, buf: &ByteBuffer<'_>) -> usize {
        match ctx.tx_max {
            0 => buf.remaining(None),
            tx_max => buf.remaining(None).min(tx_max as usize),
        }
    }

    /// Max A-XDR payload of one datablock, honouring the buffer and `tx_max`.
    /// Finds the largest `cap` with `cap + length_prefix(cap) + FIXED <= available`.
    fn block_capacity(&self, ctx: &Settings, buf: &ByteBuffer<'_>) -> usize {
        const FIXED: usize = 9; // tag + variant + invoke + presence + block-no + choice
        let max_payload = self.tx_available(ctx, buf).saturating_sub(FIXED);
        // Leave one byte for the length prefix, then walk down until it fits.
        // (A fixed-point iteration can oscillate at the 0x7F/0xFF prefix boundaries.)
        let mut cap = max_payload.saturating_sub(1);
        while cap > 0 && cap + length_prefix_len(cap) > max_payload {
            cap -= 1;
        }
        cap
    }

    /// Full encoded length of a computed value.
    fn computed_len(&self, kind: ComputedKind, ctx: &Settings) -> Result<usize, Error> {
        Ok(match kind {
            ComputedKind::XdlmsContextInfo => 19 + dedicated_key_len(ctx.dedicated_key),
            ComputedKind::DefaultXdlmsContextInfo => 19,
            ComputedKind::AssociationStatus | ComputedKind::DefaultAssociationStatus => 2,
            ComputedKind::LogicalName(_) => 8, // octet-string: tag + len(6) + 6
            // structure(7): 2 + six unsigned (2 each) + long-unsigned (3)
            ComputedKind::ApplicationContext(_) => 17,
            ComputedKind::ObjectList(sap) => {
                let mut sink = CountingSink { len: 0 };
                self.write_object_list(sap, &mut sink)?;
                sink.len
            }
        })
    }

    /// Encode the full computed value into `buf`.
    fn computed_put(
        &self,
        kind: ComputedKind,
        ctx: &Settings,
        buf: &mut ByteBuffer<'_>,
    ) -> cosempdu::Result<usize> {
        match kind {
            ComputedKind::XdlmsContextInfo => xdlms_context_info(
                ctx.conformance,
                ctx.tx_max,
                dedicated_key_to_octet_string(ctx.dedicated_key),
            )
            .put(buf),
            ComputedKind::DefaultXdlmsContextInfo => DEFAULT_XDLMS_CONTEXT_INFO.put(buf),
            ComputedKind::AssociationStatus => association_status(ctx.state).put(buf),
            ComputedKind::DefaultAssociationStatus => AssociationStatus::NonAssociated.put(buf),
            ComputedKind::LogicalName(obis) => Data::OctetString(&obis.bytes).put(buf),
            ComputedKind::ApplicationContext(app) => {
                ContextNameStructure::from_application_context(app).put(buf)
            }
            ComputedKind::ObjectList(sap) => {
                let start = buf.pos();
                {
                    let mut sink = BufferSink { out: &mut *buf };
                    self.write_object_list(sap, &mut sink)?;
                }
                Ok(buf.pos() - start)
            }
        }
    }

    /// Strategy 1: encode the value and copy the window `[offset, offset+max)`
    /// into `out`; returns the number of bytes copied.
    fn computed_put_range(
        &self,
        kind: ComputedKind,
        ctx: &Settings,
        offset: usize,
        max: usize,
        out: &mut ByteBuffer<'_>,
    ) -> Result<usize, Error> {
        match kind {
            ComputedKind::ObjectList(sap) => {
                let start = out.pos();
                {
                    let mut sink = WindowSink {
                        out: &mut *out,
                        offset,
                        end: offset.saturating_add(max),
                        seen: 0,
                    };
                    self.write_object_list(sap, &mut sink)?;
                }
                Ok(out.pos() - start)
            }
            // Small values: encode fully into a scratch, then copy the window.
            _ => {
                let mut storage = [0u8; COMPUTED_SCRATCH];
                let len = {
                    let mut b = ByteBuffer::new(&mut storage);
                    self.computed_put(kind, ctx, &mut b)?
                };
                let end = core::cmp::min(offset.saturating_add(max), len);
                if offset >= end {
                    return Ok(0);
                }
                Ok(out.write(&storage[offset..end])?)
            }
        }
    }

    /// Write block `block_number` of a computed value as a
    /// `get-response-with-datablock`.
    ///
    /// The payload is written straight into `buf` (no payload scratch): reserve
    /// the block header, write the window, then fill the header in place.
    /// Returns `(bytes_written, last_block)`.
    fn put_computed_block(
        &self,
        invoke: InvokeIdAndPriority,
        kind: ComputedKind,
        ctx: &Settings,
        block_number: u32,
        buf: &mut ByteBuffer<'_>,
    ) -> Result<(usize, bool), Error> {
        let total = self.computed_len(kind, ctx)?;
        let capacity = self.block_capacity(ctx, buf);
        if capacity == 0 {
            let n = GetResponse::put_normal(
                invoke,
                GetDataResultWrite::DataAccessError(DataAccessResult::DataBlockUnavailable),
                buf,
            )?;
            return Ok((n, true));
        }
        let offset = (block_number as usize).saturating_mul(capacity);
        if offset >= total {
            let n = GetResponse::put_normal(
                invoke,
                GetDataResultWrite::DataAccessError(DataAccessResult::DataBlockNumberInvalid),
                buf,
            )?;
            return Ok((n, true));
        }
        let written = core::cmp::min(capacity, total - offset);
        let last = offset + written >= total;

        const FIXED: usize = 9; // tag + variant + invoke + presence + block-no + choice
        let header_len = FIXED + length_prefix_len(written);
        let start = buf.pos();

        // Payload first (leaving room for the header), then the header in place.
        buf.set_pos(start + header_len)?;
        let payload_len = self.computed_put_range(kind, ctx, offset, written, buf)?;
        if payload_len != written {
            return Err(Error::Codec(cosempdu::Error::Message(
                "computed block window size mismatch",
            )));
        }
        let end = buf.pos();

        buf.set_pos(start)?;
        buf.put_u8(<GetResponse as ImplicitTagged>::TAG)?;
        buf.put_u8(2)?; // with-datablock
        buf.put_u8(invoke.0)?;
        buf.put_u8(if last { 0xFF } else { 0x00 })?;
        buf.write(&block_number.to_be_bytes())?;
        buf.put_u8(0)?; // raw-data CHOICE
        put_length(buf, written)?;
        if buf.pos() != start + header_len {
            return Err(Error::Codec(cosempdu::Error::Message(
                "computed block header size mismatch",
            )));
        }
        buf.set_pos(end)?;
        Ok((end - start, last))
    }

    /// Remote client_SAP of an Association LN object.
    fn association_sap(&self, ctx: &Settings, obis: &ObisCode) -> u8 {
        if *obis == ASSOC_LN_BASE_OBIS || Some(*obis) == self.assoc_obis(ctx.assoc_idx) {
            ctx.client_sap
        } else if *obis == ASSOC_LN_PUBLIC_OBIS {
            client_sap::PUBLIC
        } else if *obis == ASSOC_LN_READER_OBIS {
            client_sap::READER
        } else if *obis == ASSOC_LN_CONFIGURATOR_OBIS {
            client_sap::CONFIGURATOR
        } else {
            ctx.client_sap
        }
    }

    /// `application_context_name` (Association LN attr 4).
    ///
    /// The current/base association reports the negotiated context. A foreign
    /// association has no session, so ciphering is inferred from its
    /// `security_setup_reference` (attr 9): present and readable for its SAP →
    /// LN with ciphering, otherwise LN without ciphering.
    fn association_app_context(&self, ctx: &Settings, obis: &ObisCode) -> ApplicationContextName {
        if *obis == ASSOC_LN_BASE_OBIS || Some(*obis) == self.assoc_obis(ctx.assoc_idx) {
            return ctx.app_context;
        }
        let sap = self.association_sap(ctx, obis);
        let Some(index) = self.object_index(obis) else {
            return ApplicationContextName::LogicalNameNoCiphering;
        };
        match self.attr(index, ATTR_SECURITY_SETUP_REFERENCE) {
            Some(desc) if matches!(desc.access.for_sap(sap), Some(m) if m != AttributeAccessMode::NoAccess) => {
                ApplicationContextName::LogicalNameCiphering
            }
            _ => ApplicationContextName::LogicalNameNoCiphering,
        }
    }

    /// Registered attributes of the object at `index` (in attribute_id order).
    fn object_attrs(&self, index: u16) -> impl Iterator<Item = AttrDesc> + '_ {
        let start = self.attrs.partition_point(|d| d.key.object < index);
        self.attrs[start..]
            .iter()
            .take_while(move |d| d.key.object == index)
            .copied()
    }

    /// Encode Association LN `object_list` (v1) for the given client_SAP.
    ///
    /// Lists only the objects that expose anything to that level (see
    /// [`ServerObjectList::visible`]).
    fn write_object_list<S: ObjectListSink>(&self, sap: u8, sink: &mut S) -> cosempdu::Result<()> {
        let source = ServerObjectList { server: self, sap };
        encode_object_list(sink, &source)
    }

    /// OBIS of the association object by its catalog index (for computed attributes).
    fn assoc_obis(&self, assoc_idx: u8) -> Option<ObisCode> {
        self.objects.get(assoc_idx as usize).map(|o| o.obis())
    }

    /// Resolve the base alias `0.0.40.0.0.255` to the OBIS of the Association LN
    /// object selected during AARQ (`assoc_idx`), so that the attribute
    /// descriptors and access rights are those of the client's association
    /// (e.g. `associated_partners_id`). With no association selected
    /// (`assoc_idx == u8::MAX`) or for another class the OBIS is returned as is.
    ///
    /// Only the *lookup* address is rewritten: the caller decides what to report
    /// back (`logical_name` of the alias stays the alias).
    fn resolve_alias(&self, class_id: u16, obis: ObisCode, assoc_idx: u8) -> ObisCode {
        if class_id == ClassId::AssociationLn.as_u16() && obis == ASSOC_LN_BASE_OBIS {
            if let Some(real) = self.assoc_obis(assoc_idx) {
                return real;
            }
        }
        obis
    }

    /// `security_setup_reference` (attr 9) of the association at `assoc_idx`: the
    /// OBIS of the Security setup object it references.
    ///
    /// `None` when the association has no (readable) reference, e.g. an LLS one.
    fn security_setup_reference(&self, assoc_idx: u8) -> Option<ObisCode> {
        let bytes = self
            .attr_codec(assoc_idx, ATTR_SECURITY_SETUP_REFERENCE)?
            .octet_string()?;
        ObisCode::from_logical_name(bytes).ok()
    }

    /// Whether the object at catalog `index` exposes anything to the client level
    /// `sap`: at least one attribute (other than the implicit `logical_name`) or
    /// method with a non-`NoAccess` mode.
    ///
    /// This is the single visibility rule: it decides both `object_list`
    /// membership and whether `logical_name` (attr 1) is readable.
    fn object_visible(&self, index: u16, sap: u8) -> bool {
        self.object_attrs(index)
            .any(|d| access_mode(d.access, sap).is_some())
            || self
                .methods_of(index)
                .iter()
                .any(|d| method_visible(d.access, sap))
    }

    /// Registry entries of the object at catalog `index` (sorted by method number).
    fn methods_of(&self, index: u16) -> &[MethodDesc] {
        let index = index as usize;
        let start = self
            .methods
            .partition_point(|d| (d.key.object as usize) < index);
        let rest = &self.methods[start..];
        let len = rest.partition_point(|d| d.key.object as usize == index);
        &rest[..len]
    }

    /// Parse the descriptor (`class_id` + OBIS + `attribute_id`) and find the value
    /// for GET (the class is checked by [`Server::find_object`], then read access):
    /// a stored `&dyn Codec` or a computed [`GetValue::Computed`].
    fn lookup_value(
        &self,
        descriptor: CosemAttributeDescriptor,
        ctx: &Settings,
    ) -> Result<GetValue<'_>, DataAccessResult> {
        let requested = ObisCode::from_bytes(descriptor.instance_id);
        let attribute_id = descriptor.attribute_id;
        let obis = self.resolve_alias(descriptor.class_id, requested, ctx.assoc_idx);

        let (index, object) = self.find_object(descriptor.class_id, &obis)?;

        // Attribute 1 (`logical_name`) is implicit for every catalog object and
        // is readable at all levels — but only for objects this level can see at
        // all (the same rule as `object_list`). It must match the addressed
        // instance (the base alias stays the base alias).
        if attribute_id == ATTR_LOGICAL_NAME {
            if !self.object_visible(index, ctx.client_sap) {
                return Err(DataAccessResult::ScopeOfAccessViolated);
            }
            return Ok(GetValue::Computed(ComputedKind::LogicalName(requested)));
        }

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
            // Computed value (`xDLMS_context_info`): O(1) match. The current
            // association's OBIS (including the base alias, already resolved
            // above) uses the negotiated session parameters; any other
            // Association LN association (public/reader/configurator) has no
            // negotiated parameters and falls back to the server defaults.
            RomKind::Computed => match (object.class_id(), attribute_id, obis) {
                (ClassId::AssociationLn, ATTR_XDLMS_CONTEXT_INFO, o)
                    if Some(o) == self.assoc_obis(ctx.assoc_idx) =>
                {
                    Ok(GetValue::Computed(ComputedKind::XdlmsContextInfo))
                }
                (ClassId::AssociationLn, ATTR_XDLMS_CONTEXT_INFO, _) => {
                    Ok(GetValue::Computed(ComputedKind::DefaultXdlmsContextInfo))
                }
                (ClassId::AssociationLn, ATTR_ASSOCIATION_STATUS, o)
                    if Some(o) == self.assoc_obis(ctx.assoc_idx) =>
                {
                    Ok(GetValue::Computed(ComputedKind::AssociationStatus))
                }
                (ClassId::AssociationLn, ATTR_ASSOCIATION_STATUS, _) => {
                    Ok(GetValue::Computed(ComputedKind::DefaultAssociationStatus))
                }
                (ClassId::AssociationLn, ATTR_OBJECT_LIST, o) => Ok(GetValue::Computed(
                    ComputedKind::ObjectList(self.association_sap(ctx, &o)),
                )),
                (ClassId::AssociationLn, ATTR_APPLICATION_CONTEXT_NAME, o) => {
                    Ok(GetValue::Computed(ComputedKind::ApplicationContext(
                        self.association_app_context(ctx, &o),
                    )))
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
        let obis = self.resolve_alias(class_id.as_u16(), key.obis, ctx.assoc_idx);
        let (index, _) = self.find_object(class_id.as_u16(), &obis)?;
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
            if session.settings.state == SessionState::Disconnecting {
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
        // `None` — the APDU is dropped (no response at all, the session goes on).
        let apdu_len: Option<usize> = match (tag.class, tag.number, tag.constructed, settings.state)
        {
            // ACSE: AARQ = [APPLICATION 0] IMPLICIT SEQUENCE.
            (Class::Application, 0, true, SessionState::Idle) => {
                let (apdu, response_allowed) = self.process_aarq(settings, rx, tx, source_port);
                send = response_allowed;
                apdu
            }
            // AARQ for an already existing AA: Table 89 "Association is not established"
            // (9.4.4.2 allows this optional exception-response).
            (Class::Application, 0, true, _) => build_association_not_established(tx),
            // ACSE: RLRQ = [APPLICATION 2] IMPLICIT SEQUENCE.
            (Class::Application, 2, true, _) => handle_release(settings, rx, tx),
            // xDLMS: Get-Request = [192] IMPLICIT CHOICE (association established).
            // A client-caused failure becomes an exception-response (Table 89), our
            // own failure ends the session (see [`service_outcome`]).
            (Class::Private, 0, false, SessionState::Associated) => {
                service_outcome(self.process_get(settings, rx, tx), tx)?
            }
            // xDLMS: Set-Request = [193] IMPLICIT CHOICE (association established).
            (Class::Private, 1, false, SessionState::Associated) => {
                service_outcome(self.process_set(settings, rx, tx), tx)?
            }
            // xDLMS: Action-Request = [195] IMPLICIT CHOICE (association established).
            (Class::Private, 3, false, SessionState::Associated) => {
                service_outcome(self.process_action(settings, rx, tx), tx)?
            }
            // GET/SET/ACTION without an established association → "Association is not established".
            (Class::Private, 0 | 1 | 3, false, _) => build_association_not_established(tx),
            // Table 89. Request is not well formed
            _ => build_exception_response(
                tx,
                StateError::ServiceUnknown,
                ServiceError_::OperationNotPossible,
            ),
        };

        let Some(apdu_len) = apdu_len else {
            // The APDU is dropped: there is nothing to send.
            return Ok(false);
        };
        if !send {
            return Ok(false);
        }
        // Back up the 8-byte WPDU header at the start of tx.
        tx.write_at(&wrapper.header_bytes(apdu_len as u16), 0)?;
        Ok(true)
    }

    /// AARQ → AARE: parse the association request, check client_SAP,
    /// application-context and DLMS version; write the AARE (APDU) into tx.
    ///
    /// `Some(n)` — an `n`-byte AARE is in `tx`; `None` — the APDU is dropped (no
    /// response, see `send`), which cannot happen in practice: the AARE is at most
    /// a few dozen bytes in a `RX_BUF`-sized buffer.
    ///
    /// Only an *accepted* AARQ leaves negotiated state in `settings`; a rejection
    /// or a drop resets them to [`Settings::new`] so that the session stays clean
    /// (an undecodable AARQ is dropped, an AARQ with unacceptable syntax is
    /// rejected with an `acse-service-provider` diagnostic — Green Book 9.3.2,
    /// 9.4.4.1).
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_aarq(
        &self,
        settings: &mut Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
        source_port: u16,
    ) -> (Option<usize>, bool) {
        // Green Book 9.3.2: the `.indication` primitive is generated only for a
        // correctly formatted AARQ. An undecodable one is discarded (the AARE
        // would have to echo `application-context-name`, which is unknown here):
        // the AA is not established and the session stays `Idle`.
        let aarq = {
            let mut r = Reader::new(rx.extract());
            // TODO: the whole AARQapdu is decoded here, but only
            // application_context_name, user_information and calling_ap_title are used.
            // The remaining fields (called-AP-title, invocation-id, authentication-value
            // etc.) are not needed yet. When they are — decide whether to store
            // them owned in Settings (grows the persistent Session RAM) or introduce
            // a partial decoder (saves ~120 B of transient stack).
            match AARQapdu::get(&mut r) {
                Ok(aarq) => aarq,
                Err(_) => return (None, false),
            }
        };

        // The AARE echoes the proposed application-context-name, so it is needed
        // for the rejections below too (short names are rejected there).
        settings.app_context = aarq.application_context_name;

        // `user-information` carries the xDLMS InitiateRequest. Missing or
        // malformed → "the AARQ syntax is not acceptable" (9.4.4.1): an AARE with
        // an `acse-service-provider` diagnostic; no `.indication` is issued and
        // the AA is not established.
        let req = match aarq.user_information {
            Some(ui) => InitiateRequest::get(&mut Reader::new(ui)),
            None => Err(cosempdu::Error::Message("AARQ without user-information")),
        };
        let Ok(req) = req else {
            // Whether the client waits for an AARE is flagged inside the
            // (unreadable) InitiateRequest; only unconfirmed AAs mark it
            // explicitly, so the reply is sent.
            return reject_aarq(
                settings,
                tx,
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::NoReasonGiven),
                UserInformation::None,
                true,
            );
        };
        let proposed_dlms_version = req.proposed_dlms_version_number;

        settings.conformance = req.proposed_conformance.intersection(PROPOSED_CONFORMANCE);
        settings.tx_max = core::cmp::min(MAX_APDU as u16, req.client_max_receive_pdu_size);
        // Authentication chosen by the client (sender-acse-requirements, bit 0).
        settings.authenticated = aarq.sender_acse_requirements;

        // Client system-title (calling-AP-title). Invalid length → reject.
        match aarq.calling_ap_title {
            Some(calling) => match SystemTitle::from_slice(calling) {
                Ok(title) => settings.system_title_c = Some(title),
                Err(_) => {
                    return reject_aarq(
                        settings,
                        tx,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::CallingApTitleNotRecognized,
                        ),
                        UserInformation::None,
                        req.response_allowed,
                    );
                }
            },
            None => {
                // With ciphering the calling-AP-title is required (client
                // identifier for key agreement); missing → no-reason-given.
                if settings.is_ciphered() {
                    return reject_aarq(
                        settings,
                        tx,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceProvider(
                            AcseServiceProvider::NoReasonGiven,
                        ),
                        UserInformation::None,
                        req.response_allowed,
                    );
                }
                settings.system_title_c = None;
            }
        }

        // called-AP-title check: if the client explicitly names a title,
        // it must match the server-system-title (otherwise called-AP-title-not-recognized).
        if let Some(called) = aarq.called_ap_title {
            if self.system_title() != Some(called) {
                return reject_aarq(
                    settings,
                    tx,
                    AssociationResult::RejectedPermanent,
                    AssociateSourceDiagnostic::ServiceUser(
                        AcseServiceUser::CalledApTitleNotRecognized,
                    ),
                    UserInformation::None,
                    req.response_allowed,
                );
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
                    return reject_aarq(
                        settings,
                        tx,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::AuthenticationFailure,
                        ),
                        UserInformation::None,
                        req.response_allowed,
                    );
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

        if matches!(
            settings.app_context,
            ApplicationContextName::ShortNameCiphering
                | ApplicationContextName::ShortNameNoCiphering
        ) {
            // Short names are not supported: the AARE echoes LN without ciphering.
            settings.app_context = ApplicationContextName::LogicalNameNoCiphering;
            return reject_aarq(
                settings,
                tx,
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceUser(
                    AcseServiceUser::ApplicationContextNameNotSupported,
                ),
                UserInformation::None,
                req.response_allowed,
            );
        }

        if proposed_dlms_version < DLMS_VERSION_NUMBER {
            // Reject: dlms-version-too-low → AARE(RejectedPermanent) +
            // ConfirmedServiceError(initiate-error: dlms-version-too-low).
            return reject_aarq(
                settings,
                tx,
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::NoReasonGiven),
                UserInformation::Error(ConfirmedServiceError {
                    tag: confirmed_service_error_tag::INITIATE_ERROR,
                    service_error: SnServiceError::Initiate(Initiate::DlmsVersionTooLow),
                }),
                req.response_allowed,
            );
        }

        // `authentication_mechanism_name` (attr 6) of the selected association:
        // the requested mechanism must match at the security-level granularity
        // (0 none / 1 LLS / 2…7 HLS). A missing mechanism is accepted only for a
        // no-auth association; an HLS association also requires the
        // authentication functional unit (sender-acse-requirements, bit 0), so
        // a mechanism name sent without it cannot be accepted.
        if let Some(expected) = self
            .attr_codec(assoc_idx, ATTR_AUTHENTICATION_MECHANISM_NAME)
            .and_then(|codec| codec.authentication_mechanism())
        {
            let expected_level = mechanism_level(expected);
            let requested_level = aarq.mechanism_name.map(|m| mechanism_level(m as u8));
            let diagnostic = match requested_level {
                Some(level) if level == expected_level => None,
                Some(_) => Some(AcseServiceUser::AuthenticationMechanismNameNotRecognised),
                None if expected_level == 0 => None,
                None => Some(AcseServiceUser::AuthenticationMechanismNameRequired),
            }
            .or_else(|| {
                (!settings.authenticated && expected_level > 1)
                    .then_some(AcseServiceUser::AuthenticationMechanismNameRequired)
            });
            if let Some(diagnostic) = diagnostic {
                return reject_aarq(
                    settings,
                    tx,
                    AssociationResult::RejectedPermanent,
                    AssociateSourceDiagnostic::ServiceUser(diagnostic),
                    UserInformation::None,
                    req.response_allowed,
                );
            }
        }

        // Authentication: dispatch by mechanism-name (checked only when
        // authentication is chosen — sender-acse-requirements, bit 0).
        match (settings.authenticated, aarq.mechanism_name) {
            // LLS (LowLevelSecurity = 1): the password from calling-authentication-value
            // is compared against the `secret` attribute (attr 7) of the chosen association.
            (true, Some(MechanismName::LowLevelSecurity)) => {
                if !self.verify_lls_secret(settings, &aarq) {
                    return reject_aarq(
                        settings,
                        tx,
                        AssociationResult::RejectedPermanent,
                        AssociateSourceDiagnostic::ServiceUser(
                            AcseServiceUser::AuthenticationFailure,
                        ),
                        UserInformation::None,
                        req.response_allowed,
                    );
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

        // Association established (AARE written to tx; sending decided by response_allowed).
        let n = match put_aare(
            tx,
            settings.app_context,
            AssociationResult::Accepted,
            AssociateSourceDiagnostic::ServiceUser(AcseServiceUser::Null),
            UserInformation::Response(InitiateResponse::new(settings.conformance, MAX_APDU as u16)),
        ) {
            Ok(n) => n,
            // Cannot answer at all: drop the APDU and leave the session clean.
            Err(_) => {
                debug_assert!(false, "AARE does not fit into tx");
                *settings = Settings::new();
                return (None, req.response_allowed);
            }
        };
        settings.state = SessionState::Associated;
        (Some(n), req.response_allowed)
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
    ) -> (Option<usize>, bool) {
        let handshake = hls_handshake();
        if handshake.busy {
            // Scratch is busy with another session's check → rejected-transient.
            return reject_aarq(
                settings,
                tx,
                AssociationResult::RejectedTransient,
                AssociateSourceDiagnostic::ServiceProvider(AcseServiceProvider::NoReasonGiven),
                UserInformation::None,
                response_allowed,
            );
        }

        // The client certificate is required for HLS (length 64/96 → P256/P384).
        // TODO: confirm that qualifier = only the public key (not system-title || key).
        let qualifier = match aarq.calling_ae_qualifier {
            Some(cert) => CallingAeQualifier::from_slice(cert),
            None => {
                return reject_aarq(
                    settings,
                    tx,
                    AssociationResult::RejectedPermanent,
                    AssociateSourceDiagnostic::ServiceUser(
                        AcseServiceUser::CallingAeQualifierNotRecognized,
                    ),
                    UserInformation::None,
                    response_allowed,
                );
            }
        };
        if matches!(qualifier, CallingAeQualifier::None) {
            return reject_aarq(
                settings,
                tx,
                AssociationResult::RejectedPermanent,
                AssociateSourceDiagnostic::ServiceUser(
                    AcseServiceUser::CallingAeQualifierNotRecognized,
                ),
                UserInformation::None,
                response_allowed,
            );
        }

        // CtoS — client challenge from calling-authentication-value (optional;
        // the server needs it for pass 4, where it returns f(CtoS)).
        let ctos = match aarq.calling_authentication_value {
            Some(AuthenticationValue::CharString(v)) => v,
            Some(AuthenticationValue::BitString(v)) => v,
            None => &[],
        };
        // TODO: server-to-client challenge (StoC) — random value (RNG); constant stub.
        let stoc = [0x43u8; 16];

        // AARE (pass 2): accepted + HLS success + StoC in responding-authentication-value.
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
        // Encode first, commit afterwards: a failed encoding must not leave the
        // handshake scratch claimed (it would reject all later HLS associations).
        let encoded = {
            let n = {
                let mut buf = ByteBuffer::new(tx.as_bytes_mut());
                if buf.set_pos(WPDU_HEADER_LEN).is_ok() {
                    aare.put(&mut buf).ok()
                } else {
                    None
                }
            };
            n.filter(|&n| tx.set_pos(WPDU_HEADER_LEN + n).is_ok())
        };
        let Some(n) = encoded else {
            // Cannot answer: drop the APDU and leave the session clean.
            debug_assert!(false, "AARE does not fit into tx");
            *settings = Settings::new();
            return (None, response_allowed);
        };

        // Claim the scratch for the handshake (released after pass 3;
        // TODO: timeout/release if the client never sends the ACTION reply).
        handshake.busy = true;
        handshake.qualifier = qualifier;
        let len = ctos.len().min(16);
        handshake.ctos[..len].copy_from_slice(&ctos[..len]);
        handshake.stoc = stoc;
        settings.state = SessionState::Associating;
        (Some(n), response_allowed)
    }

    /// Get-Request (Normal or Next) → Get-Response in session.tx.
    ///
    /// `WithList` and non-empty `access_selection` are not implemented: they get
    /// a `DataAccessError` response instead of aborting the connection (an abort
    /// looks like a client timeout). A `access_selection` with selector `0`
    /// (no selector) is treated as absent.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_get(
        &self,
        settings: &mut Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
    ) -> Result<usize, RequestError> {
        // 1) Decode the Get-Request into owned fields.
        let (invoke, descriptor, block_number, unsupported) = {
            let mut r = Reader::new(rx.extract());
            match GetRequest::get(&mut r).map_err(|_| RequestError::NotWellFormed)? {
                GetRequest::Normal(GetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection,
                }) => {
                    let unsupported = matches!(access_selection, Some(s) if s.access_selector != 0);
                    (invoke, Some(descriptor), None, unsupported)
                }
                GetRequest::Next(next) => (next.invoke, None, Some(next.block_number), false),
                GetRequest::WithList(list) => (list.invoke, None, None, true),
            }
        };

        // 2) Get-Response (APDU) straight into tx, offset for the WPDU header.
        let mut buf = ByteBuffer::new(tx.as_bytes_mut());
        buf.set_pos(WPDU_HEADER_LEN).map_err(internal)?;
        let n = if unsupported {
            GetResponse::put_normal(
                invoke,
                GetDataResultWrite::DataAccessError(DataAccessResult::OtherReason),
                &mut buf,
            )
            .map_err(internal)?
        } else {
            match (descriptor, block_number) {
                (Some(descriptor), _) => self
                    .handle_get(invoke, descriptor, settings, &mut buf)
                    .map_err(internal)?,
                (None, Some(block_number)) => self
                    .handle_get_next(invoke, block_number, settings, &mut buf)
                    .map_err(internal)?,
                (None, None) => unreachable!(),
            }
        };
        tx.set_pos(WPDU_HEADER_LEN + n).map_err(internal)?;
        Ok(n)
    }

    /// Set-Request (Normal, without access_selection) → apply the value → Set-Response.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_set(
        &mut self,
        settings: &Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
    ) -> Result<usize, RequestError> {
        // 1) Decode Set-Request::Normal and apply the value to the attribute.
        //    A data-access error does not abort processing; it goes into the Set-Response.
        let (invoke, result) = {
            let mut r = Reader::new(rx.extract());
            match SetRequest::get(&mut r).map_err(|_| RequestError::NotWellFormed)? {
                SetRequest::Normal(SetRequestNormal {
                    invoke,
                    descriptor,
                    access_selection: None,
                    value,
                }) => {
                    let class_id =
                        ClassId::from_u16(descriptor.class_id).ok_or(RequestError::NotSupported)?;
                    let obis = ObisCode::from_bytes(descriptor.instance_id);
                    let key = AttributeKey::new(obis, descriptor.attribute_id);

                    // Apply the value; on a Data-Access-Result return its code in the response.
                    let result = match self.stream_set(class_id, key, settings) {
                        Ok(mut s) => {
                            // A malformed value is the client's data.
                            let decoded = s
                                .push(value.remaining_bytes())
                                .and_then(|()| s.finish())
                                .map_err(|_| RequestError::NotWellFormed);
                            decoded?;
                            DataAccessResult::Success
                        }
                        Err(code) => code,
                    };

                    (invoke, result)
                }
                // WithList / access_selection: not supported with this conformance.
                _ => return Err(RequestError::NotSupported),
            }
        };

        // 2) Set-Response (APDU) straight into tx (the WPDU-header offset was made in process_request).
        SetResponse::put_normal(invoke, result, tx).map_err(internal)
    }

    /// Action-Request (Normal, only) → Action-Response.
    ///
    /// Currently only the Association LN method `change_HLS_secret` (method 2)
    /// of the current association is implemented; batched/blockwise actions are
    /// not supported.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn process_action(
        &mut self,
        settings: &Settings,
        rx: &ArrayBuffer<RX_BUF>,
        tx: &mut ArrayBuffer<RX_BUF>,
    ) -> Result<usize, RequestError> {
        let (invoke, result) = {
            let mut r = Reader::new(rx.extract());
            match ActionRequest::get(&mut r).map_err(|_| RequestError::NotWellFormed)? {
                ActionRequest::Normal(ActionRequestNormal {
                    invoke,
                    descriptor,
                    method_invocation_parameters,
                }) => {
                    let result = action_result(self.handle_action(
                        settings,
                        descriptor,
                        method_invocation_parameters,
                    ));
                    (invoke, result)
                }
                // NextPblock / WithList: not supported.
                _ => return Err(RequestError::NotSupported),
            }
        };

        // Action-Response (APDU) straight into tx, offset for the WPDU header.
        let mut buf = ByteBuffer::new(tx.as_bytes_mut());
        buf.set_pos(WPDU_HEADER_LEN).map_err(internal)?;
        let n = ActionResponse::put_normal(
            invoke,
            ActionResponseWithOptionalDataWrite {
                result,
                return_parameters: None,
            },
            &mut buf,
        )
        .map_err(internal)?;
        tx.set_pos(WPDU_HEADER_LEN + n).map_err(internal)?;
        Ok(n)
    }

    /// Dispatch an ACTION method.
    ///
    /// Resolves the object (the base alias is resolved to the current
    /// association, like GET), looks the method up in the ROM registry
    /// ([`merge_methods`]) and checks its [`MethodAccess`] — the access rights
    /// are declarative, per client level. The `match` below is only the handler
    /// dispatch (each handler is a separate function in [`crate::methods`]).
    ///
    /// Returns the [`ActionOutcome`] of the handler: there are no transport
    /// errors here, every failure is an `Action-Result` for the client.
    #[cfg(any(feature = "tcp", feature = "ble"))]
    fn handle_action(
        &mut self,
        settings: &Settings,
        descriptor: CosemMethodDescriptor,
        params: Option<Reader<'_>>,
    ) -> ActionOutcome {
        let requested = ObisCode::from_bytes(descriptor.instance_id);
        // The base alias resolves to the current association, like GET.
        let obis = self.resolve_alias(descriptor.class_id, requested, settings.assoc_idx);
        // The class is validated against the catalog object by `find_object`, so
        // an unknown `class_id` needs no separate check: it cannot match any
        // catalog object and comes back as `ObjectClassInconsistent`.
        let (index, object) = self.find_object(descriptor.class_id, &obis)?;
        let method_id = descriptor.method_id;

        let desc = self
            .method(index, method_id)
            .ok_or(ActionResult::ObjectUndefined)?;
        if !desc.access.can_call(settings) {
            return Err(ActionResult::ScopeOfAccessViolated);
        }

        match (object.class_id(), method_id) {
            (ClassId::AssociationLn, METHOD_CHANGE_HLS_SECRET) => {
                self.change_hls_secret(settings, index, params)
            }
            // A registry entry without a handler: a configuration defect, not a
            // client error. `has_handler` guarantees this is unreachable for a
            // consistent registry (checked by `every_registry_method_has_handler`).
            _ => {
                debug_assert!(!has_handler(object.class_id(), method_id));
                Err(ActionResult::HardwareFault)
            }
        }
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

/// Reject the proposed AA: write the AARE (echoing the proposed application
/// context) and leave the session clean.
///
/// Only an *established* association may keep negotiated state in [`Settings`], so
/// a rejection resets them with [`Settings::new`]. If the AARE cannot be encoded
/// the APDU is dropped (`None`) — the state is still clean and the client falls
/// back to its own time-out.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn reject_aarq(
    settings: &mut Settings,
    tx: &mut ArrayBuffer<RX_BUF>,
    result: AssociationResult,
    diagnostic: AssociateSourceDiagnostic,
    ui: UserInformation,
    response_allowed: bool,
) -> (Option<usize>, bool) {
    let n = put_aare(tx, settings.app_context, result, diagnostic, ui).ok();
    *settings = Settings::new();
    (n, response_allowed)
}

/// Why an xDLMS service could not produce its own response (Table 89).
#[cfg(any(feature = "tcp", feature = "ble"))]
#[derive(Debug)]
enum RequestError {
    /// The request APDU cannot be decoded — the client's fault: Table 89 row
    /// "Request is not well formed" → `exception-response (service-unknown,
    /// operation-not-possible)`; the association survives.
    NotWellFormed,
    /// The service or its variant is not implemented / not negotiated: Table 89 row
    /// "Request not supported with negotiated conformance" → `exception-response
    /// (service-not-allowed, service-not-supported)`.
    NotSupported,
    /// Our own failure (buffer, encoding, invariant): the reply cannot be built,
    /// so the session cannot go on.
    Internal(Error),
}

/// Classify a failure of our own encoding/invariants as fatal for the session.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn internal<E: Into<Error>>(error: E) -> RequestError {
    RequestError::Internal(error.into())
}

/// Unknown/malformed APDU → error-response to the peer.
///
/// LN referencing — `ExceptionResponse` (service-unknown, operation-not-possible);
/// SN referencing — not used.
///
/// `None` — the response cannot be encoded (unreachable with `RX_BUF`: it is
/// ~10 bytes), so the APDU is dropped instead of tearing the session down.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_exception_response(
    tx: &mut ArrayBuffer<RX_BUF>,
    state_error: StateError,
    service_error: ServiceError_,
) -> Option<usize> {
    let exc = ExceptionResponse {
        state_error,
        service_error,
    };
    match exc.put(tx) {
        Ok(n) => Some(n),
        Err(_) => {
            debug_assert!(false, "exception-response does not fit into tx");
            None
        }
    }
}

/// LN referencing — `ExceptionResponse` (service-not-allowed, operation-not-possible).
///
/// `None` — cannot encode (see [`build_exception_response`]).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn build_association_not_established(tx: &mut ArrayBuffer<RX_BUF>) -> Option<usize> {
    build_exception_response(
        tx,
        StateError::ServiceNotAllowed,
        ServiceError_::OperationNotPossible,
    )
}

/// Turn a service outcome into "a response is in tx" / "the APDU is dropped",
/// answering client-caused failures with the Table 89 exception-response.
#[cfg(any(feature = "tcp", feature = "ble"))]
fn service_outcome(
    result: Result<usize, RequestError>,
    tx: &mut ArrayBuffer<RX_BUF>,
) -> Result<Option<usize>, Error> {
    let (state_error, service_error) = match result {
        Ok(n) => return Ok(Some(n)),
        // Table 89: "Request is not well formed".
        Err(RequestError::NotWellFormed) => (
            StateError::ServiceUnknown,
            ServiceError_::OperationNotPossible,
        ),
        // Table 89: "Request not supported with negotiated conformance".
        Err(RequestError::NotSupported) => (
            StateError::ServiceNotAllowed,
            ServiceError_::ServiceNotSupported,
        ),
        // Our own defect: the session cannot go on.
        Err(RequestError::Internal(error)) => return Err(error),
    };

    // Nothing was written to tx for a client-caused failure, but make the
    // position explicit: the exception-response replaces the service response.
    if tx.set_pos(WPDU_HEADER_LEN).is_err() {
        return Ok(None);
    }
    Ok(build_exception_response(tx, state_error, service_error))
}

/// RLRQ → RLRE: confirm the association release.
///
/// `Some(n)` — an `n`-byte RLRE is written into `tx`, the release is confirmed on
/// the wire and the session becomes `Disconnecting`.
///
/// `None` — no response is sent (`process_request` suppresses it) and the session
/// state is left untouched: the APDU was discarded (not an RLRQ, or the RLRE cannot
/// be encoded). In both cases the AA stays as it is and the client confirms the
/// release locally by its own time-out (Green Book 9.3.3 lists that `.confirm`
/// variant explicitly).
#[cfg(any(feature = "tcp", feature = "ble"))]
fn handle_release(
    settings: &mut Settings,
    rx: &ArrayBuffer<RX_BUF>,
    tx: &mut ArrayBuffer<RX_BUF>,
) -> Option<usize> {
    // Green Book 9.3.3: the release `.indication` is generated only for an RLRQ
    // that can be interpreted. Anything else (undecodable BER, another ACSE PDU)
    // is silently discarded: no `.indication`, no RLRE, the AA stays established.
    match ACSEApdu::get(&mut Reader::new(rx.extract())) {
        Ok(ACSEApdu::Rlrq(_)) => {}
        _ => return None,
    }

    // RLRE (APDU, reason normal) into tx (the WPDU-header offset was made in process_request).
    let rlre = RLREapdu {
        reason: Some(ReleaseResponseReason::Normal),
        user_information: None,
    };
    match rlre.put(tx) {
        // Encoded: the release is confirmed on the wire and the session ends.
        Ok(n) => {
            settings.state = SessionState::Disconnecting;
            Some(n)
        }
        // The reply cannot be produced, so the APDU is dropped (like an undecodable
        // RLRQ): the AA stays as it is and the client confirms the release locally
        // by its own time-out (9.3.3). Unreachable in practice — an RLRE is 5 bytes
        // written from position `WPDU_HEADER_LEN` (8) into `RX_BUF` (1032).
        Err(_) => {
            debug_assert!(false, "RLRE does not fit into tx");
            None
        }
    }
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
            attribute_id: key.attribute_id,
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
                .handle_get(invoke, descriptor, &mut Settings::public(), &mut b)
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
                .handle_get(invoke, descriptor, &mut Settings::public(), &mut b)
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
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        // Four Association LN objects: base + public/reader/configurator.
        let assocs = server
            .get_objects::<AssociationLn>()
            .collect::<std::vec::Vec<_>>();
        assert_eq!(assocs.len(), 4);

        let partners = |ctx: &Settings, obis: ObisCode| -> Option<(u8, u16)> {
            let key = AttributeKey::new(obis, ATTR_ASSOCIATED_PARTNERS_ID);
            match server.lookup_value(descriptor(ClassId::AssociationLn, key), ctx) {
                Ok(GetValue::Codec(codec)) => codec.associated_partners(),
                _ => None,
            }
        };

        let mechanism = |ctx: &Settings, obis: ObisCode| -> Option<u8> {
            let key = AttributeKey::new(obis, ATTR_AUTHENTICATION_MECHANISM_NAME);
            match server.lookup_value(descriptor(ClassId::AssociationLn, key), ctx) {
                Ok(GetValue::Codec(codec)) => codec.authentication_mechanism(),
                _ => None,
            }
        };

        // Without an association selected, the base alias has no attr 3.
        let base_key = AttributeKey::new(ASSOC_LN_BASE_OBIS, ATTR_ASSOCIATED_PARTNERS_ID);
        assert!(matches!(
            server.lookup_value(
                descriptor(ClassId::AssociationLn, base_key),
                &Settings::public()
            ),
            Err(DataAccessResult::ReadWriteDenied)
        ));

        // `associated_partners_id` (attr 3) of the real associations is Static
        // (read-only) and reports `{client_SAP, server_SAP = 1}`;
        // `authentication_mechanism_name` (attr 6) — LLS for public/reader, HLS
        // for the configurator. The base alias (`0.0.40.0.0.255`) resolves to
        // the selected association.
        for assoc in &assocs {
            if assoc.obis == ASSOC_LN_BASE_OBIS {
                continue;
            }
            let expected_sap = match assoc.obis {
                ASSOC_LN_PUBLIC_OBIS => client_sap::PUBLIC,
                ASSOC_LN_READER_OBIS => client_sap::READER,
                _ => client_sap::CONFIGURATOR,
            };
            let expected_mechanism = match assoc.obis {
                ASSOC_LN_PUBLIC_OBIS => AUTH_MECH_PUBLIC,
                ASSOC_LN_READER_OBIS => AUTH_MECH_READER,
                _ => AUTH_MECH_CONFIGURATOR,
            };
            let idx = server
                .find_object(ClassId::AssociationLn.as_u16(), &assoc.obis)
                .unwrap()
                .0 as u8;
            let mut ctx = Settings::with_sap(expected_sap);
            ctx.assoc_idx = idx;
            assert_eq!(
                partners(&ctx, assoc.obis),
                Some((expected_sap, SERVER_SAP)),
                "OBIS {:?}",
                assoc.obis
            );
            assert_eq!(
                partners(&ctx, ASSOC_LN_BASE_OBIS),
                Some((expected_sap, SERVER_SAP)),
                "base alias for {:?}",
                assoc.obis
            );
            assert_eq!(
                mechanism(&ctx, assoc.obis),
                Some(expected_mechanism),
                "OBIS {:?}",
                assoc.obis
            );
            assert_eq!(
                mechanism(&ctx, ASSOC_LN_BASE_OBIS),
                Some(expected_mechanism),
                "base alias for {:?}",
                assoc.obis
            );
        }
    }

    /// `object_list` advertises only the methods that the requesting client
    /// level may invoke (the ROM method registry, filtered by `MethodAccess`).
    #[test]
    fn server_object_list_methods_follow_access() {
        use dlms1::ic::association_ln::{
            MethodAccessMode, ObjectListSource, METHOD_CHANGE_HLS_SECRET,
        };
        use dlms1::ic::client_sap;

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);
        static METHODS: [crate::MethodDesc; 2] =
            crate::merge_methods::<2>(&[], crate::OBJECTS, &[], crate::METHODS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        })
        .with_methods(&METHODS);

        let public = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_PUBLIC_OBIS)
            .unwrap()
            .0 as usize;
        let reader = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_READER_OBIS)
            .unwrap()
            .0 as usize;
        let configurator = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as usize;

        // The reader sees its own `change_HLS_secret`, not the configurator's.
        let list = ServerObjectList {
            server: &server,
            sap: client_sap::READER,
        };
        assert_eq!(list.method_count(reader), 1);
        assert_eq!(
            list.method(reader, 0),
            (
                METHOD_CHANGE_HLS_SECRET,
                MethodAccessMode::AuthenticatedAccess
            )
        );
        assert_eq!(list.method_count(configurator), 0);
        assert_eq!(list.method_count(public), 0);

        // Same for the configurator.
        let list = ServerObjectList {
            server: &server,
            sap: client_sap::CONFIGURATOR,
        };
        assert_eq!(list.method_count(configurator), 1);
        assert_eq!(list.method_count(reader), 0);

        // The anonymous public level has no methods at all.
        let list = ServerObjectList {
            server: &server,
            sap: client_sap::PUBLIC,
        };
        assert_eq!(list.method_count(public), 0);
        assert_eq!(list.method_count(reader), 0);
    }

    /// Security setup — общий объект: доступен только тому уровню клиента,
    /// чья ассоциация ссылается на него (`security_setup_reference`, attr 9).
    /// Одна ассоциация на уровень → правило выражено потолком `Access`.
    #[test]
    fn server_security_setup_only_for_configurator() {
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let mut server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        let suite = SecuritySetup::new(SECURITY_SETUP_OBIS).security_suite();
        let title = SecuritySetup::new(SECURITY_SETUP_OBIS).server_system_title();

        // The configurator association references the Security setup → read allowed.
        assert!(server
            .lookup_value(
                descriptor(ClassId::SecuritySetup, suite),
                &Settings::configurator()
            )
            .is_ok());

        // Public and reader have no reference → no access at all.
        assert!(matches!(
            server.lookup_value(
                descriptor(ClassId::SecuritySetup, suite),
                &Settings::public()
            ),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));
        let reader = Settings::reader();
        assert!(matches!(
            server.lookup_value(descriptor(ClassId::SecuritySetup, suite), &reader),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // Write side: both Security setup attributes are not SET-able at all
        // (`Static`/`Dynamic`), so the denial is kind-based for every level;
        // `SHARED_WRITE` would matter only for a `Persistent` attribute.
        assert!(matches!(
            server.stream_set(ClassId::SecuritySetup, title, &reader),
            Err(DataAccessResult::ReadWriteDenied)
        ));
        assert!(matches!(
            server.stream_set(ClassId::SecuritySetup, title, &Settings::configurator()),
            Err(DataAccessResult::ReadWriteDenied)
        ));
    }

    /// `object_list` advertises only objects that the level can access at all.
    #[test]
    fn server_object_list_hides_inaccessible_objects() {
        use dlms1::ic::association_ln::ObjectListSource;
        use dlms1::ic::client_sap;

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        // `(objects listed, is the Security setup among them)`.
        let scan = |sap: u8| -> (usize, bool) {
            let source = ServerObjectList {
                server: &server,
                sap,
            };
            let mut has_security_setup = false;
            for item in 0..source.object_count() {
                if source.element(item).logical_name == SECURITY_SETUP_OBIS {
                    has_security_setup = true;
                }
            }
            (source.object_count(), has_security_setup)
        };

        // The configurator level references it → the whole catalog (6 objects).
        assert_eq!(scan(client_sap::CONFIGURATOR), (6, true));
        // Public/reader have no access to it → the object is left out.
        assert_eq!(scan(client_sap::PUBLIC), (5, false));
        assert_eq!(scan(client_sap::READER), (5, false));
    }

    /// Attribute 1 (`logical_name`) is implicit for every catalog object.
    ///
    /// The base alias (`0.0.40.0.0.255`) reports its own OBIS even when a real
    /// association is selected (it is a catalog object listed in `object_list`),
    /// while attr 3/5/8 resolve to the selected association.
    #[test]
    fn server_get_logical_name_for_all_objects() {
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        // The configurator association references the Security setup, so every
        // catalog object (including the shared one) is reachable.
        let mut ctx = Settings::configurator();
        ctx.assoc_idx = server.object_index(&ASSOC_LN_CONFIGURATOR_OBIS).unwrap() as u8;
        for &(obj, _) in crate::OBJECTS {
            let obis = obj.obis();
            let descriptor = CosemAttributeDescriptor {
                class_id: obj.class_id().as_u16(),
                instance_id: obis.bytes,
                attribute_id: ATTR_LOGICAL_NAME,
            };
            let mut tx = [0u8; 64];
            let n = {
                let mut b = ByteBuffer::new(&mut tx);
                server
                    .handle_get(invoke, descriptor, &mut ctx, &mut b)
                    .unwrap()
            };
            let resp = {
                let mut r = Reader::new(&tx[..n]);
                GetResponse::get(&mut r).unwrap()
            };
            let mut expected = [0u8; 8];
            expected[0] = 0x09; // octet-string
            expected[1] = 0x06;
            expected[2..].copy_from_slice(&obis.bytes);
            match resp {
                GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::Data(d),
                    ..
                }) => assert_eq!(d.as_bytes(), &expected[..], "OBIS {obis:?}"),
                other => panic!("expected data, got {other:?}"),
            }
        }
    }

    /// `application_context_name` (attr 4): the current/base association uses the
    /// negotiated context; a foreign one infers ciphering from attr 9.
    #[test]
    fn server_get_application_context_name() {
        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });
        let invoke = InvokeIdAndPriority::from_bits(1, true, false);

        let expected = |app: ApplicationContextName| {
            let mut bytes = [0u8; 17];
            let n = {
                let mut b = ByteBuffer::new(&mut bytes);
                ContextNameStructure::from_application_context(app)
                    .put(&mut b)
                    .unwrap()
            };
            assert_eq!(n, 17);
            bytes
        };

        let get = |ctx: &mut Settings, obis: ObisCode| -> std::vec::Vec<u8> {
            let descriptor = CosemAttributeDescriptor {
                class_id: ClassId::AssociationLn.as_u16(),
                instance_id: obis.bytes,
                attribute_id: ATTR_APPLICATION_CONTEXT_NAME,
            };
            let mut tx = [0u8; 64];
            let n = {
                let mut b = ByteBuffer::new(&mut tx);
                server.handle_get(invoke, descriptor, ctx, &mut b).unwrap()
            };
            let mut r = Reader::new(&tx[..n]);
            match GetResponse::get(&mut r).unwrap() {
                GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::Data(d),
                    ..
                }) => d.as_bytes().to_vec(),
                other => panic!("expected data, got {other:?}"),
            }
        };

        let configurator_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as u8;
        let reader_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_READER_OBIS)
            .unwrap()
            .0 as u8;

        // Current = configurator, negotiated ciphering.
        let mut ctx = Settings::configurator();
        ctx.assoc_idx = configurator_idx;
        ctx.app_context = ApplicationContextName::LogicalNameCiphering;
        assert_eq!(
            get(&mut ctx, ASSOC_LN_CONFIGURATOR_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameCiphering)[..]
        );
        assert_eq!(
            get(&mut ctx, ASSOC_LN_BASE_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameCiphering)[..]
        );
        // Foreign public/reader have no `security_setup_reference`.
        assert_eq!(
            get(&mut ctx, ASSOC_LN_PUBLIC_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameNoCiphering)[..]
        );
        assert_eq!(
            get(&mut ctx, ASSOC_LN_READER_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameNoCiphering)[..]
        );

        // Current = reader, no ciphering; a foreign configurator still has attr 9.
        let mut ctx = Settings::reader();
        ctx.assoc_idx = reader_idx;
        ctx.app_context = ApplicationContextName::LogicalNameNoCiphering;
        assert_eq!(
            get(&mut ctx, ASSOC_LN_READER_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameNoCiphering)[..]
        );
        assert_eq!(
            get(&mut ctx, ASSOC_LN_BASE_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameNoCiphering)[..]
        );
        assert_eq!(
            get(&mut ctx, ASSOC_LN_CONFIGURATOR_OBIS).as_slice(),
            &expected(ApplicationContextName::LogicalNameCiphering)[..]
        );
    }

    /// `xDLMS_context_info` (attr 5) is computed from the session state (not stored):
    /// GET returns the structure `{ conformance, max_receive, max_send, dlms_version,
    /// quality_of_service = 0, cyphering_info }`.
    #[test]
    fn server_get_xdlms_context_info_computed() {
        use dlms1::ic::association_ln::{ATTR_ASSOCIATION_STATUS, ATTR_XDLMS_CONTEXT_INFO};

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(NO_MUT)
        });

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_CONFIGURATOR_OBIS.bytes,
            attribute_id: ATTR_XDLMS_CONTEXT_INFO,
        };
        let mut ctx = Settings::configurator();
        ctx.tx_max = 1200;
        ctx.conformance = Conformance([0x11, 0x22, 0x33]);
        ctx.assoc_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as u8;
        ctx.state = SessionState::Associated;

        let mut tx = [0u8; 128];
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, descriptor, &mut ctx, &mut b)
                .unwrap()
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
            attribute_id: ATTR_XDLMS_CONTEXT_INFO,
        };
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, base_descriptor, &mut ctx, &mut b)
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
            attribute_id: ATTR_XDLMS_CONTEXT_INFO,
        };
        let n = {
            let mut b = ByteBuffer::new(&mut tx);
            server
                .handle_get(invoke, other_descriptor, &mut ctx, &mut b)
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

        // association_status (attr 8): the current/base association reflects the
        // session state; a foreign association has no active session.
        let mut get_bytes = |obis: ObisCode, attribute_id: i8| {
            let descriptor = CosemAttributeDescriptor {
                class_id: ClassId::AssociationLn.as_u16(),
                instance_id: obis.bytes,
                attribute_id,
            };
            let mut tx = [0u8; 128];
            let n = {
                let mut b = ByteBuffer::new(&mut tx);
                server
                    .handle_get(invoke, descriptor, &mut ctx, &mut b)
                    .unwrap()
            };
            let mut r = Reader::new(&tx[..n]);
            match GetResponse::get(&mut r).unwrap() {
                GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::Data(d),
                    ..
                }) => d.as_bytes().to_vec(),
                other => panic!("expected GetResponse::Normal with data, got {other:?}"),
            }
        };
        assert_eq!(
            get_bytes(ASSOC_LN_CONFIGURATOR_OBIS, ATTR_ASSOCIATION_STATUS).as_slice(),
            &[0x16, 0x02], // enum 2 (associated)
        );
        assert_eq!(
            get_bytes(ASSOC_LN_BASE_OBIS, ATTR_ASSOCIATION_STATUS).as_slice(),
            &[0x16, 0x02], // enum 2 (associated)
        );
        assert_eq!(
            get_bytes(ASSOC_LN_READER_OBIS, ATTR_ASSOCIATION_STATUS).as_slice(),
            &[0x16, 0x00], // enum 0 (non-associated)
        );
    }

    /// Computed values that do not fit into `tx` are split into
    /// `get-response-with-datablock` blocks (strategy 1: re-encode + window).
    /// A 20-byte buffer is too small even for the 19-byte `xDLMS_context_info`.
    #[test]
    fn server_get_xdlms_context_info_block_transfer() {
        use cosempdu::apdu::GetResponseWithDatablock;

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);
        static mut MUT: [Option<&'static mut dyn Codec>; 5] = [None, None, None, None, None];

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_CONFIGURATOR_OBIS.bytes,
            attribute_id: ATTR_XDLMS_CONTEXT_INFO,
        };
        let mut ctx = Settings::configurator();
        ctx.tx_max = 1200;
        ctx.conformance = Conformance([0x11, 0x22, 0x33]);
        ctx.assoc_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as u8;
        ctx.state = SessionState::Associated;

        // Full A-XDR `xDLMS_context_info` (19 bytes).
        let expected = [
            0x02, 0x06, // structure {6}
            0x04, 0x18, 0x11, 0x22, 0x33, // bit-string 24
            0x12, 0x04, 0x00, // long-unsigned 1024
            0x12, 0x04, 0xB0, // long-unsigned 1200
            0x11, 0x06, // unsigned 6
            0x0F, 0x00, // integer 0
            0x09, 0x00, // empty octet-string
        ];

        let mut assembled = [0u8; 32];
        let mut len = 0usize;
        let mut block_number = 0u32;
        loop {
            let mut tx = [0u8; 20];
            let n = {
                let mut b = ByteBuffer::new(&mut tx);
                if block_number == 0 {
                    server
                        .handle_get(invoke, descriptor, &mut ctx, &mut b)
                        .unwrap()
                } else {
                    server
                        .handle_get_next(invoke, block_number, &mut ctx, &mut b)
                        .unwrap()
                }
            };
            let resp = {
                let mut r = Reader::new(&tx[..n]);
                GetResponse::get(&mut r).unwrap()
            };
            match resp {
                GetResponse::WithDatablock(GetResponseWithDatablock { result: block, .. }) => {
                    let payload = match block.result {
                        cosempdu::apdu::DataBlockGResult::RawData(bytes) => bytes,
                        other => panic!("expected raw-data, got {other:?}"),
                    };
                    assembled[len..len + payload.len()].copy_from_slice(payload);
                    len += payload.len();
                    if block.last_block {
                        break;
                    }
                    block_number = block.block_number + 1;
                }
                other => panic!("expected GetResponse::WithDatablock, got {other:?}"),
            }
        }

        assert_eq!(&assembled[..len], &expected);
        assert!(ctx.get_block.is_none());
    }

    /// `block_capacity` must terminate and be maximal at the A-XDR length-prefix
    /// boundaries (fixed-point iteration used to oscillate at `tx_max` 138/267).
    #[test]
    fn block_capacity_boundaries() {
        let server = server(&[]);
        let mut ctx = Settings::configurator();
        ctx.tx_max = 0; // use the buffer size

        for avail in [
            10usize, 11, 20, 127, 128, 129, 130, 137, 138, 139, 255, 256, 257, 258, 267, 268, 1024,
        ] {
            let mut backing = [0u8; 1024];
            let buf = ByteBuffer::new(&mut backing[..avail]);
            let cap = server.block_capacity(&ctx, &buf);
            assert!(
                9 + length_prefix_len(cap) + cap <= avail,
                "does not fit: avail={avail} cap={cap}"
            );
            if cap + 1 <= avail {
                assert!(
                    9 + length_prefix_len(cap + 1) + cap + 1 > avail,
                    "not maximal: avail={avail} cap={cap}"
                );
            }
        }
    }

    /// `object_list` (Association LN, attr 2) is computed per association and can
    /// be transferred in blocks: the reassembled blocks equal the whole value.
    #[test]
    fn server_get_object_list_transfer() {
        use cosempdu::apdu::GetResponseWithDatablock;
        use cosempdu::axdr::get_length;

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);
        static mut MUT: [Option<&'static mut dyn Codec>; 5] = [None, None, None, None, None];

        let server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(MUT)
        });

        let invoke = InvokeIdAndPriority::from_bits(1, true, false);
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: ASSOC_LN_CONFIGURATOR_OBIS.bytes,
            attribute_id: ATTR_OBJECT_LIST,
        };
        let mut ctx = Settings::configurator();
        ctx.tx_max = 1200;
        ctx.assoc_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_CONFIGURATOR_OBIS)
            .unwrap()
            .0 as u8;
        ctx.state = SessionState::Associated;

        // 1) Whole value in one normal response (large buffer).
        let mut big = [0u8; 1024];
        let n = {
            let mut b = ByteBuffer::new(&mut big);
            server
                .handle_get(invoke, descriptor, &mut ctx, &mut b)
                .unwrap()
        };
        let full = {
            let mut r = Reader::new(&big[..n]);
            match GetResponse::get(&mut r).unwrap() {
                GetResponse::Normal(GetResponseNormal {
                    result: GetDataResult::Data(d),
                    ..
                }) => d.as_bytes().to_vec(),
                other => panic!("expected normal data, got {other:?}"),
            }
        };
        // array of all catalog objects
        assert_eq!(full[0], 0x01);
        {
            let mut r = Reader::new(&full[1..]);
            assert_eq!(get_length(&mut r).unwrap(), crate::OBJECTS.len());
        }

        // 2) Same value split into 20-byte blocks.
        let mut assembled = std::vec::Vec::new();
        let mut block_number = 0u32;
        loop {
            let mut tx = [0u8; 20];
            let n = {
                let mut b = ByteBuffer::new(&mut tx);
                if block_number == 0 {
                    server
                        .handle_get(invoke, descriptor, &mut ctx, &mut b)
                        .unwrap()
                } else {
                    server
                        .handle_get_next(invoke, block_number, &mut ctx, &mut b)
                        .unwrap()
                }
            };
            let resp = {
                let mut r = Reader::new(&tx[..n]);
                GetResponse::get(&mut r).unwrap()
            };
            match resp {
                GetResponse::WithDatablock(GetResponseWithDatablock { result: block, .. }) => {
                    let payload = match block.result {
                        cosempdu::apdu::DataBlockGResult::RawData(bytes) => bytes,
                        other => panic!("expected raw-data, got {other:?}"),
                    };
                    assembled.extend_from_slice(payload);
                    if block.last_block {
                        break;
                    }
                    block_number = block.block_number + 1;
                }
                other => panic!("expected GetResponse::WithDatablock, got {other:?}"),
            }
        }

        assert_eq!(assembled, full);
        assert!(ctx.get_block.is_none());
    }

    /// Secret (attr 7) — Persistent: readable only by the owning association's
    /// client level after authentication; SET is denied (the value is changed
    /// through `change_HLS_secret`, method 2). Other levels — no access.
    #[test]
    fn server_secret_authenticated_owner_only() {
        static mut SECRETS: [Option<&'static mut dyn Codec>; 4] = [None, None, None, None];
        static mut S_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut S_CONFIG: OctetString<16> = OctetString::new(b"ABCDEFGH");

        unsafe {
            SECRETS[2] = Some(&mut *core::ptr::addr_of_mut!(S_READER));
            SECRETS[3] = Some(&mut *core::ptr::addr_of_mut!(S_CONFIG));
        }

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let mut server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(SECRETS)
        });

        let reader_secret = AssociationLn::new(ASSOC_LN_READER_OBIS).secret();
        let config_secret = AssociationLn::new(ASSOC_LN_CONFIGURATOR_OBIS).secret();

        // The owning level reads its own secret after authentication; SET is
        // denied — the value is changed through method 2 (see the ACTION test).
        let mut reader = Settings::reader();
        reader.authenticated = true;
        assert!(server
            .lookup_value(descriptor(ClassId::AssociationLn, reader_secret), &reader)
            .is_ok());
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, reader_secret, &reader),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        let mut configurator = Settings::configurator();
        configurator.authenticated = true;
        assert!(server
            .lookup_value(
                descriptor(ClassId::AssociationLn, config_secret),
                &configurator
            )
            .is_ok());
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, config_secret, &configurator),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // Without authentication the owning level has no access (`Authenticated*`).
        let plain_reader = Settings::reader();
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, reader_secret, &plain_reader),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));
        assert!(matches!(
            server.lookup_value(
                descriptor(ClassId::AssociationLn, reader_secret),
                &plain_reader
            ),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // Other client levels have no access to a foreign secret.
        let public = Settings::public();
        for ctx in [&public, &configurator] {
            assert!(matches!(
                server.stream_set(ClassId::AssociationLn, reader_secret, ctx),
                Err(DataAccessResult::ScopeOfAccessViolated)
            ));
            assert!(matches!(
                server.lookup_value(descriptor(ClassId::AssociationLn, reader_secret), ctx),
                Err(DataAccessResult::ScopeOfAccessViolated)
            ));
        }
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, config_secret, &reader),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));
    }

    /// The base alias `0.0.40.0.0.255` is resolved by SET as well (like GET/ACTION):
    /// the lookup address becomes the current association's object.
    #[test]
    fn server_stream_set_resolves_base_alias() {
        static mut SECRETS: [Option<&'static mut dyn Codec>; 4] = [None, None, None, None];
        static mut S_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        unsafe {
            SECRETS[2] = Some(&mut *core::ptr::addr_of_mut!(S_READER));
        }

        static OBJECTS: &[&dyn InterfaceClass] = &crate::merge_objects::<6>(&[], crate::OBJECTS);
        static ROM_ATTRS: [AttrDesc; 28] =
            crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
        static ROM_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

        let mut server = Server::new(OBJECTS, &ROM_ATTRS, &ROM_CODECS, unsafe {
            &mut *core::ptr::addr_of_mut!(SECRETS)
        });
        let reader_idx = server
            .find_object(ClassId::AssociationLn.as_u16(), &ASSOC_LN_READER_OBIS)
            .unwrap()
            .0 as u8;

        // `secret` (attr 7) does not exist on the bare alias object, but it does
        // on the resolved association — where it is write-protected. So the denial
        // is `ScopeOfAccessViolated`, not `ObjectUndefined`.
        let key = AssociationLn::new(ASSOC_LN_BASE_OBIS).secret();
        let mut ctx = Settings::reader();
        ctx.assoc_idx = reader_idx;
        ctx.authenticated = true;
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, key, &ctx),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // Without a selected association the alias stays the alias (no attr 7).
        ctx.assoc_idx = u8::MAX;
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, key, &ctx),
            Err(DataAccessResult::ObjectUndefined)
        ));
    }

    /// Every entry of the ROM method registry must have a dispatch handler in
    /// `Server::handle_action` — otherwise the method is advertised in
    /// `object_list` but cannot be executed (`hardware-fault`).
    #[cfg(any(feature = "tcp", feature = "ble"))]
    #[test]
    fn every_registry_method_has_handler() {
        /// Same check as below, for an arbitrary registry table.
        fn all_handled(methods: &[MethodSpec]) -> bool {
            methods.iter().all(|spec| {
                let class_id = crate::OBJECTS
                    .iter()
                    .find(|(_, obis)| *obis == spec.key.obis)
                    .expect("a method OBIS must be in the catalog")
                    .0
                    .class_id();
                has_handler(class_id, spec.key.method_id)
            })
        }

        assert!(
            all_handled(crate::METHODS),
            "a registry entry is advertised but has no handler in handle_action"
        );

        // Negative control: `add_object` (method 3) is a declared method of
        // Association LN without a handler, so the check must reject it.
        let drifted = [MethodSpec {
            key: AssociationLn::new(ASSOC_LN_READER_OBIS).add_object(),
            access: READER_METHOD_ACCESS,
        }];
        assert!(
            !all_handled(&drifted),
            "a method without a handler was not detected"
        );
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
    static DEFAULT_ATTRS: [AttrDesc; 28] =
        crate::merge_attrs::<28>(&[], crate::OBJECTS, &[], crate::ATTRS);
    static DEFAULT_CODECS: [&dyn Codec; 8] = crate::merge_codecs::<8>(&[], crate::ATTRS);

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
        use crate::SessionState;

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
        assert_eq!(session.settings.state, SessionState::Disconnecting);

        // Response: WPDU header + RLRE.
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Rlre(r) => assert_eq!(r.reason, Some(ReleaseResponseReason::Normal)),
            other => panic!("expected RLRE, got {other:?}"),
        }
    }

    /// A release APDU that cannot be interpreted is silently discarded: no RLRE
    /// is sent and the association stays established (Green Book 9.3.3 — no
    /// `.indication` without an RLRQ).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_discards_malformed_rlrq() {
        use crate::SessionState;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));
        session.settings.state = SessionState::Associated;

        // `62 05` promises 5 content bytes, only 3 follow → BER length mismatch.
        let malformed = [0x62, 0x05, 0x80, 0x01, 0x00];
        session.rx_mut()[..malformed.len()].copy_from_slice(&malformed);
        session.set_rx_len(malformed.len());

        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap()
        };
        assert!(!send, "a discarded APDU must not produce a response");
        assert_eq!(session.settings.state, SessionState::Associated);

        // An RLRQ with no optional fields is valid: `62 00` → RLRE + release.
        session.rx_mut()[..2].copy_from_slice(&[0x62, 0x00]);
        session.set_rx_len(2);
        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap()
        };
        assert!(send, "a valid RLRQ must be answered with an RLRE");
        assert_eq!(session.settings.state, SessionState::Disconnecting);
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        assert!(matches!(
            ACSEApdu::get(&mut Reader::new(apdu)).unwrap(),
            ACSEApdu::Rlre(_)
        ));
    }

    /// AARQ (anonymous public association) → AARE + Session.state = Associated.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_aarq() {
        use crate::SessionState;
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
        assert_eq!(session.settings.state, SessionState::Associated);

        // Response: AARE (accepted).
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
            ACSEApdu::Aare(a) => assert_eq!(a.result, AssociationResult::Accepted),
            other => panic!("expected AARE, got {other:?}"),
        }
    }

    /// An AARQ that cannot be decoded is discarded: no AARE, no state change
    /// (Green Book 9.3.2 — `.indication` only for a correctly formatted AARQ).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_discards_malformed_aarq() {
        use crate::SessionState;

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        // `60 05` promises 5 content bytes, only 3 follow → BER length mismatch.
        let malformed = [0x60, 0x05, 0xA1, 0x09, 0x06];
        session.rx_mut()[..malformed.len()].copy_from_slice(&malformed);
        session.set_rx_len(malformed.len());

        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap()
        };
        assert!(!send, "a discarded AARQ must not produce a response");
        assert_eq!(session.settings.state, SessionState::Idle);
        assert_eq!(session.settings.assoc_idx, u8::MAX);
    }

    /// A valid AARQ without `user-information` (no xDLMS InitiateRequest) is
    /// rejected with an AARE carrying an `acse-service-provider` diagnostic
    /// (Green Book 9.4.4.1: "the AARQ syntax is not acceptable").
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_aarq_without_user_information() {
        use crate::SessionState;
        use cosempdu::acse::{
            AARQapdu, AcseServiceProvider, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult,
        };

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();

        let aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        let mut apdu = [0u8; 128];
        let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
        session.set_rx_len(m);

        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap()
        };
        assert!(
            send,
            "the rejection AARE is sent even without a known response_allowed"
        );
        assert_eq!(session.settings.state, SessionState::Idle);
        // A rejection leaves no negotiated state behind.
        assert_eq!(session.settings.assoc_idx, u8::MAX);

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

    /// The requested mechanism must correspond to the association's
    /// `authentication_mechanism_name` (attr 6): public/reader are LLS, the
    /// configurator is HLS. A missing mechanism is rejected for an
    /// authenticating association, and an HLS association requires the
    /// authentication functional unit (sender-acse-requirements, bit 0).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_checks_authentication_mechanism() {
        use crate::{Session, SessionState};
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult, AuthenticationValue, MechanismName,
        };
        use cosempdu::apdu::InitiateRequest;
        use dlms1::ic::client_sap;

        fn put_aarq(session: &mut Session, mechanism: Option<MechanismName>, auth_bit: bool) {
            let req = InitiateRequest::new(CONF, 1200);
            let mut ui = [0u8; 64];
            let n = req.put(&mut ByteBuffer::new(&mut ui)).unwrap();
            let mut aarq = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
            aarq.sender_acse_requirements = auth_bit;
            aarq.mechanism_name = mechanism;
            if auth_bit {
                aarq.calling_authentication_value = Some(AuthenticationValue::CharString(b"x"));
            }
            aarq.user_information = Some(&ui[..n]);
            let mut apdu = [0u8; 256];
            let m = aarq.put(&mut ByteBuffer::new(&mut apdu)).unwrap();
            session.rx_mut()[..m].copy_from_slice(&apdu[..m]);
            session.set_rx_len(m);
        }

        fn run(
            server: &mut Server,
            mechanism: Option<MechanismName>,
            auth_bit: bool,
            source_sap: u16,
        ) -> (SessionState, AcseServiceUser) {
            let mut session = server.on_connect(Media::Tcp).unwrap();
            put_aarq(&mut session, mechanism, auth_bit);
            {
                let (settings, transport_ref, rx, tx) = session.parts();
                server
                    .process_request(settings, transport_ref, rx, tx, Wrapper::new(source_sap, 1))
                    .unwrap();
            }
            let state = session.settings.state;
            let tx = session.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            let diagnostic = match ACSEApdu::get(&mut Reader::new(apdu)).unwrap() {
                ACSEApdu::Aare(a) => {
                    assert_eq!(a.result, AssociationResult::RejectedPermanent);
                    match a.result_source_diagnostic {
                        AssociateSourceDiagnostic::ServiceUser(d) => d,
                        other => panic!("expected service-user diagnostic, got {other:?}"),
                    }
                }
                other => panic!("expected AARE, got {other:?}"),
            };
            (state, diagnostic)
        }

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);

        // Public (no auth) + HLS mechanism → mechanism name not recognised.
        let (state, diagnostic) = run(
            &mut server,
            Some(MechanismName::HighLevelSecurityEcdsa),
            true,
            client_sap::PUBLIC as u16,
        );
        assert_eq!(state, SessionState::Idle);
        assert_eq!(
            diagnostic,
            AcseServiceUser::AuthenticationMechanismNameNotRecognised
        );

        // Reader (LLS) without a mechanism → mechanism name required.
        let (state, diagnostic) = run(&mut server, None, false, client_sap::READER as u16);
        assert_eq!(state, SessionState::Idle);
        assert_eq!(
            diagnostic,
            AcseServiceUser::AuthenticationMechanismNameRequired
        );

        // Configurator (HLS) names a mechanism but does not select authentication
        // (sender-acse-requirements bit 0 clear) → mechanism name required.
        let (state, diagnostic) = run(
            &mut server,
            Some(MechanismName::HighLevelSecurity),
            false,
            client_sap::CONFIGURATOR as u16,
        );
        assert_eq!(state, SessionState::Idle);
        assert_eq!(
            diagnostic,
            AcseServiceUser::AuthenticationMechanismNameRequired
        );
    }

    /// AARQ with version-too-low → AARE(RejectedPermanent) + ConfirmedServiceError(initiate: dlms-version-too-low).
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_dlms_version_too_low() {
        use crate::SessionState;
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

        // Association NOT established (stays idle).
        assert_eq!(session.settings.state, SessionState::Idle);

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

        // The rejection leaves no association state behind: the session is clean
        // and usable, so a corrected AARQ on the same session is accepted.
        assert_eq!(session.settings.assoc_idx, u8::MAX);
        let mut retry_ui = [0u8; 64];
        let n = InitiateRequest::new(CONF, 1200)
            .put(&mut ByteBuffer::new(&mut retry_ui))
            .unwrap();
        let mut retry = AARQapdu::new(ApplicationContextName::LogicalNameNoCiphering);
        retry.user_information = Some(&retry_ui[..n]);
        let mut retry_apdu = [0u8; 256];
        let m = retry.put(&mut ByteBuffer::new(&mut retry_apdu)).unwrap();
        session.rx_mut()[..m].copy_from_slice(&retry_apdu[..m]);
        session.set_rx_len(m);
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, SessionState::Associated);
        assert_ne!(session.settings.assoc_idx, u8::MAX);
    }

    /// AARQ with ciphering but without calling-AP-title → AARE(RejectedPermanent) +
    /// acse-service-provider: no-reason-given.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_rejects_ciphering_without_calling_ap_title() {
        use crate::SessionState;
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

        // Association NOT established (stays idle).
        assert_eq!(session.settings.state, SessionState::Idle);

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
        use crate::{CallingAeQualifier, Session, SessionState};
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
        //    The configurator association (SAP 0x30) is the HLS one.
        let mut session = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session, Some(&cert), Some(&ctos));
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x30, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, SessionState::Associating);
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
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x30, 1))
                .unwrap();
        }
        assert_eq!(session2.settings.state, SessionState::Idle);
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
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x30, 1))
                .unwrap();
        }
        assert_eq!(session3.settings.state, SessionState::Idle);
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

    /// A malformed xDLMS request is answered with an exception-response (Table 89)
    /// and the association survives: the next valid request is served normally.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_answers_malformed_get_and_keeps_association() {
        use crate::SessionState;
        use cosempdu::apdu::{
            CosemAttributeDescriptor, ExceptionResponse, GetDataResult, GetRequest, GetResponse,
            GetResponseNormal, ImplicitTagged, InvokeIdAndPriority, ServiceError_, StateError,
        };
        use dlms1::ic::association_ln::ATTR_LOGICAL_NAME;
        use dlms1::ic::{client_sap, ClassId};

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(NO_MUT)
            });
        server.set_wport(1);
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 16));
        session.settings.state = SessionState::Associated;
        session.settings.client_sap = client_sap::PUBLIC;

        // Get-Request truncated after the tag and the type count: no invoke-id.
        session.rx_mut()[..2].copy_from_slice(&[0xC0, 0x01]);
        session.set_rx_len(2);

        let send = {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap()
        };
        assert!(send, "the exception-response is a real response");
        assert_eq!(
            session.settings.state,
            SessionState::Associated,
            "the association must survive a malformed request"
        );
        {
            let tx = session.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            let exc = ExceptionResponse::get(&mut Reader::new(apdu)).unwrap();
            assert_eq!(exc.state_error, StateError::ServiceUnknown);
            assert_eq!(exc.service_error, ServiceError_::OperationNotPossible);
        }

        // The session is still usable: `logical_name` of the base association.
        let descriptor = CosemAttributeDescriptor {
            class_id: ClassId::AssociationLn.as_u16(),
            instance_id: crate::ASSOC_LN_BASE_OBIS.bytes,
            attribute_id: ATTR_LOGICAL_NAME,
        };
        let mut backing = [0u8; 32];
        let n = {
            let mut b = ByteBuffer::new(&mut backing);
            GetRequest::put_normal(
                InvokeIdAndPriority::from_bits(3, true, false),
                descriptor,
                None,
                &mut b,
            )
            .unwrap()
        };
        session.rx_mut()[..n].copy_from_slice(&backing[..n]);
        session.set_rx_len(n);
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(16, 1))
                .unwrap();
        }
        let tx = session.tx();
        let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
        let apdu = &tx[8..8 + frame.apdu_len() as usize];
        match GetResponse::get(&mut Reader::new(apdu)).unwrap() {
            GetResponse::Normal(GetResponseNormal {
                result: GetDataResult::Data(d),
                ..
            }) => {
                let mut expected = [0u8; 8];
                expected[0] = 0x09; // octet-string
                expected[1] = 0x06;
                expected[2..].copy_from_slice(&crate::ASSOC_LN_BASE_OBIS.bytes);
                assert_eq!(d.as_bytes(), &expected[..]);
            }
            other => panic!("expected data, got {other:?}"),
        }
    }

    /// LLS (LowLevelSecurity): the password from calling-authentication-value is compared with
    /// the association `secret` (attr 7); correct password → accepted, wrong → rejected.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_lls_secret() {
        use crate::{Session, SessionState};
        use cosempdu::acse::{
            AARQapdu, AcseServiceUser, ApplicationContextName, AssociateSourceDiagnostic,
            AssociationResult, AuthenticationValue, MechanismName,
        };
        use cosempdu::apdu::InitiateRequest;
        use dlms1::common_data_types::OctetString;

        // Association secrets (Persistent slots 2/3 of the default registry).
        static mut SECRET_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut SECRET_CONFIGURATOR: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut LLS_MUT: [Option<&'static mut dyn Codec>; 4] = [None, None, None, None];

        unsafe {
            LLS_MUT[2] = Some(&mut *core::ptr::addr_of_mut!(SECRET_READER));
            LLS_MUT[3] = Some(&mut *core::ptr::addr_of_mut!(SECRET_CONFIGURATOR));
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
        //    LLS belongs to the reader association (SAP 0x20).
        let mut session = server.on_connect(Media::Tcp).unwrap();
        put_aarq(&mut session, Some(b"ABCDEFGH"));
        {
            let (settings, transport_ref, rx, tx) = session.parts();
            server
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x20, 1))
                .unwrap();
        }
        assert_eq!(session.settings.state, SessionState::Associated);
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
                .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x20, 1))
                .unwrap();
        }
        assert_eq!(session2.settings.state, SessionState::Idle);
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
            .find_object(
                ClassId::AssociationLn.as_u16(),
                &crate::ASSOC_LN_CONFIGURATOR_OBIS,
            )
            .unwrap();
        assert_eq!(
            server.security_suite(idx as u8),
            Some(SecuritySuite::AesGcm128)
        );

        // Reader (LLS) has no reference → None.
        let (idx, _) = server
            .find_object(
                ClassId::AssociationLn.as_u16(),
                &crate::ASSOC_LN_READER_OBIS,
            )
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
        use crate::{Access, AttrDesc, AttrKind, AttrSpec, SessionState};
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
        session.settings.state = SessionState::Associated;
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
        use crate::{Access, AttrDesc, AttrKind, AttrSpec, SessionState};
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
        session.settings.state = SessionState::Associated;
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

    /// `change_HLS_secret` (Association LN method 2): the current association
    /// changes its own secret through ACTION; the `secret` attribute stays
    /// read-only for SET.
    #[cfg(feature = "tcp")]
    #[test]
    fn process_request_handles_change_secret_action() {
        use crate::{Session, SessionState};
        use cosempdu::apdu::{
            ActionRequest, ActionResponse, ActionResponseNormal, ActionResult,
            CosemAttributeDescriptor, CosemMethodDescriptor, DataAccessResult, ImplicitTagged,
            InvokeIdAndPriority,
        };
        use dlms1::common_data_types::OctetString;
        use dlms1::ic::association_ln::{ATTR_SECRET, METHOD_CHANGE_HLS_SECRET};
        use dlms1::ic::{client_sap, AttributeKey, ClassId};
        use dlms1::obis::ObisCode;

        static mut SECRETS: [Option<&'static mut dyn Codec>; 4] = [None, None, None, None];
        static mut S_READER: OctetString<16> = OctetString::new(b"ABCDEFGH");
        static mut S_CONFIG: OctetString<16> = OctetString::new(b"ABCDEFGH");
        unsafe {
            SECRETS[2] = Some(&mut *core::ptr::addr_of_mut!(S_READER));
            SECRETS[3] = Some(&mut *core::ptr::addr_of_mut!(S_CONFIG));
        }

        static METHODS: [crate::MethodDesc; 2] =
            crate::merge_methods::<2>(&[], crate::OBJECTS, &[], crate::METHODS);

        let mut server: Server =
            Server::new(DEFAULT_OBJECTS, &DEFAULT_ATTRS, &DEFAULT_CODECS, unsafe {
                &mut *core::ptr::addr_of_mut!(SECRETS)
            })
            .with_methods(&METHODS);
        server.set_wport(1);
        let reader_idx = server
            .find_object(
                ClassId::AssociationLn.as_u16(),
                &crate::ASSOC_LN_READER_OBIS,
            )
            .unwrap()
            .0 as u8;
        let configurator_idx = server
            .find_object(
                ClassId::AssociationLn.as_u16(),
                &crate::ASSOC_LN_CONFIGURATOR_OBIS,
            )
            .unwrap()
            .0 as u8;

        fn put_action(session: &mut Session, obis: ObisCode, params: Option<&dyn Codec>) {
            let mut backing = [0u8; 128];
            let n = ActionRequest::put_normal(
                InvokeIdAndPriority::from_bits(1, true, false),
                CosemMethodDescriptor {
                    class_id: ClassId::AssociationLn.as_u16(),
                    instance_id: obis.bytes,
                    method_id: METHOD_CHANGE_HLS_SECRET,
                },
                params,
                &mut ByteBuffer::new(&mut backing),
            )
            .unwrap();
            session.rx_mut()[..n].copy_from_slice(&backing[..n]);
            session.set_rx_len(n);
        }

        /// Already A-XDR encoded invocation parameters (wire-level framing cases).
        struct Raw<'a>(&'a [u8]);

        impl Codec for Raw<'_> {
            fn put(&self, buf: &mut ByteBuffer<'_>) -> cosempdu::Result<usize> {
                for b in self.0 {
                    buf.put_u8(*b)?;
                }
                Ok(self.0.len())
            }

            fn assign(&mut self, _: &cosempdu::data::Data<'_>) -> cosempdu::Result<()> {
                Err(cosempdu::Error::Message("test-only encode parameters"))
            }
        }

        fn response_result(session: &Session) -> ActionResult {
            let tx = session.tx();
            let frame = Wrapper::get(&mut Reader::new(&tx[..8])).unwrap();
            let apdu = &tx[8..8 + frame.apdu_len() as usize];
            match ActionResponse::get(&mut Reader::new(apdu)).unwrap() {
                ActionResponse::Normal(ActionResponseNormal {
                    single_response, ..
                }) => single_response.result,
                other => panic!("expected ActionResponse::Normal, got {other:?}"),
            }
        }

        /// Feed one ACTION request through `process_request`, return its result.
        fn exchange(
            server: &mut Server,
            session: &mut Session,
            obis: ObisCode,
            params: Option<&dyn Codec>,
        ) -> ActionResult {
            put_action(session, obis, params);
            {
                let (settings, transport_ref, rx, tx) = session.parts();
                server
                    .process_request(settings, transport_ref, rx, tx, Wrapper::new(0x20, 1))
                    .unwrap();
            }
            response_result(session)
        }

        /// Current reader `secret` value (A-XDR, tag included).
        fn secret_bytes(server: &Server, session: &Session, out: &mut [u8; 32]) -> usize {
            let key = AttributeKey::new(crate::ASSOC_LN_READER_OBIS, ATTR_SECRET);
            server
                .lookup_value(
                    CosemAttributeDescriptor {
                        class_id: ClassId::AssociationLn.as_u16(),
                        instance_id: key.obis.bytes,
                        attribute_id: key.attribute_id,
                    },
                    &session.settings,
                )
                .unwrap()
                .put(&mut ByteBuffer::new(out))
                .unwrap()
        }

        // 1) The authenticated reader changes its own secret.
        let mut session = server.on_connect(Media::Tcp).unwrap();
        session.transport_ref = TransportRef::Wrapper(Wrapper::new(1, 0x20));
        session.settings.state = SessionState::Associated;
        session.settings.client_sap = client_sap::READER;
        session.settings.assoc_idx = reader_idx;
        session.settings.authenticated = true;
        assert_eq!(
            exchange(
                &mut server,
                &mut session,
                crate::ASSOC_LN_READER_OBIS,
                Some(&OctetString::<16>::new(b"NEWSECRET")),
            ),
            ActionResult::Success
        );

        // The new value is stored and readable by the owner; SET is still denied.
        let key = AttributeKey::new(crate::ASSOC_LN_READER_OBIS, ATTR_SECRET);
        let mut backing = [0u8; 32];
        let n = server
            .lookup_value(
                CosemAttributeDescriptor {
                    class_id: ClassId::AssociationLn.as_u16(),
                    instance_id: key.obis.bytes,
                    attribute_id: key.attribute_id,
                },
                &session.settings,
            )
            .unwrap()
            .put(&mut ByteBuffer::new(&mut backing))
            .unwrap();
        assert_eq!(&backing[..n], b"\x09\x09NEWSECRET");
        assert!(matches!(
            server.stream_set(ClassId::AssociationLn, key, &session.settings),
            Err(DataAccessResult::ScopeOfAccessViolated)
        ));

        // 2) An unauthenticated reader cannot change the secret.
        session.settings.authenticated = false;
        assert_eq!(
            exchange(
                &mut server,
                &mut session,
                crate::ASSOC_LN_READER_OBIS,
                Some(&OctetString::<16>::new(b"ANOTHER1")),
            ),
            ActionResult::ScopeOfAccessViolated
        );

        // 3) A foreign association (configurator) cannot change the reader's secret.
        session.settings.client_sap = client_sap::CONFIGURATOR;
        session.settings.assoc_idx = configurator_idx;
        session.settings.authenticated = true;
        assert_eq!(
            exchange(
                &mut server,
                &mut session,
                crate::ASSOC_LN_READER_OBIS,
                Some(&OctetString::<16>::new(b"ANOTHER1")),
            ),
            ActionResult::ScopeOfAccessViolated
        );

        // 4) `structure { octet-string }` parameters are accepted too.
        session.settings.client_sap = client_sap::READER;
        session.settings.assoc_idx = reader_idx;
        assert_eq!(
            exchange(
                &mut server,
                &mut session,
                crate::ASSOC_LN_READER_OBIS,
                Some(&Raw(&[
                    0x02, 0x01, 0x09, 0x08, b'S', b'T', b'R', b'U', b'C', b'T', b'0', b'1',
                ])),
            ),
            ActionResult::Success
        );
        let mut secret = [0u8; 32];
        let n = secret_bytes(&server, &session, &mut secret);
        assert_eq!(&secret[..n], b"\x09\x08STRUCT01");

        // 5) A `structure` with two elements is `type-unmatched`.
        assert_eq!(
            exchange(
                &mut server,
                &mut session,
                crate::ASSOC_LN_READER_OBIS,
                Some(&Raw(&[0x02, 0x02, 0x09, 0x01, b'A', 0x09, 0x01, b'B'])),
            ),
            ActionResult::TypeUnmatched
        );

        // 6) No invocation parameters at all → `type-unmatched`.
        assert_eq!(
            exchange(&mut server, &mut session, crate::ASSOC_LN_READER_OBIS, None,),
            ActionResult::TypeUnmatched
        );

        // Neither rejected call (5, 6) changed the secret.
        let mut secret = [0u8; 32];
        let n = secret_bytes(&server, &session, &mut secret);
        assert_eq!(&secret[..n], b"\x09\x08STRUCT01");
    }
}
