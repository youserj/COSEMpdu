//! Association LN method handlers (ACTION dispatch targets).
//!
//! [`crate::Server::handle_action`] keeps the single `match` dispatch point;
//! every method is a separate function here (a dedicated module — so that a
//! large method set does not bloat `lib.rs`).

use cosempdu::apdu::ActionResult;
use cosempdu::axdr::get_length;
use cosempdu::buffer::Reader;
use cosempdu::stream::StreamDecoder;
use dlms1::ic::association_ln::ATTR_SECRET;

use crate::{RomKind, Server, Settings};

/// Outcome of a method handler: `Ok(())` is the `Action-Result` `success` (0),
/// `Err(result)` means the method was not performed and carries the reason.
///
/// Transport/APDU errors do not belong here: the request is already parsed by
/// [`crate::Server::process_action`] before the handler runs. `hardware-fault` is
/// reserved for server-side defects (a codec that cannot stream, a missing
/// slot), never for malformed client parameters — those are `type-unmatched`.
pub(crate) type ActionOutcome = Result<(), ActionResult>;

/// Invocation parameters of a single-argument method: a bare A-XDR value
/// (e.g. `octet-string`) or a `structure` with exactly one element.
///
/// Returns the A-XDR value (tag included) for [`StreamDecoder`]; `Err` is always
/// `type-unmatched` — it is the client's encoding that does not match.
fn single_parameter(raw: &[u8]) -> Result<&[u8], ActionResult> {
    match raw.first().copied() {
        // Bare value.
        Some(tag) if tag != 0x02 => Ok(raw),
        // `structure`: take the single element, drop the tag and the count.
        Some(_) => {
            let mut r = Reader::new(raw);
            r.get_u8().map_err(|_| ActionResult::TypeUnmatched)?;
            if get_length(&mut r).map_err(|_| ActionResult::TypeUnmatched)? != 1 {
                return Err(ActionResult::TypeUnmatched);
            }
            Ok(r.remaining_bytes())
        }
        None => Err(ActionResult::TypeUnmatched),
    }
}

/// The `Action-Result` for the response: `Ok(())` is `success`, `Err` carries the
/// reason as-is.
pub(crate) fn action_result(outcome: ActionOutcome) -> ActionResult {
    match outcome {
        Ok(()) => ActionResult::Success,
        Err(result) => result,
    }
}

impl<const N: usize> Server<N> {
    /// Association LN method 2 `change_HLS_secret`: set the association's
    /// `secret` (attr 7).
    ///
    /// Invocation parameters are the new secret as an `octet-string` (or a
    /// `structure { octet-string }`, for interoperability). Allowed only for
    /// the current association and only when authenticated.
    pub(crate) fn change_hls_secret(
        &mut self,
        settings: &Settings,
        index: u16,
        params: Option<Reader<'_>>,
    ) -> ActionOutcome {
        // The registry checks client level/auth (`MethodAccess`); here we
        // additionally require the current association (a session can only be
        // associated with the object of its client_SAP).
        if settings.assoc_idx == u8::MAX || u16::from(settings.assoc_idx) != index {
            return Err(ActionResult::ScopeOfAccessViolated);
        }

        let desc = self
            .attr(index, ATTR_SECRET)
            .ok_or(ActionResult::ObjectUndefined)?;
        // A non-persistent `secret` is a catalog defect, not a client error.
        let RomKind::Persistent(slot) = desc.kind else {
            return Err(ActionResult::HardwareFault);
        };

        let raw = params.ok_or(ActionResult::TypeUnmatched)?.remaining_bytes();
        let value = single_parameter(raw)?;

        // Write the value straight into the attribute slot: the method is the
        // write path for `secret` (the attribute itself is read-only).
        let codec = self.mutable[slot as usize]
            .as_deref_mut()
            .ok_or(ActionResult::HardwareFault)?;
        let sink = codec.stream_sink().ok_or(ActionResult::HardwareFault)?;
        let mut decoder = StreamDecoder::new(sink);
        decoder
            .push(value)
            .and_then(|()| decoder.finish())
            .map_err(|_| ActionResult::TypeUnmatched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OCTETS: [u8; 10] = [0x09, 0x08, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H'];

    #[test]
    fn bare_value_is_passed_through() {
        assert_eq!(single_parameter(&OCTETS), Ok(&OCTETS[..]));
    }

    #[test]
    fn single_element_structure_is_unwrapped() {
        let raw = [
            0x02, 0x01, 0x09, 0x08, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',
        ];
        // Tag and count dropped: the element itself is the parameter.
        assert_eq!(single_parameter(&raw), Ok(&raw[2..]));
    }

    #[test]
    fn malformed_parameters_are_type_unmatched() {
        // No parameters at all.
        assert_eq!(single_parameter(&[]), Err(ActionResult::TypeUnmatched));
        // `structure` truncated right after the tag (no length).
        assert_eq!(single_parameter(&[0x02]), Err(ActionResult::TypeUnmatched));
        // Empty `structure`.
        assert_eq!(
            single_parameter(&[0x02, 0x00]),
            Err(ActionResult::TypeUnmatched)
        );
        // `structure` with two elements: a method takes exactly one.
        assert_eq!(
            single_parameter(&[0x02, 0x02, 0x09, 0x01, b'A', 0x09, 0x01, b'B']),
            Err(ActionResult::TypeUnmatched)
        );
    }

    #[test]
    fn outcome_maps_to_action_result() {
        assert_eq!(action_result(Ok(())), ActionResult::Success);
        assert_eq!(
            action_result(Err(ActionResult::ScopeOfAccessViolated)),
            ActionResult::ScopeOfAccessViolated
        );
    }
}
