//! Transport traits for DKGKit.
//!
//! Transport implementations move already-serialized protocol messages. They do
//! not implement DKG, signing, Bitcoin logic, or application policy.

use dkgkit_core::{ProtocolMessage, Result, SessionId};

pub trait Transport {
    fn connect(&mut self) -> Result<()>;
    fn disconnect(&mut self) -> Result<()>;
    fn publish(&mut self, message: ProtocolMessage) -> Result<()>;

    fn drain_matching(
        &mut self,
        session_id: &SessionId,
        predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>>;

    fn drain_session(&mut self, session_id: &SessionId) -> Result<Vec<ProtocolMessage>> {
        let mut all = |_message: &ProtocolMessage| true;
        self.drain_matching(session_id, &mut all)
    }
}

#[derive(Debug, Default)]
pub struct MemoryTransport {
    connected: bool,
    messages: Vec<ProtocolMessage>,
}

impl MemoryTransport {
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn pending_len(&self) -> usize {
        self.messages.len()
    }

    pub fn peek_session(&self, session_id: &SessionId) -> Vec<ProtocolMessage> {
        self.messages
            .iter()
            .filter(|message| &message.session_id == session_id)
            .cloned()
            .collect()
    }
}

impl Transport for MemoryTransport {
    fn connect(&mut self) -> Result<()> {
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.connected = false;
        Ok(())
    }

    fn publish(&mut self, message: ProtocolMessage) -> Result<()> {
        self.messages.push(message);
        Ok(())
    }

    fn drain_matching(
        &mut self,
        session_id: &SessionId,
        predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>> {
        let mut matched = Vec::new();
        self.messages.retain(|message| {
            if &message.session_id == session_id && predicate(message) {
                matched.push(message.clone());
                false
            } else {
                true
            }
        });
        Ok(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dkgkit_core::{ParticipantId, ProtocolMessage, ProtocolMessageKind};

    #[test]
    fn memory_transport_drains_only_target_session() {
        let mut transport = MemoryTransport::default();
        let session_a = SessionId::new("a").unwrap();
        let session_b = SessionId::new("b").unwrap();
        transport.connect().unwrap();
        transport
            .publish(ProtocolMessage::new(
                session_a.clone(),
                ParticipantId::new(1).unwrap(),
                ProtocolMessageKind::FrostDkgRound1,
                vec![1],
            ))
            .unwrap();
        transport
            .publish(ProtocolMessage::new(
                session_b.clone(),
                ParticipantId::new(2).unwrap(),
                ProtocolMessageKind::FrostDkgRound1,
                vec![2],
            ))
            .unwrap();

        let drained = transport.drain_session(&session_a).unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(transport.pending_len(), 1);
        assert_eq!(transport.peek_session(&session_b).len(), 1);
    }

    #[test]
    fn memory_transport_selectively_drains_matching_messages() {
        let mut transport = MemoryTransport::default();
        let session = SessionId::new("signing").unwrap();
        transport
            .publish(ProtocolMessage::new(
                session.clone(),
                ParticipantId::new(1).unwrap(),
                ProtocolMessageKind::FrostSigningNonce,
                vec![1],
            ))
            .unwrap();
        transport
            .publish(ProtocolMessage::new(
                session.clone(),
                ParticipantId::new(2).unwrap(),
                ProtocolMessageKind::FrostSignatureShare,
                vec![2],
            ))
            .unwrap();

        let mut only_nonces =
            |message: &ProtocolMessage| message.kind == ProtocolMessageKind::FrostSigningNonce;
        let drained = transport
            .drain_matching(&session, &mut only_nonces)
            .unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(transport.pending_len(), 1);
        assert_eq!(
            transport.peek_session(&session)[0].kind,
            ProtocolMessageKind::FrostSignatureShare
        );
    }
}
