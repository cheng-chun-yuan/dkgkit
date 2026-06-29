//! Live Nostr relay transport (feature `live`).
//!
//! Bridges the synchronous `Transport` trait to the async `nostr-sdk` client via
//! a dedicated background thread that owns a multi-thread tokio runtime. The
//! caller stays fully synchronous; inbound relay events are decoded into
//! `ProtocolMessage`s and buffered for `drain_matching`.
//!
//! Only `FrostDkgRound2`/`HtssDkgRound2` direct messages are NIP-44-encrypted;
//! everything else is published in clear. Subscriptions are scoped to a stable
//! vault topic tag (`#t = dkgkit:<vault_tag>`) so one connection serves DKG,
//! idle pre-signs, and signing.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use dkgkit_core::{
    DkgKitError, ParticipantId, ProtocolMessage, ProtocolMessageKind, Result, SessionId,
};
use dkgkit_transport::Transport;
use nostr_sdk::prelude::*;

use crate::{NostrEnvelopeEvent, DKGKIT_NOSTR_APP_TAG, DKGKIT_NOSTR_EVENT_KIND};

const ENCRYPTED_TAG_KEY: &str = "encrypted";
const ENCRYPTED_TAG_VALUE: &str = "nip44";

// --------------------------------------------------------------------------
// NIP-44 helpers
// --------------------------------------------------------------------------

/// NIP-44 v2 encrypt `plaintext` from `sender` to `recipient`.
fn encrypt_for(sender: &Keys, recipient: &PublicKey, plaintext: &str) -> Result<String> {
    nip44::encrypt(
        sender.secret_key(),
        recipient,
        plaintext,
        nip44::Version::V2,
    )
    .map_err(|err| DkgKitError::Protocol(format!("nip44 encrypt failed: {err}")))
}

/// NIP-44 decrypt `ciphertext` sent by `sender` to us (`receiver`).
fn decrypt_from(receiver: &Keys, sender: &PublicKey, ciphertext: &str) -> Result<String> {
    nip44::decrypt(receiver.secret_key(), sender, ciphertext)
        .map_err(|err| DkgKitError::Protocol(format!("nip44 decrypt failed: {err}")))
}

// --------------------------------------------------------------------------
// Event <-> envelope tag mapping
// --------------------------------------------------------------------------

fn vault_hashtag(vault_tag: &str) -> String {
    format!("dkgkit:{vault_tag}")
}

fn build_event_tags(
    envelope: &NostrEnvelopeEvent,
    vault_tag: &str,
    encrypted_recipient: Option<&PublicKey>,
) -> Vec<Tag> {
    let mut tags: Vec<Tag> = envelope
        .tags()
        .into_iter()
        .map(|values| Tag::parse(values).expect("envelope tags are well-formed"))
        .collect();
    tags.push(Tag::hashtag(vault_hashtag(vault_tag)));
    if let Some(recipient) = encrypted_recipient {
        tags.push(Tag::public_key(*recipient));
        tags.push(
            Tag::parse([ENCRYPTED_TAG_KEY, ENCRYPTED_TAG_VALUE]).expect("static encrypted tag"),
        );
    }
    tags
}

fn tag_value(event: &Event, key: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let slice = tag.as_slice();
        if slice.len() >= 2 && slice[0] == key {
            Some(slice[1].clone())
        } else {
            None
        }
    })
}

fn has_encrypted_marker(event: &Event) -> bool {
    tag_value(event, ENCRYPTED_TAG_KEY).as_deref() == Some(ENCRYPTED_TAG_VALUE)
}

fn envelope_from_event(content: String, event: &Event) -> Result<NostrEnvelopeEvent> {
    let session_id = tag_value(event, "session")
        .ok_or_else(|| DkgKitError::Protocol("missing session tag".into()))?;
    let sender = tag_value(event, "sender")
        .ok_or_else(|| DkgKitError::Protocol("missing sender tag".into()))?
        .parse::<u16>()
        .map_err(|err| DkgKitError::Protocol(format!("bad sender tag: {err}")))?;
    let recipient = match tag_value(event, "recipient") {
        Some(value) => Some(
            value
                .parse::<u16>()
                .map_err(|err| DkgKitError::Protocol(format!("bad recipient tag: {err}")))?,
        ),
        None => None,
    };
    let message_kind = tag_value(event, "message_kind")
        .ok_or_else(|| DkgKitError::Protocol("missing message_kind tag".into()))?;
    Ok(NostrEnvelopeEvent {
        kind: DKGKIT_NOSTR_EVENT_KIND,
        app: tag_value(event, "app").unwrap_or_else(|| DKGKIT_NOSTR_APP_TAG.to_string()),
        session_id,
        sender,
        recipient,
        message_kind,
        content,
    })
}

// --------------------------------------------------------------------------
// Participant directory and config
// --------------------------------------------------------------------------

/// Maps DKGKit participants to their Nostr public keys.
#[derive(Debug, Clone, Default)]
pub struct ParticipantDirectory {
    by_participant: BTreeMap<ParticipantId, PublicKey>,
}

impl ParticipantDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: ParticipantId, pubkey: PublicKey) {
        self.by_participant.insert(id, pubkey);
    }

    pub fn get(&self, id: ParticipantId) -> Option<PublicKey> {
        self.by_participant.get(&id).copied()
    }
}

/// Configuration for a `LiveNostrTransport`.
#[derive(Clone)]
pub struct LiveNostrTransportConfig {
    /// Relay URLs, e.g. `ws://127.0.0.1:7777`.
    pub relays: Vec<String>,
    /// Stable vault scope; becomes the `#t = dkgkit:<vault_tag>` subscription tag.
    pub vault_tag: String,
    /// Which participant this transport speaks for.
    pub self_id: ParticipantId,
    /// This device's Nostr identity (signs events, performs NIP-44).
    pub keys: Keys,
    /// Maps participants to Nostr pubkeys for encrypting direct messages.
    pub directory: ParticipantDirectory,
    pub connect_timeout: Duration,
    pub publish_timeout: Duration,
}

fn is_secret_kind(kind: &ProtocolMessageKind) -> bool {
    matches!(
        kind,
        ProtocolMessageKind::FrostDkgRound2 | ProtocolMessageKind::HtssDkgRound2
    )
}

// --------------------------------------------------------------------------
// Background relay thread
// --------------------------------------------------------------------------

enum Command {
    Publish {
        content: String,
        tags: Vec<Tag>,
        ack: std::sync::mpsc::SyncSender<Result<()>>,
    },
    Shutdown,
}

/// Relay-backed implementation of the synchronous `Transport` trait.
pub struct LiveNostrTransport {
    cfg: LiveNostrTransportConfig,
    cmd_tx: Option<tokio::sync::mpsc::UnboundedSender<Command>>,
    inbound: Arc<Mutex<VecDeque<ProtocolMessage>>>,
    handle: Option<JoinHandle<()>>,
    connected: bool,
}

impl LiveNostrTransport {
    pub fn new(cfg: LiveNostrTransportConfig) -> Self {
        Self {
            cfg,
            cmd_tx: None,
            inbound: Arc::new(Mutex::new(VecDeque::new())),
            handle: None,
            connected: false,
        }
    }

    /// Number of decoded messages waiting in the inbound buffer.
    pub fn pending_len(&self) -> usize {
        self.inbound.lock().expect("inbound lock").len()
    }
}

fn handle_inbound_event(
    keys: &Keys,
    self_id: ParticipantId,
    seen: &mut HashSet<EventId>,
    event: &Event,
    inbound: &Arc<Mutex<VecDeque<ProtocolMessage>>>,
) {
    if !seen.insert(event.id) {
        return;
    }
    if tag_value(event, "app").as_deref() != Some(DKGKIT_NOSTR_APP_TAG) {
        return;
    }
    // Skip direct messages addressed to someone else.
    if let Some(recipient) = tag_value(event, "recipient") {
        if recipient.parse::<u16>().ok() != Some(self_id.0) {
            return;
        }
    }
    let content = if has_encrypted_marker(event) {
        match decrypt_from(keys, &event.pubkey, &event.content) {
            Ok(plaintext) => plaintext,
            Err(_) => return, // not for us / spam
        }
    } else {
        event.content.clone()
    };
    let Ok(envelope) = envelope_from_event(content, event) else {
        return;
    };
    let Ok(message) = envelope.to_protocol_message() else {
        return;
    };
    inbound.lock().expect("inbound lock").push_back(message);
}

impl Transport for LiveNostrTransport {
    fn connect(&mut self) -> Result<()> {
        if self.connected {
            return Ok(());
        }
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Command>();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);

        let relays = self.cfg.relays.clone();
        let keys = self.cfg.keys.clone();
        let vault_filter = vault_hashtag(&self.cfg.vault_tag);
        let self_id = self.cfg.self_id;
        let inbound = Arc::clone(&self.inbound);

        let handle = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = ready_tx.send(Err(DkgKitError::Transport(format!(
                        "tokio runtime build failed: {err}"
                    ))));
                    return;
                }
            };

            runtime.block_on(async move {
                let client = Client::new(keys.clone());
                for relay in &relays {
                    if let Err(err) = client.add_relay(relay).await {
                        let _ = ready_tx.send(Err(DkgKitError::Transport(format!(
                            "add_relay {relay} failed: {err}"
                        ))));
                        return;
                    }
                }
                client.connect().await;

                let filter = Filter::new()
                    .kind(Kind::Custom(DKGKIT_NOSTR_EVENT_KIND as u16))
                    .hashtag(vault_filter);
                if let Err(err) = client.subscribe(filter, None).await {
                    let _ = ready_tx.send(Err(DkgKitError::Transport(format!(
                        "subscribe failed: {err}"
                    ))));
                    return;
                }

                let mut notifications = client.notifications();
                let mut seen: HashSet<EventId> = HashSet::new();
                let _ = ready_tx.send(Ok(()));

                loop {
                    tokio::select! {
                        cmd = cmd_rx.recv() => match cmd {
                            Some(Command::Publish { content, tags, ack }) => {
                                let builder = EventBuilder::new(
                                    Kind::Custom(DKGKIT_NOSTR_EVENT_KIND as u16),
                                    content,
                                )
                                .tags(tags);
                                let result = client
                                    .send_event_builder(builder)
                                    .await
                                    .map(|_| ())
                                    .map_err(|err| {
                                        DkgKitError::Transport(format!("send_event failed: {err}"))
                                    });
                                let _ = ack.send(result);
                            }
                            Some(Command::Shutdown) | None => break,
                        },
                        notification = notifications.recv() => {
                            if let Ok(RelayPoolNotification::Event { event, .. }) = notification {
                                handle_inbound_event(&keys, self_id, &mut seen, event.as_ref(), &inbound);
                            }
                        }
                    }
                }
                client.disconnect().await;
            });
        });

        match ready_rx.recv_timeout(self.cfg.connect_timeout) {
            Ok(Ok(())) => {
                self.cmd_tx = Some(cmd_tx);
                self.handle = Some(handle);
                self.connected = true;
                Ok(())
            }
            Ok(Err(err)) => Err(err),
            Err(_) => Err(DkgKitError::Transport("relay connect timed out".into())),
        }
    }

    fn disconnect(&mut self) -> Result<()> {
        if let Some(cmd_tx) = self.cmd_tx.take() {
            let _ = cmd_tx.send(Command::Shutdown);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.connected = false;
        Ok(())
    }

    fn publish(&mut self, message: ProtocolMessage) -> Result<()> {
        let cmd_tx = self
            .cmd_tx
            .as_ref()
            .ok_or_else(|| DkgKitError::Transport("transport not connected".into()))?;
        let envelope = NostrEnvelopeEvent::from_protocol_message(&message)?;

        let (content, tags) = if is_secret_kind(&message.kind) && message.recipient.is_some() {
            let recipient_id = message.recipient.expect("checked is_some");
            let recipient_pk = self.cfg.directory.get(recipient_id).ok_or_else(|| {
                DkgKitError::Transport(format!(
                    "no directory pubkey for participant {}",
                    recipient_id.0
                ))
            })?;
            let ciphertext = encrypt_for(&self.cfg.keys, &recipient_pk, &envelope.content)?;
            let tags = build_event_tags(&envelope, &self.cfg.vault_tag, Some(&recipient_pk));
            (ciphertext, tags)
        } else {
            let tags = build_event_tags(&envelope, &self.cfg.vault_tag, None);
            (envelope.content.clone(), tags)
        };

        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
        cmd_tx
            .send(Command::Publish {
                content,
                tags,
                ack: ack_tx,
            })
            .map_err(|_| DkgKitError::Transport("relay thread is gone".into()))?;
        match ack_rx.recv_timeout(self.cfg.publish_timeout) {
            Ok(result) => result?,
            Err(_) => return Err(DkgKitError::Transport("relay publish timed out".into())),
        }

        // Loop back our own deliverable messages: the relay does not echo a
        // client's own events, but the coordinator pattern drains them locally.
        if message.is_for(self.cfg.self_id) {
            self.inbound
                .lock()
                .expect("inbound lock")
                .push_back(message);
        }
        Ok(())
    }

    fn drain_matching(
        &mut self,
        session_id: &SessionId,
        predicate: &mut dyn FnMut(&ProtocolMessage) -> bool,
    ) -> Result<Vec<ProtocolMessage>> {
        let mut buffer = self.inbound.lock().expect("inbound lock");
        let mut matched = Vec::new();
        let mut kept = VecDeque::with_capacity(buffer.len());
        for message in buffer.drain(..) {
            if &message.session_id == session_id && predicate(&message) {
                matched.push(message);
            } else {
                kept.push_back(message);
            }
        }
        *buffer = kept;
        Ok(matched)
    }
}

impl Drop for LiveNostrTransport {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod nip44_tests {
    use super::*;

    #[test]
    fn round_trips_between_two_keys() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let ciphertext = encrypt_for(&alice, &bob.public_key(), "secret-share").unwrap();
        assert_ne!(ciphertext, "secret-share");
        let plaintext = decrypt_from(&bob, &alice.public_key(), &ciphertext).unwrap();
        assert_eq!(plaintext, "secret-share");
    }

    #[test]
    fn third_party_cannot_decrypt() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let eve = Keys::generate();
        let ciphertext = encrypt_for(&alice, &bob.public_key(), "secret-share").unwrap();
        assert!(decrypt_from(&eve, &alice.public_key(), &ciphertext).is_err());
    }
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    fn sample_message() -> ProtocolMessage {
        ProtocolMessage::direct(
            SessionId::new("vault-1-dkg").unwrap(),
            ParticipantId::new(1).unwrap(),
            ParticipantId::new(2).unwrap(),
            ProtocolMessageKind::HtssDkgRound2,
            vec![9, 8, 7],
        )
    }

    #[test]
    fn event_round_trips_to_protocol_message() {
        let keys = Keys::generate();
        let message = sample_message();
        let envelope = NostrEnvelopeEvent::from_protocol_message(&message).unwrap();
        let tags = build_event_tags(&envelope, "vault-1", None);
        let event = EventBuilder::new(
            Kind::Custom(DKGKIT_NOSTR_EVENT_KIND as u16),
            envelope.content.clone(),
        )
        .tags(tags)
        .sign_with_keys(&keys)
        .unwrap();

        assert_eq!(
            tag_value(&event, "app").as_deref(),
            Some(DKGKIT_NOSTR_APP_TAG)
        );
        assert_eq!(tag_value(&event, "session").as_deref(), Some("vault-1-dkg"));
        assert!(!has_encrypted_marker(&event));

        let rebuilt = envelope_from_event(event.content.clone(), &event).unwrap();
        assert_eq!(rebuilt.to_protocol_message().unwrap(), message);
    }

    #[test]
    fn encrypted_marker_round_trips() {
        let keys = Keys::generate();
        let recipient = Keys::generate();
        let message = sample_message();
        let envelope = NostrEnvelopeEvent::from_protocol_message(&message).unwrap();
        let tags = build_event_tags(&envelope, "vault-1", Some(&recipient.public_key()));
        let event = EventBuilder::new(Kind::Custom(DKGKIT_NOSTR_EVENT_KIND as u16), "ciphertext")
            .tags(tags)
            .sign_with_keys(&keys)
            .unwrap();
        assert!(has_encrypted_marker(&event));
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    fn transport_with_buffer(messages: Vec<ProtocolMessage>) -> LiveNostrTransport {
        let cfg = LiveNostrTransportConfig {
            relays: vec![],
            vault_tag: "vault-1".into(),
            self_id: ParticipantId::new(1).unwrap(),
            keys: Keys::generate(),
            directory: ParticipantDirectory::new(),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
        };
        let transport = LiveNostrTransport::new(cfg);
        {
            let mut buffer = transport.inbound.lock().unwrap();
            buffer.extend(messages);
        }
        transport
    }

    #[test]
    fn drains_only_matching_session_and_predicate() {
        let session = SessionId::new("s1").unwrap();
        let other = SessionId::new("s2").unwrap();
        let mut transport = transport_with_buffer(vec![
            ProtocolMessage::new(
                session.clone(),
                ParticipantId::new(1).unwrap(),
                ProtocolMessageKind::FrostDkgRound1,
                vec![1],
            ),
            ProtocolMessage::new(
                session.clone(),
                ParticipantId::new(2).unwrap(),
                ProtocolMessageKind::FrostSigningNonce,
                vec![2],
            ),
            ProtocolMessage::new(
                other,
                ParticipantId::new(3).unwrap(),
                ProtocolMessageKind::FrostDkgRound1,
                vec![3],
            ),
        ]);
        let mut only_round1 = |m: &ProtocolMessage| m.kind == ProtocolMessageKind::FrostDkgRound1;
        let drained = transport
            .drain_matching(&session, &mut only_round1)
            .unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(transport.pending_len(), 2);
    }
}
