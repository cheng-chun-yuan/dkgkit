# Vault Chat Demo

Hackathon showcase concept built on DKGKit.

Flow:

1. Create Bitcoin vault group.
2. Participants join over Nostr.
3. Run FROST DKG.
4. Show shared Bitcoin address.
5. Create chat approval message.
6. Threshold participants sign the message.
7. Verify aggregate signature against the group key.

This demo intentionally starts with message authorization, not PSBT or transaction broadcast.
